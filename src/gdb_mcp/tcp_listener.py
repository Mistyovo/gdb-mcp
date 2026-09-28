"""TCP endpoint the in-gdb plugins connect to.

Flow per connection: handshake (hello, optionally token-wrapped) -> bind to a
:class:`~gdb_mcp.sessions.Session` -> hello_ack -> reader loop dispatching
``response`` / ``notification`` messages -> heartbeat task pinging every
``heartbeat_sec`` (a connection silent for 2x the interval is dropped).
"""

from __future__ import annotations

import asyncio
import logging
import time

from gdb_mcp import __version__
from gdb_mcp.config import Config
from gdb_mcp.errors import ProtocolError
from gdb_mcp.protocol import (
    LineReader,
    build_hello_ack,
    build_ping,
    encode,
    parse_line,
    peek_session_id,
    unwrap_token,
    validate_hello,
    validate_plugin_message,
)
from gdb_mcp.sessions import Session, SessionRegistry

log = logging.getLogger("gdb_mcp.listener")

HELLO_TIMEOUT = 10.0


class PluginTcpListener:
    def __init__(self, config: Config, registry: SessionRegistry):
        self.config = config
        self.registry = registry
        self.server: asyncio.Server | None = None

    async def start(self) -> None:
        self.config.validate()
        self.server = await asyncio.start_server(
            self._on_connect,
            self.config.host_bind,
            self.config.port,
        )
        log.info(
            "gdb plugin listener on %s:%d",
            self.config.host_bind,
            self.config.port,
        )

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        tasks = []
        for session in self.registry.list_all():
            if session.writer is not None:
                session.writer.close()
            for task in (session.reader_task, session.hb_task):
                if task is not None and not task.done():
                    task.cancel()
                    tasks.append(task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # -- connection handling ------------------------------------------------

    async def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            session = await self._handshake(reader, writer)
        except Exception as exc:
            log.warning("handshake with %s failed: %s", peer, exc)
            writer.close()
            return
        session.reader_task = asyncio.create_task(
            self._reader_loop(session, reader, writer)
        )
        session.hb_task = asyncio.create_task(self._heartbeat_loop(session, writer))

    async def _handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Session:
        try:
            data = await asyncio.wait_for(reader.readline(), HELLO_TIMEOUT)
        except asyncio.TimeoutError:
            raise ProtocolError("MALFORMED", "no hello received") from None
        except asyncio.IncompleteReadError:
            raise ProtocolError("MALFORMED", "connection closed before hello") from None
        if not data:
            raise ProtocolError("MALFORMED", "connection closed before hello")
        raw = data.rstrip(b"\r\n")
        if len(raw) > self.config.max_async_line:
            raise ProtocolError("MALFORMED", "hello line too long")
        parsed = parse_line(raw)
        # E4: a launched session verifies against its scoped token. An
        # unknown session_id is NOT enough to pick a token: the hello also
        # has to prove the master token, which a launched plugin never
        # holds. Falling back silently would let any master-token holder
        # squat a session id it was never given, so say so in the log.
        sid = peek_session_id(parsed)
        if sid and not self.registry.has_session(sid):
            # Claiming an id this server never reserved cannot bind anything;
            # the hello still has to prove the master token, but say so --
            # an unexpected session id is the one clue a squatted launch
            # leaves.
            expected = self.config.token
            log.warning(
                "hello claims unknown session %r; accepting as external "
                "plugin under the master token",
                sid[:40],
            )
        else:
            expected = self.registry.token_for(sid) or self.config.token
        msg = unwrap_token(parsed, expected)
        validate_hello(msg)
        session = self.registry.register_hello(msg, writer)
        ack = build_hello_ack(
            session.session_id, __version__, self.config.heartbeat_sec
        )
        writer.write(encode(ack, self.config.token))
        await writer.drain()
        return session

    async def _reader_loop(
        self,
        session: Session,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        frames = LineReader(self.config.max_async_line)
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break  # EOF
                for line in frames.feed(data):
                    await self._dispatch(session, parse_line(line))
        except ProtocolError as exc:
            log.warning("session %s protocol error: %s", session.session_id, exc)
        except (ConnectionError, asyncio.IncompleteReadError, OSError) as exc:
            log.debug("session %s connection closed: %s", session.session_id, exc)
        finally:
            # Only tear down if this connection is still the session's
            # current one (a reconnected plugin may have rebound already).
            if session.writer is writer:
                if session.hb_task is not None:
                    session.hb_task.cancel()
                await session.on_disconnect()
            try:
                writer.close()
            except Exception:  # pragma: no cover
                pass

    async def _dispatch(self, session: Session, msg: dict) -> None:
        # launched sessions keep presenting their session-scoped token on
        # every message — unwrap with the session's token, not the master
        msg = unwrap_token(msg, session.token or self.config.token)
        validate_plugin_message(msg)
        session.update_seen()
        mtype = msg.get("type")
        if mtype == "response":
            await session.complete_response(msg.get("id"), msg)
        elif mtype == "notification":
            await session.push_notification(msg.get("event"), msg.get("payload") or {})

    async def _heartbeat_loop(
        self, session: Session, connection_writer: asyncio.StreamWriter
    ) -> None:
        interval = self.config.heartbeat_sec
        try:
            while True:
                await asyncio.sleep(interval)
                writer = session.writer
                if writer is None or writer is not connection_writer:
                    return
                if (
                    session.last_seen is not None
                    and time.monotonic() - session.last_seen > 2 * interval
                ):
                    log.warning(
                        "session %s heartbeat timeout, closing", session.session_id
                    )
                    writer.close()
                    return
                async with session.lock:
                    if session.writer is writer and not writer.is_closing():
                        writer.write(encode(build_ping(), self.config.token))
                        await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception:  # pragma: no cover - keep the listener alive
            log.exception("heartbeat loop for %s failed", session.session_id)
            if session.writer is connection_writer:
                connection_writer.close()
