"""Pwn-workflow tools: structured heap bins and checkpoints."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import parse_pwndbg_bins

from ._common import check_stopped, config_from, resolve_gdb

_SNAPSHOT_ACTIONS = ("create", "list", "restore", "diff")


def register(app, registry, config) -> None:
    @app.tool()
    async def heap_bins(
        include_raw: bool = False,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Structured glibc heap bins (tcachebins/fastbins/unsorted/small/
        large, each a size -> chunk-addresses map) parsed from pwndbg's
        `bins` command. Requires pwndbg in this gdb session. When the
        output shape is not recognized, parsed=False and the raw text is
        returned for manual reading."""
        cfg = config_from(ctx)
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        if not (session.hello or {}).get("pwndbg"):
            raise GdbMcpError(
                "NO_PWNDBG",
                "heap_bins requires pwndbg; start gdb with pwndbg loaded "
                "or use execute_command('bins')",
            )
        result = await session.request(
            "eval", {"command": "bins"}, timeout=cfg.request_timeout
        )
        parsed = parse_pwndbg_bins(result.get("output", ""))
        parsed["truncated"] = bool(result.get("truncated", False))
        if not parsed["parsed"] or include_raw:
            parsed["output"] = result.get("output", "")
        return parsed

    @app.tool()
    async def run_policy(
        kind: str,
        params: dict | None = None,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Delegate a bounded loop to the plugin so it runs at native
        speed; the response is a constant-size summary regardless of
        iterations. Kinds (all need a stopped inferior):
        - trace: {max_steps} single-steps, returns unique PCs in order.
        - heap_arm: arm allocation-symbol probes {symbols, max_events}
          that record args per hit and auto-continue invisibly;
          heap_read accumulates the timeline; heap_disarm removes them.
        - fuzz_loop: per payload — restore checkpoint, write payload at
          buffer_addr, resume; stops at stop_location (a guaranteed-stop
          marker, e.g. the caller of the function under test) count as
          survived, anything else is a deduped crash. params:
          snapshot_id, buffer_addr, payloads (hex list), stop_location,
          max_rounds.
        - crash_check: single-payload verdict {survived, stop}.
        - minimize: delta-debug a crashing payload down to its minimal
          crashing form (params: snapshot_id, payload, buffer_addr,
          stop_location, max_rounds); removals that change the crash
          signal are rejected so the minimizer cannot drift to another
          bug.
        - bp_stats: hit-count probes at locations (auto-continue) plus
          a temporary marker at stop_location; resumes until the hit
          budget (max_hits), max_passes marker hits, or the inferior's
          own stop — then reports per-location counts. The long-run
          version of manual breakpoint hit counting."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        policy_params = dict(params or {})
        policy_params["kind"] = kind
        # policies loop plugin-side; a large fuzz sweep can legitimately
        # run for minutes, so the default request timeout does not apply
        return await session.request(
            "policy",
            policy_params,
            timeout=max(config_from(ctx).request_timeout, 600.0),
        )

    @app.tool()
    async def checkpoint(
        action: str = "create",
        snapshot_id: str | None = None,
        max_segment_bytes: int | None = None,
        max_total_bytes: int | None = None,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Registers + writable-memory snapshots for hypothesis testing:
        create a checkpoint, mutate state (payloads, patched metadata),
        then diff against it or restore it. Actions: create (returns
        snapshot_id), list, restore (needs snapshot_id), diff (needs
        snapshot_id; reports changed registers and 16-byte memory rows).
        Budgets (bytes, defaults 4MiB/segment and 8MiB total) bound the
        snapshot size."""
        if action not in _SNAPSHOT_ACTIONS:
            raise GdbMcpError(
                "BAD_PARAMS",
                "action must be one of create, list, restore, diff",
            )
        if action in ("restore", "diff") and not snapshot_id:
            raise GdbMcpError(
                "BAD_PARAMS", "action %r requires snapshot_id" % action
            )
        cfg = config_from(ctx)
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        params: dict = {}
        if snapshot_id:
            params["snapshot_id"] = snapshot_id
        if max_segment_bytes is not None:
            params["max_segment_bytes"] = max_segment_bytes
        if max_total_bytes is not None:
            params["max_total_bytes"] = max_total_bytes
        verb = (
            "snapshot_create"
            if action == "create"
            else "snapshot_list"
            if action == "list"
            else "snapshot_restore"
            if action == "restore"
            else "snapshot_diff"
        )
        return await session.request(
            verb, params, timeout=cfg.request_timeout
        )
