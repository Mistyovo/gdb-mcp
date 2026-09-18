"""Non-blocking event fan-out for sessions, analysis jobs, and the dashboard."""

from __future__ import annotations

import asyncio
import copy
import threading
import time
from typing import Any


class EventBroker:
    """Publish ordered events without ever blocking a producer.

    Each subscriber owns a bounded queue. A slow subscriber gets a single
    ``resync`` marker and must fetch a fresh snapshot rather than replay stale
    state.
    """

    def __init__(self, queue_size: int = 256):
        self.queue_size = max(2, queue_size)
        self._seq = 0
        self._subscribers: dict[asyncio.Queue, asyncio.AbstractEventLoop | None] = {}
        self._lock = threading.Lock()

    @property
    def sequence(self) -> int:
        with self._lock:
            return self._seq

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.queue_size)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        with self._lock:
            self._subscribers[queue] = loop
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers.pop(queue, None)

    def publish(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        payload = copy.deepcopy(data)
        with self._lock:
            self._seq += 1
            event = {
                "seq": self._seq,
                "type": event_type,
                "timestamp": time.time(),
                "data": payload,
            }
            stale = []
            for queue, loop in self._subscribers.items():
                if loop is None:
                    self._deliver(queue, event)
                    continue
                try:
                    loop.call_soon_threadsafe(self._deliver_if_subscribed, queue, event)
                except RuntimeError:
                    stale.append(queue)
            for queue in stale:
                self._subscribers.pop(queue, None)
        return event

    def _deliver_if_subscribed(self, queue: asyncio.Queue, event: dict[str, Any]) -> None:
        with self._lock:
            subscribed = queue in self._subscribers
        if subscribed:
            self._deliver(queue, event)

    @staticmethod
    def _deliver(queue: asyncio.Queue, event: dict[str, Any]) -> None:
        if queue.full():
            while not queue.empty():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:  # pragma: no cover - defensive
                    break
            queue.put_nowait(
                {
                    "seq": event["seq"],
                    "type": "resync",
                    "timestamp": event["timestamp"],
                    "data": {},
                }
            )
        else:
            queue.put_nowait(event)


__all__ = ["EventBroker"]
