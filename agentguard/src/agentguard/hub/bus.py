"""
Event Bus — §1.1

In-process EventBus → WebSocket fan-out.
Per-connection asyncio.Queue(maxsize=1000).
On overflow, drop oldest and emit SLOW_CONSUMER error.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class EventBus:
    """
    In-process pub/sub bus for ledger events → WebSocket fan-out. §1.4.5

    Each subscriber gets its own bounded queue. If the queue is full,
    the oldest events are dropped and a SLOW_CONSUMER error is queued.
    """

    def __init__(self) -> None:
        self._subscribers: dict[int, asyncio.Queue[dict[str, Any]]] = {}
        self._next_id: int = 0

    def subscribe(self) -> tuple[int, asyncio.Queue[dict[str, Any]]]:
        """Register a new subscriber. Returns (subscriber_id, queue)."""
        sub_id = self._next_id
        self._next_id += 1
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)
        self._subscribers[sub_id] = queue
        return sub_id, queue

    def unsubscribe(self, sub_id: int) -> None:
        """Remove a subscriber."""
        self._subscribers.pop(sub_id, None)

    def publish(self, event: dict[str, Any]) -> None:
        """
        Publish an event to all subscribers.

        If a subscriber's queue is full, drop the oldest event and
        emit a SLOW_CONSUMER error. §1.4.5
        """
        for sub_id, queue in self._subscribers.items():
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop oldest, then add the new event
                try:
                    dropped = queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass
                # Queue an error notification
                try:
                    queue.put_nowait({
                        "type": "error",
                        "code": "SLOW_CONSUMER",
                        "message": "Events dropped; resync with since_idx",
                    })
                except asyncio.QueueFull:
                    pass
                logger.warning("bus.slow_consumer", sub_id=sub_id)
