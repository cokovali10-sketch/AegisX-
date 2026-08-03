"""WebSocket event fan-out for the Executive Control Center.

A single pub/sub hub; PhishGuard pushes every scored honeypot event and the
Kotlin dashboard receives it over one long-lived WebSocket connection.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class WSManager:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    async def broadcast(self, payload: dict[str, Any]) -> None:
        """Deliver a JSON payload to all live subscribers (best-effort)."""
        data = json.dumps(payload, default=str)
        for q in list(self._subscribers):
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                self._subscribers.discard(q)

    def register(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.add(q)
        return q

    def unregister(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)


# process-wide singleton
manager = WSManager()
