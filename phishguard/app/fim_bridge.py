"""Filesystem/kernel event bridge.

Bridges the eBPF FIM (file integrity + exec) daemon into PhishGuard's gRPC
streaming. A background task reads JSON-lines from a Unix socket
(``AEGISX_FIM_IPC``) or a polled JSON-lines log file (``AEGISX_FIM_LOG``), and
pushes raw events onto a shared asyncio queue consumed by ``eBPFStreamer``.
When no source is present it emits synthetic idle keepalives so the RPC channel
stays warm. Every error is swallowed + logged.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_IDLE_INTERVAL = 60.0


class FIMBridge:
    """Background FIM source reader feeding a shared asyncio queue."""

    def __init__(self, ipc: str = "/var/run/aegisx-fim.sock",
                 log_path: str = ""):
        self.ipc = ipc
        self.log_path = log_path
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._task: asyncio.Task | None = None
        self._log_offset = 0
        self._last_idle = 0.0
        self._socket_available = True

    # ------------------------------------------------------------------ io
    async def _read_socket(self) -> None:
        """Blockingly sit on a Unix socket and parse JSON-lines."""
        while True:
            try:
                reader, _writer = await asyncio.open_unix_connection(self.ipc)
                self._socket_available = True
                logger.info("FIM bridge connected to socket %s", self.ipc)
                while True:
                    line = await reader.readline()
                    if not line:
                        break
                    self._emit(line)
            except Exception as exc:
                self._socket_available = False
                logger.debug("FIM socket unavailable (%s); %s", self.ipc, exc)
                return

    def _read_log(self) -> list[bytes]:
        """Read any new lines appended to the fallback JSON-lines file."""
        if not self.log_path:
            return []
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._log_offset)
                lines = fh.readlines()
                self._log_offset = fh.tell()
                return lines
        except Exception as exc:
            logger.debug("FIM log read failed: %s", exc)
            return []

    def _emit(self, line) -> None:
        line = line.strip()
        if not line:
            return
        try:
            data = json.loads(line.decode("utf-8", "replace")) if isinstance(line, bytes) \
                else json.loads(line)
        except (ValueError, TypeError) as exc:
            logger.debug("FIM skipped unparseable line: %s", exc)
            return
        if not isinstance(data, dict):
            return
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            logger.warning("FIM queue full; dropping event")

    def _idle_keepalive(self) -> dict:
        return {
            "type": "idle",
            "pid": 0,
            "ppid": 0,
            "comm": "",
            "exe": "",
            "argv": [],
            "user": "",
            "uid": "0",
            "start_ns": int(time.time_ns()),
            "anomaly": False,
            "anomaly_type": "",
            "detail": "fim-idle-keepalive",
            "node": "phishguard",
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------ loop
    async def _run(self) -> None:
        while True:
            if self._socket_available:
                await self._read_socket()
                continue
            lines = self._read_log()
            for raw in lines:
                self._emit(raw)
            now = time.monotonic()
            if now - self._last_idle >= _IDLE_INTERVAL:
                self._last_idle = now
                self._emit(self._idle_keepalive())
            await asyncio.sleep(30.0)

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


fim_bridge = FIMBridge()