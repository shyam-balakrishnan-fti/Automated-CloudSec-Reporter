"""
api/sse.py — Server-Sent Events infrastructure.

Provides a simple async queue-based SSE stream.
Used by:
  - Tool installer (Phase 2): streams install output
  - Pipeline runner (Phase 3): streams pipeline stdout/stderr

Usage pattern:
    # In a route that starts a background task:
    stream = SseStream()
    active_streams[task_id] = stream
    asyncio.create_task(run_something(stream))
    return stream.response()

    # In the background task:
    await stream.send("Installing prowler...")
    await stream.send_json({"type": "status", "value": "complete"})
    await stream.close()

    # In the consuming route (GET /events/{task_id}):
    stream = active_streams.get(task_id)
    return stream.response()

Event format (each SSE event):
    data: {"type": "log",    "text": "...", "stream": "stdout"}
    data: {"type": "status", "value": "running|complete|failed"}
    data: {"type": "done"}
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from fastapi.responses import StreamingResponse


class SseStream:
    """
    A single SSE stream backed by an asyncio Queue.
    One instance per running task. Consumed by exactly one HTTP client.
    """

    def __init__(self, task_id: str = "") -> None:
        self.task_id   = task_id
        self._queue:   asyncio.Queue[str | None] = asyncio.Queue()
        self._closed   = False

    # ── Sending ───────────────────────────────────────────────────────

    async def send_log(self, text: str, stream: str = "stdout") -> None:
        """Send a log line from subprocess stdout/stderr."""
        if self._closed:
            return
        await self._put({"type": "log", "text": text, "stream": stream,
                         "ts": _now()})

    async def send_status(self, value: str) -> None:
        """Send a status change event (running, complete, failed, etc.)."""
        if self._closed:
            return
        await self._put({"type": "status", "value": value, "ts": _now()})

    async def send_json(self, payload: dict[str, Any]) -> None:
        """Send an arbitrary JSON payload."""
        if self._closed:
            return
        await self._put(payload)

    async def close(self) -> None:
        """Signal end of stream. Sends a 'done' event then closes."""
        if self._closed:
            return
        self._closed = True
        await self._put({"type": "done", "ts": _now()})
        await self._queue.put(None)  # sentinel

    # ── HTTP response ─────────────────────────────────────────────────

    def response(self) -> StreamingResponse:
        """Return a FastAPI StreamingResponse for this stream."""
        return StreamingResponse(
            self._generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control":    "no-cache",
                "X-Accel-Buffering": "no",   # disable nginx buffering if proxied
                "Connection":       "keep-alive",
            },
        )

    async def _generate(self) -> AsyncGenerator[str, None]:
        """Yield SSE-formatted strings from the queue until closed."""
        # Send an initial heartbeat so the browser connection is confirmed
        yield "data: {\"type\": \"heartbeat\"}\n\n"

        while True:
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=25.0)
            except asyncio.TimeoutError:
                # Keep-alive ping every 25 seconds to prevent proxy timeouts
                yield ": ping\n\n"
                continue

            if item is None:
                # Sentinel — stream is done
                break

            yield f"data: {item}\n\n"

    # ── Internal ──────────────────────────────────────────────────────

    async def _put(self, payload: dict[str, Any]) -> None:
        await self._queue.put(json.dumps(payload, ensure_ascii=False))


# ── Stream registry ───────────────────────────────────────────────────
# In-process store of active streams keyed by task_id.
# Phase 3 will use the same registry for pipeline runs.
# Key: task_id (str)  Value: SseStream

_streams: dict[str, SseStream] = {}


def register_stream(task_id: str) -> SseStream:
    """Create and register a new SSE stream for task_id."""
    stream = SseStream(task_id=task_id)
    _streams[task_id] = stream
    return stream


def get_stream(task_id: str) -> SseStream | None:
    """Retrieve an existing stream by task_id."""
    return _streams.get(task_id)


def remove_stream(task_id: str) -> None:
    """Remove a stream from the registry after it's been consumed."""
    _streams.pop(task_id, None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()