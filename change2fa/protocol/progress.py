"""Thread-safe Check GPT step notes → WS job_log (login runs in to_thread)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from change2fa.protocol.ids import now_ms

log = logging.getLogger(__name__)

EmitLog = Callable[[dict[str, Any]], Awaitable[None] | None]


class CheckProgress:
    """Fire-and-forget UI steps. ``emit_log=None`` still writes server logs."""

    def __init__(self, email: str, emit_log: EmitLog | None = None) -> None:
        self.email = email
        self._emit = emit_log
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self._pending: set[Any] = set()

    def _payload(self, step: str, message: str, level: str) -> dict[str, Any]:
        return {
            "email": self.email,
            "tsMs": now_ms(),
            "level": level,
            "step": step,
            "message": message,
        }

    def note(self, step: str, message: str, *, level: str = "info") -> None:
        log.info("[%s] %s", step, message)
        self._dispatch(self._payload(step, message, level))

    async def anote(self, step: str, message: str, *, level: str = "info") -> None:
        log.info("[%s] %s", step, message)
        if self._emit is None:
            return
        result = self._emit(self._payload(step, message, level))
        if asyncio.iscoroutine(result):
            await result

    def _dispatch(self, payload: dict[str, Any]) -> None:
        emit = self._emit
        if emit is None:
            return
        if not asyncio.iscoroutinefunction(emit):
            emit(payload)
            return
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        try:
            if asyncio.get_running_loop() is loop:
                task = loop.create_task(emit(payload))
                self._pending.add(task)
                task.add_done_callback(self._pending.discard)
                return
        except RuntimeError:
            pass
        fut = asyncio.run_coroutine_threadsafe(emit(payload), loop)
        self._pending.add(fut)
        fut.add_done_callback(self._pending.discard)
