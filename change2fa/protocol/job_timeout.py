"""Check job wall-clock: abort curl so timeout does not sit on a hung GET."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

T = TypeVar("T")

from change2fa.protocol.live_curl import abort as abort_curl

_UNWIND_S = 2.0


async def await_or_timeout(
    coro: Awaitable[T],
    *,
    timeout: int,
    abort_key: str,
) -> tuple[T | None, bool]:
    """Return ``(result, timed_out)``. On timeout, close live curl then cancel."""
    if timeout <= 0:
        return await coro, False
    task = asyncio.ensure_future(coro)
    killer = asyncio.create_task(_abort_after(float(timeout), abort_key))
    try:
        done, _ = await asyncio.wait({task}, timeout=float(timeout))
        if task in done:
            return task.result(), False
        abort_curl(abort_key)
        done2, _ = await asyncio.wait({task}, timeout=_UNWIND_S)
        if task not in done2:
            task.cancel()
            await asyncio.wait({task}, timeout=1.0)
        return None, True
    except asyncio.CancelledError:
        abort_curl(abort_key)
        if not task.done():
            task.cancel()
        raise
    finally:
        killer.cancel()
        try:
            await killer
        except asyncio.CancelledError:
            pass


async def _abort_after(timeout: float, key: str) -> None:
    await asyncio.sleep(timeout)
    abort_curl(key)
