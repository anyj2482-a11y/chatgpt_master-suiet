"""Run blocking login / MFA hops off the event loop."""

from __future__ import annotations

import asyncio
import contextvars
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import TypeVar

T = TypeVar("T")

from change2fa.limits import MAX_CONCURRENCY

_WORKERS = MAX_CONCURRENCY
_exec: ThreadPoolExecutor | None = None


def get_probe_executor() -> ThreadPoolExecutor:
    global _exec
    if _exec is None:
        _exec = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="c2fa")
    return _exec


async def run_probe(fn: Callable[..., T], *args: object, **kwargs: object) -> T:
    loop = asyncio.get_running_loop()
    bound: Callable[[], T] = partial(fn, *args, **kwargs)
    ctx = contextvars.copy_context()
    return await loop.run_in_executor(get_probe_executor(), lambda: ctx.run(bound))
