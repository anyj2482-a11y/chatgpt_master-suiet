"""Thread-safe live curl registry — abort hung Check GETs from the event loop."""

from __future__ import annotations

import contextvars
import logging
import threading
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

log = logging.getLogger(__name__)

abort_key_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "curl_abort_key", default=None
)

_lock = threading.Lock()
_live: dict[str, list[Any]] = defaultdict(list)


@contextmanager
def using_abort_key(key: str) -> Iterator[None]:
    token = abort_key_var.set(key)
    try:
        yield
    finally:
        abort_key_var.reset(token)


def track(session: Any, key: str | None = None) -> None:
    k = key if key is not None else abort_key_var.get()
    if not k:
        return
    with _lock:
        _live[k].append(session)


def untrack(session: Any, key: str | None = None) -> None:
    k = key if key is not None else abort_key_var.get()
    if not k:
        return
    with _lock:
        bucket = _live.get(k)
        if not bucket:
            return
        try:
            bucket.remove(session)
        except ValueError:
            pass
        if not bucket:
            _live.pop(k, None)


def abort(key: str) -> int:
    """Close every tracked session for ``key``. Safe from any thread."""
    with _lock:
        sessions = list(_live.pop(key, ()))
    n = 0
    for session in sessions:
        try:
            session.close()
            n += 1
        except Exception:
            log.debug("live curl abort close failed", exc_info=True)
    return n


def abort_prefix(prefix: str) -> int:
    """Close sessions whose abort key starts with ``prefix`` (one lane)."""
    if not prefix:
        return 0
    with _lock:
        keys = [k for k in _live if k.startswith(prefix)]
    n = 0
    for key in keys:
        n += abort(key)
    return n


def abort_all() -> int:
    with _lock:
        keys = list(_live)
    n = 0
    for key in keys:
        n += abort(key)
    return n
