"""Idempotent GET transport retry — rust auth_gpt/login/net_retry.rs parity."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from change2fa.protocol.login.timings import RETRY_BACKOFF_S

log = logging.getLogger(__name__)

_TRANSPORT_MARKERS = (
    "connection reset",
    "connection refused",
    "connection aborted",
    "connection closed",
    "connection timed out",
    "timed out",
    "timeout",
    "could not connect",
    "failed to connect",
    "broken pipe",
    "tls",
    "ssl",
    "proxy",
    "recv failure",
    "curl: (7)",
    "curl: (28)",
    "curl: (35)",
    "curl: (56)",
)


def is_aborted_session(exc: BaseException | str | None) -> bool:
    """Stop All / job-timeout closed the curl session mid-hop."""
    if exc is None:
        return False
    name = type(exc).__name__.lower() if not isinstance(exc, str) else ""
    msg = str(exc).lower()
    return "sessionclosed" in name or "session is closed" in msg


def is_transient_transport_error(exc: BaseException) -> bool:
    """True for connect/timeout-class errors safe to retry on idempotent GET."""
    if is_aborted_session(exc):
        return False
    name = type(exc).__name__.lower()
    if "timeout" in name or "connect" in name:
        return True
    msg = str(exc).lower()
    return any(m in msg for m in _TRANSPORT_MARKERS)


from typing import TypeVar

T = TypeVar("T")


def send_with_retry(
    label: str,
    attempts: int,
    make: Callable[[], T],
) -> T:
    """Call ``make`` up to ``attempts`` times; retry only transport blips.

    ``attempts`` is total tries (>=1). Permanent errors (or exhausted) re-raise.
    """
    total = max(1, attempts)
    last: BaseException | None = None
    for attempt in range(total):
        try:
            return make()
        except Exception as e:
            last = e
            if is_transient_transport_error(e) and attempt + 1 < total:
                wait = RETRY_BACKOFF_S * (attempt + 1)
                log.warning(
                    "[login] %s transient transport error → retry in %ss "
                    "(attempt %s): %s",
                    label,
                    wait,
                    attempt,
                    e,
                )
                time.sleep(wait)
                continue
            raise
    assert last is not None
    raise last
