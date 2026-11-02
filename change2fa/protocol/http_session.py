"""curl_cffi session factory."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from change2fa.protocol.ca_bundle import curl_ca_bundle
from change2fa.protocol.live_curl import abort_key_var, track, untrack
from change2fa.protocol.proxy_parse import normalize_proxy_url

try:
    from curl_cffi import requests as cf_requests
except ImportError:  # pragma: no cover
    cf_requests = None  # type: ignore

CONNECT_TIMEOUT = 15.0
DEFAULT_TIMEOUT = 60.0
# ponytail: chrome145 Session() is CPU-heavy; cap inits, not HTTP Multi.
SESSION_INIT_LIMIT = 4
_SESSION_INIT = threading.Semaphore(SESSION_INIT_LIMIT)


def create_session(
    *,
    proxy_url: str | None = None,
    impersonate: str = "chrome131",
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
) -> Any:
    if cf_requests is None:
        raise RuntimeError("curl_cffi is required")
    resolved: float | tuple[float, float]
    if isinstance(timeout, tuple):
        resolved = timeout
    else:
        resolved = (CONNECT_TIMEOUT, float(timeout))
    ca = curl_ca_bundle()
    with _SESSION_INIT:
        try:
            session = cf_requests.Session(
                impersonate=impersonate, timeout=resolved, verify=ca
            )
        except TypeError:
            session = cf_requests.Session(impersonate=impersonate, timeout=timeout, verify=ca)
    proxy = normalize_proxy_url(proxy_url)
    if proxy:
        # Both schemes must use the same HTTP CONNECT proxy URL (not https://).
        session.proxies = {"http": proxy, "https": proxy}
    _attach_abort(session)
    return session


def _attach_abort(session: Any) -> None:
    key = abort_key_var.get()
    if not key:
        return
    track(session, key)
    orig_close = session.close

    def close() -> None:
        untrack(session, key)
        orig_close()

    session.close = close


@contextmanager
def closing_session(**kwargs: Any) -> Iterator[Any]:
    session = create_session(**kwargs)
    try:
        yield session
    finally:
        try:
            session.close()
        except Exception:
            pass
