"""Recover BoringSSL SSL_ERROR_SYSCALL on the auth.openai.com hop.

Check login uses one curl_cffi handle: HTTP/2 to chatgpt.com, then a new
TLS handshake to auth.openai.com. Proxies often RST that handshake
(``SSL_ERROR_SYSCALL``, empty error queue). A new easy handle keeps
cookies and retries the same hop; if the RST repeats, the rest of the
login stays on HTTP/1.1. Broken-pipe curl 35 is a dead proxy — no retry.
"""

from __future__ import annotations

import logging
from typing import Any

from curl_cffi import CurlHttpVersion

from change2fa.protocol.login.net_retry import is_aborted_session
from change2fa.protocol.http_session import create_session

log = logging.getLogger(__name__)


def is_ssl_syscall(exc: BaseException) -> bool:
    if is_aborted_session(exc):
        return False
    msg = str(exc).lower()
    if "ssl_error_syscall" in msg or "connection closed abruptly" in msg:
        return True
    return "curl: (35)" in msg and "ssl_connect" in msg


def drop_curl_connections(session: Any) -> None:
    """Drop the easy handle so the next request opens a new TLS tunnel."""
    local = getattr(session, "_local", None)
    curl = None
    if local is not None:
        curl = getattr(local, "curl", None)
        try:
            del local.curl
        except Exception:
            pass
    elif hasattr(session, "_curl"):
        curl = session._curl
        session._curl = None
    if curl is None:
        return
    try:
        curl.close()
    except Exception:
        pass


class LoginTlsSession:
    """Session proxy: one fresh-handle retry, then pin HTTP/1.1."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._fresh_tried = False
        self._http1 = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def get(self, url: str, **kwargs: Any) -> Any:
        return self._call("get", url, kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self._call("post", url, kwargs)

    def close(self) -> None:
        self._inner.close()

    def _call(self, method: str, url: str, kwargs: dict[str, Any]) -> Any:
        fn = getattr(self._inner, method)
        if self._http1:
            kwargs.setdefault("http_version", CurlHttpVersion.V1_1)
        try:
            out = fn(url, **kwargs)
        except Exception as e:
            if not is_ssl_syscall(e) or self._http1:
                raise
            return self._recover(fn, url, kwargs, e)
        self._fresh_tried = False
        return out

    def _recover(self, fn: Any, url: str, kwargs: dict[str, Any], exc: BaseException) -> Any:
        if not self._fresh_tried:
            self._fresh_tried = True
            log.warning("[login] ssl syscall → fresh handle: %s", exc)
            drop_curl_connections(self._inner)
            try:
                out = fn(url, **kwargs)
            except Exception as again:
                if not is_ssl_syscall(again):
                    raise
                exc = again
            else:
                self._fresh_tried = False
                return out
        log.warning("[login] ssl syscall persists → http/1.1: %s", exc)
        drop_curl_connections(self._inner)
        self._http1 = True
        self._inner.http_version = CurlHttpVersion.V1_1
        kwargs["http_version"] = CurlHttpVersion.V1_1
        return fn(url, **kwargs)


def open_login_session(**kwargs: Any) -> LoginTlsSession:
    return LoginTlsSession(create_session(**kwargs))
