"""Step 0: warm CF via GET chatgpt.com/ (ref bootstrap), seed oai-did first."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import quote, urlencode

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.headers import bootstrap_nav_headers, login_with_nav_headers
from change2fa.protocol.login.net_retry import send_with_retry
from change2fa.protocol.login.result import LoginResult
from change2fa.protocol.login.timings import BOOTSTRAP_HTTP_ATTEMPTS, BOOTSTRAP_TIMEOUT

log = logging.getLogger(__name__)


class PrimeTransportError(RuntimeError):
    """Bootstrap GET exhausted transport — rust LoginError::Network."""


def build_login_with_url(email: str, device_id: str, logging_id: str) -> str:
    """HAR `/auth/login_with` — Check bootstrap + NextAuth referer."""
    qs = urlencode(
        {
            "callback_path": "/",
            "screen_hint": "login_or_signup",
            "login_hint": email,
            "auth_session_logging_id": logging_id,
            "ext-oai-did": device_id,
        },
        quote_via=quote,
        safe="",
    )
    return f"{ep.URL_LOGIN_WITH}?{qs}"


def _jar_has_cookie(session: Any, name: str) -> bool:
    try:
        for c in session.cookies.jar:
            if c.name == name:
                return True
    except Exception:
        pass
    try:
        return bool(session.cookies.get(name))
    except Exception:
        return False


def _set_cookie(session: Any, name: str, value: str, domain: str) -> None:
    try:
        session.cookies.set(name, value, domain=domain, path="/", secure=True)
        return
    except TypeError:
        pass
    try:
        session.cookies.set(name, value, domain=domain)
    except TypeError:
        session.cookies.set(name, value)


def _set_chatgpt_cookie(session: Any, name: str, value: str) -> None:
    """Ref sets oai-did on both `.chatgpt.com` and `chatgpt.com`."""
    _set_cookie(session, name, value, ".chatgpt.com")
    _set_cookie(session, name, value, "chatgpt.com")


def seed_chatgpt_bootstrap_cookies(
    session: Any, device_id: str, logging_id: str
) -> None:
    """Seed browser-like chatgpt.com cookies before bootstrap GET."""
    if device_id and not _jar_has_cookie(session, "oai-did"):
        _set_chatgpt_cookie(session, "oai-did", device_id)
    if logging_id and not _jar_has_cookie(session, "oai-asli"):
        _set_chatgpt_cookie(session, "oai-asli", logging_id)
    if not _jar_has_cookie(session, "oai-mweb-route-desktop"):
        _set_chatgpt_cookie(session, "oai-mweb-route-desktop", "1")
    if not _jar_has_cookie(session, "oai-mweb-origin"):
        _set_chatgpt_cookie(session, "oai-mweb-origin", "1")


def _warm_nav(session: Any, url: str, headers: dict[str, str]) -> int:
    """Document GET to collect CF cookies. HTML 403 is not fatal (HAR/live)."""
    t0 = time.monotonic()
    try:
        send_with_retry(
            "bootstrap",
            BOOTSTRAP_HTTP_ATTEMPTS,
            lambda: session.get(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=BOOTSTRAP_TIMEOUT,
            ),
        )
    except Exception as e:
        raise PrimeTransportError(f"bootstrap attempt: {e}") from e
    return int((time.monotonic() - t0) * 1000)


def _note_hop(progress: Any | None, label: str, ms: int) -> None:
    log.info("[login] bootstrap %s %dms", label, ms)
    if progress is not None:
        progress.note("bootstrap", f"{label} {ms}ms")


def step_prime(
    session: Any,
    email: str,
    device_id: str,
    logging_id: str,
    *,
    proxy_url: str | None = None,
    progress: Any | None = None,
) -> str | LoginResult:
    """Seed mweb cookies, warm home + login_with. Document CF is not fatal."""
    _ = proxy_url
    seed_chatgpt_bootstrap_cookies(session, device_id, logging_id)
    log.info("[login] [0/9] bootstrap GET chatgpt.com/ + login_with")
    home_ms = _warm_nav(session, f"{ep.CHATGPT_BASE}/", bootstrap_nav_headers())
    _note_hop(progress, "GET chatgpt.com/", home_ms)
    login_with = build_login_with_url(email, device_id, logging_id)
    login_ms = _warm_nav(session, login_with, login_with_nav_headers())
    _note_hop(progress, "GET /auth/login_with", login_ms)
    return login_with
