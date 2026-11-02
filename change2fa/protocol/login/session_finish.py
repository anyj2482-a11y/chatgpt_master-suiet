"""Shared session finalize: follow continue → /api/auth/session → /me.

Used by both the password and inbox-OTP login paths so the token/cookie
snapshot and validation stay identical.
"""

from __future__ import annotations

import re
import time
from typing import Any

from change2fa.protocol.cookies import session_token_from_cookies, snapshot_session
from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.cf_retry import warm_cf
from change2fa.protocol.login.errors import annotate_login_error, hop_http_error
from change2fa.protocol.login.headers import bootstrap_nav_headers, nextauth_headers
from change2fa.protocol.login.me import step_validate_me
from change2fa.protocol.login.redirect import follow_continue
from change2fa.protocol.login.result import LoginResult, SessionBundle
from change2fa.protocol.login.timings import HOP

_ACCESS_TOKEN_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")
_SESSION_POLL_TRIES = 4
_SESSION_POLL_SLEEPS = (0.4, 0.8, 1.2)


def _get_session_payload(
    session: Any, headers: dict[str, str]
) -> tuple[dict[str, Any], str | None]:
    r = session.get(ep.URL_SESSION, headers=headers, timeout=HOP)
    if r.status_code >= 400:
        return {}, hop_http_error("session", r.status_code, getattr(r, "text", "") or "")
    try:
        data = r.json() or {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return data, None


def _poll_session_token(
    session: Any, headers: dict[str, str]
) -> tuple[dict[str, Any], str, str | None]:
    """Empty `{}` may settle; HTTP 403/5xx fail so Check can rotate proxy."""
    data: dict[str, Any] = {}
    warmed = False
    for i in range(_SESSION_POLL_TRIES):
        data, sess_err = _get_session_payload(session, headers)
        if sess_err:
            return {}, "", sess_err
        access = session_access_token(data)
        if access:
            return data, access, None
        if not warmed:
            warm_cf(session, f"{ep.CHATGPT_BASE}/", bootstrap_nav_headers())
            warmed = True
        if i + 1 < _SESSION_POLL_TRIES:
            time.sleep(_SESSION_POLL_SLEEPS[i])
    return data, "", None


def session_access_token(data: dict[str, Any] | None) -> str:
    """Fresh login token — top-level or user.*, no whitespace rescue."""
    if not isinstance(data, dict):
        return ""
    user = data.get("user") if isinstance(data.get("user"), dict) else {}
    for raw in (
        data.get("accessToken"),
        data.get("access_token"),
        user.get("accessToken"),
        user.get("access_token"),
    ):
        if not isinstance(raw, str) or not raw:
            continue
        if any(ch.isspace() or ord(ch) < 32 for ch in raw):
            continue
        if _ACCESS_TOKEN_RE.fullmatch(raw):
            return raw
    return ""


def finish_authed_landing(
    session: Any,
    *,
    email: str,
    password: str,
    totp_secret: str | None,
    device_id: str,
    logging_id: str,
    landing: str,
    simple_check: bool,
    progress: Any | None = None,
) -> LoginResult:
    """Authorize already on /log-in/success — simple alive or consume session."""
    if simple_check:
        return LoginResult(
            ok=True,
            simple=True,
            bundle=SessionBundle(
                email=email,
                device_id=device_id,
                password=password,
                totp_secret=totp_secret,
            ),
        )
    return finalize_session(
        session,
        email=email,
        device_id=device_id,
        logging_id=logging_id,
        cont=landing,
        password=password,
        totp_secret=totp_secret,
        progress=progress,
    )


def finalize_session(
    session: Any,
    *,
    email: str,
    device_id: str,
    logging_id: str,
    cont: str | None,
    password: str = "",
    totp_secret: str | None = None,
    otp_url: str = "",
    progress: Any | None = None,
) -> LoginResult:
    """Follow OAuth continue, read session token + cookies, validate /me."""
    if progress is not None:
        progress.note("continue", "GET oauth continue / callback")
    cont_err = follow_continue(session, cont or None, device_id)
    if cont_err:
        return LoginResult(ok=False, error=annotate_login_error(cont_err))

    if progress is not None:
        progress.note("session", "GET /api/auth/session")
    sess_headers = nextauth_headers(
        f"{ep.CHATGPT_BASE}/",
        device_id=device_id,
        session_id=logging_id,
    )
    sess_headers["accept"] = "application/json"
    data, access, sess_err = _poll_session_token(session, sess_headers)
    if sess_err:
        return LoginResult(ok=False, error=sess_err)
    cookies = snapshot_session(session)
    st = session_token_from_cookies(cookies) or ""
    if not access:
        return LoginResult(
            ok=False, error=annotate_login_error("no accessToken in session")
        )

    if progress is not None:
        progress.note("me", "GET /backend-api/me")
    me_err = step_validate_me(
        session,
        access_token=access,
        email=email,
        device_id=device_id,
        session_id=logging_id,
    )
    if me_err is not None:
        return me_err

    return LoginResult(
        ok=True,
        simple=False,
        bundle=SessionBundle(
            email=email,
            access_token=access,
            session_token=st,
            cookies=cookies,
            device_id=device_id,
            password=password,
            totp_secret=totp_secret,
            otp_url=otp_url,
            session_payload=data,
        ),
    )
