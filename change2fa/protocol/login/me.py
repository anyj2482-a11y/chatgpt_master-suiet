"""GET /backend-api/me after full login — email match + disabled check."""

from __future__ import annotations

import uuid
from typing import Any

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.cf_retry import warm_cf
from change2fa.protocol.login.errors import annotate_login_error, hop_http_error
from change2fa.protocol.login.headers import (
    LOGIN_IMPERSONATE,
    OAI_CLIENT_BUILD_NUMBER,
    OAI_CLIENT_VERSION,
    apply_browser_session_headers,
    login_with_nav_headers,
)
from change2fa.protocol.login.result import LoginResult
from change2fa.protocol.login.timings import HOP

_DISABLED_MARKERS = (
    "account_disabled",
    "account_deactivated",
    "account_locked",
    "deactivated",
    "banned",
)


def _headers(
    access_token: str, device_id: str, session_id: str = ""
) -> dict[str, str]:
    # HAR GET /backend-api/me: Accept */*, no Origin, fresh oai-session-id.
    return {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "referer": f"{ep.CHATGPT_BASE}/",
        "authorization": f"Bearer {access_token}",
        "oai-device-id": device_id or "",
        "oai-session-id": session_id or str(uuid.uuid4()),
        "oai-client-version": OAI_CLIENT_VERSION,
        "oai-client-build-number": OAI_CLIENT_BUILD_NUMBER,
        "oai-language": "en-US",
        "x-openai-target-path": "/backend-api/me",
    }


def me_indicates_disabled(me: dict[str, Any], body: str = "") -> bool:
    blob = (body or "").lower()
    if any(m in blob for m in _DISABLED_MARKERS):
        return True
    for key in ("account_deactivated", "deactivated", "disabled", "banned"):
        if me.get(key) is True:
            return True
    return False


def validate_me(me: dict[str, Any], expected_email: str) -> LoginResult | None:
    """None if OK; LoginResult on mismatch / disabled."""
    if me_indicates_disabled(me):
        return LoginResult(
            ok=False,
            error=annotate_login_error("me: account disabled"),
            fatal=True,
        )
    got = str(me.get("email") or "").strip().lower()
    want = (expected_email or "").strip().lower()
    if not got:
        return LoginResult(
            ok=False,
            error=annotate_login_error("me: email missing"),
            fatal=False,
        )
    if got != want:
        return LoginResult(
            ok=False,
            error=annotate_login_error(f"me: email mismatch (got {got})"),
            fatal=True,
        )
    return None


def is_me_retryable(err: LoginResult | None) -> bool:
    """Guide: 403/timeout/5xx after cache warm are inconclusive, not dead token."""
    if err is None or err.fatal:
        return False
    msg = (err.error or "").lower()
    if "me http 401" in msg:
        return False
    return (
        "me http 403" in msg
        or "me http 408" in msg
        or "me http 425" in msg
        or "me http 429" in msg
        or "me transport" in msg
        or any(f"me http {code}" in msg for code in range(500, 600))
    )


def revalidate_cached(
    bundle: Any,
    *,
    email: str,
    proxy_url: str | None,
) -> LoginResult | None:
    """Warm /auth/login then GET /me. One 403 retry. None = reuse."""
    from change2fa.protocol.cookies import (
        auth_cookies,
        build_cookie_header,
        merge_cookies_cf_wins,
        restore_essential,
        run_isolated_cookie_request,
        snapshot_session,
    )
    from change2fa.protocol.http_session import create_session

    device_id = getattr(bundle, "device_id", "") or ""
    session = create_session(
        proxy_url=proxy_url, impersonate=LOGIN_IMPERSONATE, timeout=HOP
    )
    try:
        apply_browser_session_headers(session, device_id)
        cached = getattr(bundle, "cookies", {}) or {}
        restore_essential(session, auth_cookies(cached))
        token = getattr(bundle, "access_token", "") or ""

        def _me(cookie_header: str) -> LoginResult | None:
            return step_validate_me(
                session,
                access_token=token,
                email=email,
                device_id=device_id,
                session_id="",
                cookie_header=cookie_header,
            )

        def _once() -> LoginResult | None:
            header = build_cookie_header(
                merge_cookies_cf_wins(cached, snapshot_session(session))
            )
            return run_isolated_cookie_request(session, header, _me)

        # Product: cheap GET /me. Warm only after CF 403. Transport = dead hop.
        err = _once()
        msg = (err.error or "").lower() if err is not None else ""
        if err is not None and "me transport" not in msg and is_me_retryable(err):
            warm_cf(session, ep.URL_AUTH_LOGIN, login_with_nav_headers())
            err = _once()
        if err is None:
            bundle.cookies = merge_cookies_cf_wins(cached, snapshot_session(session))
        return err
    except Exception as e:
        return LoginResult(ok=False, error=f"revalidate: {e}", fatal=False)
    finally:
        try:
            session.close()
        except Exception:
            pass


def step_validate_me(
    session: Any,
    *,
    access_token: str,
    email: str,
    device_id: str,
    session_id: str = "",
    cookie_header: str = "",
) -> LoginResult | None:
    """GET /backend-api/me. None = ok; LoginResult = fail (fatal when mismatch/disabled)."""
    headers = _headers(access_token, device_id, session_id)
    if cookie_header:
        headers["Cookie"] = cookie_header
    try:
        r = session.get(
            ep.URL_ME,
            headers=headers,
            timeout=HOP,
        )
    except Exception as e:
        return LoginResult(
            ok=False,
            error=annotate_login_error(f"me transport: {e}"),
            fatal=False,
        )
    text = r.text or ""
    status = int(r.status_code)
    if status >= 400:
        if me_indicates_disabled({}, text):
            return LoginResult(
                ok=False,
                error=annotate_login_error(f"me: account disabled (HTTP {status})"),
                fatal=True,
            )
        return LoginResult(
            ok=False,
            error=hop_http_error("me", status, text),
            fatal=False,
        )
    try:
        payload = r.json() or {}
    except Exception as e:
        return LoginResult(
            ok=False,
            error=annotate_login_error(f"me JSON: {e}"),
            fatal=False,
        )
    if not isinstance(payload, dict):
        return LoginResult(
            ok=False,
            error=annotate_login_error("me: unexpected payload"),
            fatal=False,
        )
    return validate_me(payload, email)
