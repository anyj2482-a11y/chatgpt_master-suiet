"""Authorize landing classify + continue (ref authorize.py)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.cf_retry import is_cf_challenge
from change2fa.protocol.login.errors import annotate_login_error
from change2fa.protocol.login.headers import auth_api_headers, authorize_nav_headers
from change2fa.protocol.login.redirect import AUTH_LOGIN_HOSTS, get_follow, is_safe_http_url
from change2fa.protocol.login.result import LoginResult
from change2fa.protocol.login.timings import AUTHORIZE_DEADLINE_S, GET_ATTEMPTS, HOP

log = logging.getLogger(__name__)

SENTINEL_FLOW_AUTHORIZE = "authorize_continue"


class LandingFlow(StrEnum):
    PASSWORD = "password"
    OTP_PASSWORDLESS = "otp_passwordless"
    EMAIL_CONTINUE = "email_continue"
    SUCCESS = "success"
    UNKNOWN = "unknown"


@dataclass
class AuthorizeContinueResult:
    page_type: str
    continue_url: str


def detect_flow(landing_url: str) -> LandingFlow:
    path = urlparse(landing_url or "").path or "/"
    if path.startswith("/log-in/password") or path.startswith("/password"):
        return LandingFlow.PASSWORD
    if path.startswith("/email-verification"):
        return LandingFlow.OTP_PASSWORDLESS
    if path.startswith("/log-in/success"):
        return LandingFlow.SUCCESS
    if path.rstrip("/") in {"/log-in", "/log-in/email"} or path.startswith(
        "/log-in/email"
    ):
        return LandingFlow.EMAIL_CONTINUE
    return LandingFlow.UNKNOWN


def needs_reauthorize(url: str) -> bool:
    return detect_flow(url) == LandingFlow.SUCCESS


def _rewrite_json_authorize_landing(resp: Any, landing: str) -> str:
    """Guide: JSON /api/accounts/authorize — only known password/OTP types."""
    path = urlparse(landing or "").path or ""
    if not path.startswith("/api/accounts/authorize"):
        return landing
    try:
        headers = getattr(resp, "headers", None) or {}
        ctype = str(headers.get("content-type") or headers.get("Content-Type") or "")
    except Exception:
        ctype = ""
    if "json" not in ctype.lower():
        return landing
    try:
        data = resp.json() or {}
    except Exception:
        return landing
    if not isinstance(data, dict):
        return landing
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    ptype = str(page.get("type") or data.get("type") or "")
    if ptype in {"login_password", "password"}:
        return f"{ep.AUTH_BASE}/log-in/password"
    if ptype in {"email_otp_verification", "email_verification"}:
        return f"{ep.AUTH_BASE}/email-verification"
    return landing


def read_device_id_from_jar(session: Any, default: str) -> str:
    try:
        for c in session.cookies.jar:
            if c.name == "oai-did" and c.value:
                return str(c.value)
    except Exception:
        pass
    try:
        v = session.cookies.get("oai-did")
        if v:
            return str(v)
    except Exception:
        pass
    return default


def step_authorize(
    session: Any, authorize_url: str, referer: str | None = None
) -> str | LoginResult:
    """GET authorize, follow ≤12 hops by hand. CF 403 is not email-continue."""
    if not is_safe_http_url(authorize_url, allowed_hosts=AUTH_LOGIN_HOSTS):
        return LoginResult(
            ok=False,
            error=annotate_login_error("authorize url not auth.openai.com/chatgpt.com"),
        )
    try:
        resp, landing = get_follow(
            session,
            authorize_url,
            authorize_nav_headers(referer),
            hop_attempts=GET_ATTEMPTS,
            deadline_s=AUTHORIZE_DEADLINE_S,
        )
    except Exception as e:
        return LoginResult(
            ok=False, error=annotate_login_error(f"authorize transport: {e}")
        )
    landing = _rewrite_json_authorize_landing(resp, landing or authorize_url)
    status = int(getattr(resp, "status_code", 0) or 0)
    body = getattr(resp, "text", None) or ""
    cf_mit = None
    try:
        cf_mit = (getattr(resp, "headers", None) or {}).get("cf-mitigated")
    except Exception:
        cf_mit = None
    log.info(
        "[login] authorize hop status=%s url=%s body=%s",
        status,
        landing[:120],
        body[:160],
    )
    if is_cf_challenge(status, cf_mit, body):
        return LoginResult(
            ok=False,
            error=annotate_login_error(
                f"authorize HTTP {status}: just a moment",
                status_code=status,
            ),
        )
    return landing


def step_authorize_continue(
    session: Any, email: str, device_id: str
) -> AuthorizeContinueResult | str:
    """POST authorize/continue — ref `{username: email}`, no sentinel."""
    log.info("[login] email landing → authorize/continue")
    try:
        r = session.post(
            ep.URL_AUTHORIZE_CONTINUE,
            headers=auth_api_headers(
                device_id, referer=f"{ep.AUTH_BASE}/log-in"
            ),
            json={"username": email},
            timeout=HOP,
        )
    except Exception as e:
        return f"authorize/continue: {e}"
    text = r.text or ""
    log.info("[login] authorize/continue status=%s body=%s", r.status_code, text[:160])
    if r.status_code == 409 or "invalid_state" in text.lower():
        return "invalid_state"
    if r.status_code >= 400:
        return f"authorize/continue HTTP {r.status_code}: {text[:200]}"
    try:
        payload = r.json() or {}
    except Exception as e:
        return f"authorize/continue JSON: {e}"
    continue_url = payload.get("continue_url") or payload.get("url") or ""
    nav = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Upgrade-Insecure-Requests": "1",
        "Referer": "https://auth.openai.com/",
    }
    try:
        start = (
            str(continue_url)
            if continue_url and str(continue_url).startswith("http")
            else f"{ep.AUTH_BASE}/log-in/password"
        )
        page, final_url = get_follow(
            session,
            start,
            nav,
            hop_attempts=GET_ATTEMPTS,
            deadline_s=AUTHORIZE_DEADLINE_S,
        )
        final_url = final_url or str(getattr(page, "url", None) or start)
    except Exception as e:
        return f"authorize/continue follow: {e}"
    flow = detect_flow(final_url)
    if flow == LandingFlow.PASSWORD:
        page_type = "login_password"
    elif flow == LandingFlow.OTP_PASSWORDLESS:
        page_type = "email_otp_verification"
    else:
        page_type = ""
    return AuthorizeContinueResult(page_type=page_type, continue_url=final_url)
