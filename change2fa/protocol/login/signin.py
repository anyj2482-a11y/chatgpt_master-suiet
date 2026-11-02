"""POST signin/openai + reauthorize without login_hint."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.csrf import step_csrf
from change2fa.protocol.login.errors import annotate_login_error, hop_http_error
from change2fa.protocol.login.headers import nextauth_headers
from change2fa.protocol.login.landing import step_authorize
from change2fa.protocol.login.result import LoginResult
from change2fa.protocol.login.timings import HOP


def is_auth_authorize_url(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme == "https"
        and (parsed.hostname or "").lower() == "auth.openai.com"
        and not parsed.username
        and parsed.port in (None, 443)
        and bool(parsed.path)
    )


def _content_type(resp: Any) -> str:
    try:
        headers = getattr(resp, "headers", None) or {}
        return str(headers.get("content-type") or headers.get("Content-Type") or "")
    except Exception:
        return ""


def post_signin(
    session: Any,
    *,
    csrf: str,
    device_id: str,
    logging_id: str,
    referer: str,
    login_hint: str | None,
) -> str | LoginResult:
    params = {
        "prompt": "login",
        "ext-passkey-client-capabilities": "01001",
        "auth_session_logging_id": logging_id,
        "screen_hint": "login_or_signup",
        "ext-oai-did": device_id,
    }
    if login_hint:
        params["login_hint"] = login_hint
    headers = nextauth_headers(referer, device_id=device_id, session_id=logging_id)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    r = session.post(
        ep.URL_SIGNIN_OPENAI,
        params=params,
        headers=headers,
        data={"callbackUrl": f"{ep.CHATGPT_BASE}/", "csrfToken": csrf, "json": "true"},
        allow_redirects=False,
        timeout=HOP,
    )
    if r.status_code != 200:
        return LoginResult(
            ok=False,
            error=hop_http_error("signin", r.status_code, r.text or ""),
        )
    ctype = _content_type(r).lower()
    if "json" not in ctype and "html" in ctype:
        return LoginResult(
            ok=False,
            error=annotate_login_error("signin invalid response"),
        )
    body: dict[str, Any] = {}
    try:
        body = r.json() or {}
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    authorize_url = str(body.get("url") or r.headers.get("Location") or "")
    if not authorize_url:
        return LoginResult(ok=False, error=annotate_login_error("no authorize url"))
    from change2fa.protocol.login.csrf_jar import jar_has_next_auth_csrf

    jar_csrf = jar_has_next_auth_csrf(session)
    if "csrf=true" in authorize_url.lower():
        return LoginResult(
            ok=False,
            error=annotate_login_error(
                f"signin CSRF rejected (url={authorize_url[:200]}; "
                f"jar_has_csrf_cookie={jar_csrf}) — "
                "token/cookie mismatch or bot soft-block"
            ),
        )
    if not is_auth_authorize_url(authorize_url):
        return LoginResult(
            ok=False,
            error=annotate_login_error(
                f"signin url not auth.openai.com: {authorize_url[:200]} "
                f"(jar_has_csrf_cookie={jar_csrf})"
            ),
        )
    return authorize_url


def step_reauthorize(
    session: Any,
    *,
    device_id: str,
    logging_id: str,
    referer: str,
) -> str | LoginResult:
    """CSRF + signin without login_hint, then follow authorize (no prime)."""
    csrf = step_csrf(session, device_id, logging_id, referer=referer)
    if isinstance(csrf, LoginResult):
        return csrf
    authorize_url = post_signin(
        session,
        csrf=csrf,
        device_id=device_id,
        logging_id=logging_id,
        referer=referer,
        login_hint=None,
    )
    if isinstance(authorize_url, LoginResult):
        return authorize_url
    return step_authorize(session, authorize_url, referer=referer)
