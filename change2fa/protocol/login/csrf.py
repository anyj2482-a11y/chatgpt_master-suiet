"""GET /api/auth/providers then /csrf — HAR NextAuth + guide identity."""

from __future__ import annotations

from typing import Any

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.errors import hop_http_error
from change2fa.protocol.login.headers import nextauth_headers
from change2fa.protocol.login.result import LoginResult
from change2fa.protocol.login.timings import HOP


def _get(
    session: Any,
    url: str,
    headers: dict[str, str],
    label: str,
    *,
    keep_origin: bool = False,
) -> Any | LoginResult:
    if keep_origin:
        get_headers = headers
    else:
        get_headers = {k: v for k, v in headers.items() if k.lower() != "origin"}
    try:
        r = session.get(url, headers=get_headers, allow_redirects=True, timeout=HOP)
    except Exception as e:
        return LoginResult(ok=False, error=f"{label} attempt 0: {e}", fatal=False)
    if r.status_code >= 400:
        return LoginResult(
            ok=False,
            error=hop_http_error(label, r.status_code, r.text or ""),
            fatal=False,
        )
    return r


def step_csrf(
    session: Any,
    device_id: str,
    session_id: str,
    referer: str | None = None,
) -> str | LoginResult:
    headers = nextauth_headers(referer, device_id=device_id, session_id=session_id)
    providers = _get(session, ep.URL_PROVIDERS, headers, "providers")
    if isinstance(providers, LoginResult):
        return providers
    csrf_headers = dict(headers)
    csrf_headers["accept"] = "application/json"
    r = _get(session, ep.URL_CSRF, csrf_headers, "csrf", keep_origin=True)
    if isinstance(r, LoginResult):
        return r
    try:
        ctype = str((getattr(r, "headers", None) or {}).get("content-type") or "")
    except Exception:
        ctype = ""
    if "json" not in ctype.lower() and "html" in ctype.lower():
        return LoginResult(ok=False, error="csrf invalid response", fatal=False)
    try:
        csrf = (r.json() or {}).get("csrfToken") or ""
    except Exception:
        csrf = ""
    if not csrf:
        return LoginResult(
            ok=False, error="csrf missing csrfToken field", fatal=False
        )
    if not isinstance(csrf, str) or not csrf.strip() or csrf != csrf.strip():
        return LoginResult(ok=False, error="csrf invalid csrfToken field", fatal=False)
    return csrf
