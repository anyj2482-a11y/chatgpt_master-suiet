"""NextAuth CSRF jar deep-check (rust auth_gpt/login/steps/csrf_jar.rs)."""

from __future__ import annotations

from typing import Any

_CSRF_NAME_SUBSTR = "next-auth.csrf-token"


def _domain_ok(domain: str | None) -> bool:
    d = (domain or "").lstrip(".").lower()
    # __Host- cookies are host-only (domain often empty); chatgpt.com jar only.
    return d in ("", "chatgpt.com")


def jar_next_auth_csrf_raw(session: Any) -> str | None:
    """First *next-auth.csrf-token* value; decode %7C → |. Empty value → missing."""
    try:
        for c in session.cookies.jar:
            name = getattr(c, "name", "") or ""
            if _CSRF_NAME_SUBSTR not in name:
                continue
            if not _domain_ok(getattr(c, "domain", None)):
                continue
            value = (getattr(c, "value", None) or "").strip()
            if not value:
                return None
            return value.replace("%7C", "|").replace("%7c", "|")
    except Exception:
        pass
    try:
        for name, value in dict(session.cookies).items():
            if _CSRF_NAME_SUBSTR not in (name or ""):
                continue
            v = (value or "").strip()
            if not v:
                return None
            return v.replace("%7C", "|").replace("%7c", "|")
    except Exception:
        pass
    return None


def jar_has_next_auth_csrf(session: Any) -> bool:
    return jar_next_auth_csrf_raw(session) is not None


def csrf_token_matches_jar(csrf_token: str, cookie_raw: str) -> bool:
    """JSON csrfToken must equal cookie prefix before first '|'."""
    token_part = cookie_raw.split("|", 1)[0]
    return bool(csrf_token) and token_part == csrf_token
