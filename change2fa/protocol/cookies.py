"""Essential cookie whitelist — avoid CF 431.

NextAuth JWT + csrf + oai-did/sc + oai-is + cf_clearance + __cf_bm.
Skip analytics (_dd_s, ajs_*). Full jar → Cookie ~8KB → 431.
"""

from __future__ import annotations

from typing import Any

_CF_COOKIE_NAMES = frozenset({"__cf_bm", "cf_clearance"})

ESSENTIAL_PREFIXES: tuple[str, ...] = (
    "__Secure-next-auth.session-token",
    "__Host-next-auth.csrf-token",
    "__Secure-next-auth.csrf-token",
    "__Secure-oai-is",
    "oai-did",
    "oai-asli",
    "oai-mweb-route-desktop",
    "oai-mweb-origin",
    "oai-sc",
    "cf_clearance",
    "__cf_bm",
)


def is_essential(name: str) -> bool:
    return any(name.startswith(p) for p in ESSENTIAL_PREFIXES)


def filter_essential(cookies: dict[str, str]) -> dict[str, str]:
    """Keep whitelist only; deterministic key order."""
    out: dict[str, str] = {}
    for name in sorted(cookies):
        value = cookies[name]
        if is_essential(name) and value:
            out[name] = value
    return out


def build_cookie_header(cookies: dict[str, str]) -> str:
    parts = [
        f"{name}={value}"
        for name, value in sorted(cookies.items())
        if is_essential(name) and value
    ]
    return "; ".join(parts)


def session_token_from_cookies(cookies: dict[str, str]) -> str:
    """Join NextAuth session-token (+ ``.0`` / ``.1`` chunks)."""
    from change2fa.protocol.login.endpoints import COOKIE_SESSION

    if cookies.get(COOKIE_SESSION):
        return cookies[COOKIE_SESSION]
    chunks: list[tuple[int, str]] = []
    prefix = COOKIE_SESSION + "."
    for k, v in cookies.items():
        if k.startswith(prefix) and k[len(prefix) :].isdigit():
            chunks.append((int(k[len(prefix) :]), v))
    chunks.sort(key=lambda x: x[0])
    return "".join(v for _, v in chunks)


def snapshot_session(session: Any) -> dict[str, str]:
    """Essential cookies from a curl_cffi / requests session jar."""
    raw: dict[str, str] = {}
    try:
        for c in session.cookies.jar:
            name = getattr(c, "name", None)
            value = getattr(c, "value", None)
            if isinstance(name, str) and isinstance(value, str) and name:
                raw[name] = value
    except Exception:
        try:
            raw = {
                str(k): str(v)
                for k, v in dict(session.cookies).items()
                if k is not None and v is not None
            }
        except Exception:
            pass
    return filter_essential(raw)


def is_cf_cookie(name: str) -> bool:
    return name in _CF_COOKIE_NAMES


def auth_cookies(cookies: dict[str, str]) -> dict[str, str]:
    """Session/identity only — old CF must not ride along."""
    return {
        name: value
        for name, value in filter_essential(cookies).items()
        if not is_cf_cookie(name)
    }


def cf_cookies(cookies: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in filter_essential(cookies).items()
        if is_cf_cookie(name)
    }


def merge_cookies_cf_wins(
    cached: dict[str, str], warmed: dict[str, str]
) -> dict[str, str]:
    """New CF from warm/request beats cached clearance."""
    return {**auth_cookies(cached), **cf_cookies(warmed)}


def clear_jar(session: Any) -> None:
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return
    clearer = getattr(cookies, "clear", None)
    if callable(clearer):
        try:
            clearer()
            return
        except Exception:
            pass
    try:
        for cookie in list(getattr(cookies, "jar", ())):
            name = getattr(cookie, "name", "")
            if name:
                cookies.set(name, "", domain=".chatgpt.com")
    except Exception:
        pass


def run_isolated_cookie_request(
    session: Any, cookie_header: str, request_fn: Any
) -> Any:
    """Send an explicit Cookie header without merging the live jar."""
    saved = snapshot_session(session)
    try:
        clear_jar(session)
        return request_fn(cookie_header)
    finally:
        restore_essential(session, merge_cookies_cf_wins(saved, snapshot_session(session)))


def restore_essential(session: Any, cookies: dict[str, str]) -> None:
    """Restore essential cookies on both chatgpt.com hosts (ref session_from_output)."""
    for name, value in filter_essential(cookies).items():
        for domain in (".chatgpt.com", "chatgpt.com"):
            try:
                session.cookies.set(name, value, domain=domain)
            except Exception:
                try:
                    session.cookies.set(name, value)
                    break
                except Exception:
                    pass
