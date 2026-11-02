"""Login / Check error taxonomy — CF vs lock/429 markers + stable prefixes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

from change2fa.protocol.login.net_retry import is_aborted_session

# Stable prefixes in Check/login `error` strings (FE treats error as free text).
CF_PREFIX = "cf:"
LOCK_PREFIX = "lock:"

EMAIL_VERIFICATION_MSG = (
    "email-verification: inbox OTP required (not MFA TOTP); "
    "passwordless OTP not supported"
)

_CF_MARKERS = (
    "cloudflare",
    "cf-ray",
    "cf_clearance",
    "just a moment",
    "attention required",
    "cf-browser-verification",
    "challenge-platform",
    "error code 1020",
    "error 1020",
    "access denied",
    "cf-challenge",
    "cf-chl",
    "cf-mitigated",
    "/cdn-cgi/challenge",
    "<title>blocked",
)

_CREDENTIAL_CODES = frozenset({"invalid_password", "invalid_credential"})
_RESTRICT_CODES = frozenset(
    {
        "account_locked",
        "account_disabled",
        "account_deactivated",
        "deactivated",
        "deleted",
        "banned",
        "suspended",
    }
)

_LOCK_MARKERS = (
    "too many",
    "rate limit",
    "rate_limit",
    "locked",
    "lockout",
    "temporarily unavailable",
    "try again later",
    "429",
    "account_locked",
    "suspicious",
)


def has_cf_marker(text: str) -> bool:
    blob = (text or "").lower()
    return any(m in blob for m in _CF_MARKERS)


def is_cloudflare_block(
    error: str, step: str = "", status_code: int | None = None
) -> bool:
    """Cloudflare 403 / challenge — not a generic HTTP 403."""
    blob = f"{step} {error}".lower()
    marked = has_cf_marker(blob)
    if status_code == 403 and marked:
        return True
    if "http 403" in blob and marked:
        return True
    if "cloudflare 403" in blob or "cf challenge" in blob:
        return True
    if "just a moment" in blob and "cloudflare" in blob:
        return True
    if status_code == 403 and ("cf-" in blob or "blocked" in blob):
        return True
    return False


def is_lock_or_rate_limit(error: str, step: str = "") -> bool:
    """Account lock / 429 / rate-limit — excludes Cloudflare blocks."""
    if is_cloudflare_block(error, step):
        return False
    blob = f"{step} {error}".lower()
    return any(m in blob for m in _LOCK_MARKERS)


def one_line(text: str) -> str:
    """Account error output is one line — collapse HTML / log newlines."""
    return " ".join(text.split())


_NEXTAUTH_HOPS = frozenset(
    {"providers", "csrf", "signin", "authorize", "session", "me"}
)
_HTML_MARKERS = ("<html", "<!doctype", "<head", "<style", "<meta", "<body")
_NEXTAUTH_403_RE = re.compile(
    r"\b(?:providers|csrf|signin|authorize|session|me)\b.*\bhttp 403\b",
    re.I,
)
_NEXTAUTH_403_HEAD = re.compile(
    r"^(?P<pre>(?:cf:\s+|lock:\s+)?)(?P<head>.+?\bHTTP\s+403)(?:\s*:\s*(?P<body>.*))?$",
    re.I,
)
_PROXY_SUFFIX = re.compile(r"\s*\(proxy \d+/\d+\)\s*$")


def _looks_like_html(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in _HTML_MARKERS)


def is_nextauth_http_403(error: str) -> bool:
    return bool(_NEXTAUTH_403_RE.search(error or ""))


def strip_nextauth_html_body(error: str) -> str:
    """`providers HTTP 403: <html>…` → `providers HTTP 403`. Keep non-HTML snips."""
    m = _NEXTAUTH_403_HEAD.match(error or "")
    if not m:
        return error
    blob = f"{m.group('pre')}{m.group('head')}".lower()
    if not any(h in blob for h in _NEXTAUTH_HOPS):
        return error
    body = (m.group("body") or "").strip()
    if body and not _looks_like_html(body):
        return error
    pre = (m.group("pre") or "").strip()
    head = m.group("head").strip()
    return f"{pre} {head}".strip() if pre else head


def hop_http_error(label: str, status: int, body: str = "") -> str:
    """NextAuth 403 is `cf: {label} HTTP 403` — no HTML body (product)."""
    base = f"{label} HTTP {status}"
    if status == 403 and label.lower() in _NEXTAUTH_HOPS:
        return annotate_login_error(base, status_code=403) or f"{CF_PREFIX} {base}"
    snip = one_line(body or "")[:200]
    if snip and not _looks_like_html(snip):
        base = f"{base}: {snip}"
    return annotate_login_error(base, status_code=status) or base


def annotate_login_error(error: str | None, status_code: int | None = None) -> str | None:
    """Prefix `cf:` / `lock:` once. NextAuth 403 drops HTML. Else unchanged."""
    if error is None:
        return None
    msg = strip_nextauth_html_body(one_line(error))
    if not msg:
        return error
    if is_aborted_session(msg):
        return "cancelled"
    low = msg.lower()
    if low.startswith(CF_PREFIX) or low.startswith(LOCK_PREFIX):
        return msg
    if is_cloudflare_block(msg, status_code=status_code) or is_nextauth_http_403(msg):
        return f"{CF_PREFIX} {msg}"
    if is_lock_or_rate_limit(msg):
        return f"{LOCK_PREFIX} {msg}"
    return msg


def annotate_proxy_attempts(
    error: str | None, *, attempt: int, max_attempts: int
) -> str | None:
    """Suffix `(proxy k/n)` after a rotate. Pool 0/1 and first shot stay bare."""
    msg = annotate_login_error(error)
    if not msg or max_attempts <= 1 or attempt <= 1:
        return msg
    if _PROXY_SUFFIX.search(msg):
        return msg
    return f"{msg} (proxy {attempt}/{max_attempts})"


@dataclass(frozen=True)
class PasswordBodyClass:
    error: str
    fatal: bool


def _collect_codes(obj: Any, *, depth: int = 0, remaining: list[int] | None = None) -> list[str]:
    """Guide: code field in error/errors/data/result/page, depth 3, 16 objects."""
    if remaining is None:
        remaining = [16]
    if depth > 3 or remaining[0] <= 0:
        return []
    codes: list[str] = []
    if isinstance(obj, list):
        for item in obj:
            if remaining[0] <= 0:
                break
            if isinstance(item, dict):
                remaining[0] -= 1
                codes.extend(_collect_codes(item, depth=depth + 1, remaining=remaining))
        return codes
    if not isinstance(obj, dict):
        return []
    remaining[0] -= 1
    code = obj.get("code")
    if isinstance(code, str) and code:
        codes.append(code)
    for key in ("error", "errors", "data", "result", "page"):
        if key in obj:
            codes.extend(_collect_codes(obj[key], depth=depth + 1, remaining=remaining))
    return codes


def classify_password_body(text: str) -> PasswordBodyClass | None:
    """Fatal credential / lock from structured codes, then phrase fallback."""
    payload: Any = None
    raw = (text or "").strip()
    if raw.startswith("{") or raw.startswith("["):
        try:
            payload = json.loads(raw)
        except Exception:
            payload = None
    if payload is not None:
        codes = _collect_codes(payload)
        for code in codes:
            low = code.lower()
            if low in _CREDENTIAL_CODES:
                return PasswordBodyClass("invalid credentials", True)
            if low in _RESTRICT_CODES:
                return PasswordBodyClass("account locked/disabled", True)
        if codes:
            return None
    lower = (text or "").lower()
    if (
        "password_incorrect" in lower
        or "incorrect password" in lower
        or ("invalid" in lower and "password" in lower and "mfa" not in lower)
    ):
        return PasswordBodyClass("invalid credentials", True)
    if any(
        x in lower
        for x in (
            "account_locked",
            "account_disabled",
            "account_deactivated",
            "banned",
            "deactivated",
        )
    ):
        return PasswordBodyClass("account locked/disabled", True)
    return None


def classify_push_auth(payload: dict[str, Any] | None, continue_url: str = "") -> str | None:
    """Device-approval checkpoint — do not follow or treat as login success."""
    page = payload.get("page") if isinstance(payload, dict) else None
    ptype = page.get("type") if isinstance(page, dict) else ""
    parsed = urlparse(continue_url or "")
    path = parsed.path or ""
    if str(ptype) != "push_auth_verification" and not path.startswith(
        "/push-auth-verification/"
    ):
        return None
    if path.startswith("/push-auth-verification/"):
        if parsed.scheme and parsed.scheme != "https":
            return "push_auth_required"
        if parsed.hostname and parsed.hostname != "auth.openai.com":
            return "push_auth_required"
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.query and (
            list(qs) != ["mfa_token"] or not (qs.get("mfa_token") or [""])[0]
        ):
            return "push_auth_required"
    return "push_auth_required"
