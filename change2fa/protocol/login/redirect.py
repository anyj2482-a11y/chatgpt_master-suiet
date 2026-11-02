"""Manual redirect follow — rust auth_gpt/login/redirect.rs parity.

curl_cffi ``allow_redirects=True`` mutates Referer per hop and can trip CF.
Rust uses Policy::none + same headers every hop.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from change2fa.protocol.cookies import session_token_from_cookies, snapshot_session
from change2fa.protocol.login.headers import callback_nav_headers
from change2fa.protocol.login.net_retry import is_aborted_session, send_with_retry
from change2fa.protocol.login.timings import GET_ATTEMPTS, HOP

log = logging.getLogger(__name__)

MAX_REDIRECT_HOPS = 12
FOLLOW_CONTINUE_HOPS = 12
FOLLOW_CONTINUE_DEADLINE_S = 15.0
CALLBACK_PATH = "/api/auth/callback/openai"
MAX_CALLBACK_QUERY_FIELDS = 16
# Cookie is optional; accessToken comes from GET /api/auth/session.
# Replaying the OAuth code 3× with 60s×3 transport retries hung jobs ~1–2 min.
CALLBACK_CONSUME_ATTEMPTS = 1
CALLBACK_HOP_TIMEOUT = HOP
CALLBACK_HOP_ATTEMPTS = 1
AUTH_LOGIN_HOSTS = frozenset({"auth.openai.com", "chatgpt.com"})
CHATGPT_HOSTS = frozenset({"chatgpt.com"})


def is_safe_http_url(
    url: str, *, allowed_hosts: frozenset[str] | None = None
) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    if parsed.username or parsed.password:
        return False
    if parsed.port not in (None, 443):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    return allowed_hosts is None or host in allowed_hosts


def is_chatgpt_callback(url: str) -> bool:
    parsed = urlparse(url)
    if not is_safe_http_url(url, allowed_hosts=CHATGPT_HOSTS):
        return False
    if (parsed.path or "") != CALLBACK_PATH or parsed.fragment:
        return False
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if len(qs) > MAX_CALLBACK_QUERY_FIELDS:
        return False
    codes = qs.get("code") or []
    return len(codes) == 1 and bool(codes[0])


def get_follow(
    session: Any,
    url: str,
    headers: dict[str, str],
    *,
    timeout: float | tuple[float, float] = HOP,
    allowed_hosts: frozenset[str] | None = AUTH_LOGIN_HOSTS,
    hop_attempts: int = GET_ATTEMPTS,
    max_hops: int = MAX_REDIRECT_HOPS,
    deadline_s: float | None = None,
) -> tuple[Any, str]:
    """GET ``url`` following redirects manually; return (last_response, final_url)."""
    current = url
    if not is_safe_http_url(current, allowed_hosts=allowed_hosts):
        raise RuntimeError(f"unsafe login url: {current[:80]}")
    tries = max(1, hop_attempts)
    t0 = time.monotonic()
    hops = max(1, min(MAX_REDIRECT_HOPS, max_hops))
    for hop in range(hops):
        if deadline_s is not None and time.monotonic() - t0 >= deadline_s:
            raise RuntimeError("redirect deadline")
        r = send_with_retry(
            "authorize_hop",
            tries,
            lambda u=current: session.get(
                u,
                headers=headers,
                allow_redirects=False,
                timeout=timeout,
            ),
        )
        status = int(r.status_code)
        if 300 <= status < 400:
            loc = r.headers.get("Location") or r.headers.get("location")
            if not loc:
                raise RuntimeError(
                    f"hop {hop} status={status} but no Location header"
                )
            nxt = _resolve_relative(current, loc)
            hosts = CHATGPT_HOSTS if is_chatgpt_callback(current) else allowed_hosts
            if not is_safe_http_url(nxt, allowed_hosts=hosts):
                return r, current
            current = nxt
            continue
        return r, current
    raise RuntimeError(
        f"too many redirects (max={hops}) starting from {url[:200]}"
    )


def follow_continue(session: Any, start_url: str | None, device_id: str) -> str | None:
    """GET OAuth continue/callback. None = ok / nothing to do. str = error."""
    _ = device_id
    if not start_url:
        return None
    reject = _continue_reject_reason(start_url)
    if reject:
        return reject
    headers = callback_nav_headers()
    hosts = CHATGPT_HOSTS if is_chatgpt_callback(start_url) else AUTH_LOGIN_HOSTS
    attempts = CALLBACK_CONSUME_ATTEMPTS if is_chatgpt_callback(start_url) else 1
    for attempt in range(attempts):
        try:
            get_follow(
                session,
                start_url,
                headers,
                timeout=CALLBACK_HOP_TIMEOUT,
                allowed_hosts=hosts,
                hop_attempts=CALLBACK_HOP_ATTEMPTS,
                max_hops=FOLLOW_CONTINUE_HOPS,
                deadline_s=FOLLOW_CONTINUE_DEADLINE_S,
            )
        except Exception as e:
            if is_aborted_session(e):
                return "cancelled"
            log.warning("[login] callback consume: %s", e)
            return f"callback consume: {e}"
        if attempts == 1 or _jar_has_session_token(session):
            return None
        if attempt + 1 < attempts:
            time.sleep(1.0)
    return None


def _continue_reject_reason(start_url: str) -> str | None:
    query = urlparse(start_url).query or ""
    q_low = query.lower()
    if "error_code=" in start_url or q_low.startswith("error=") or "&error=" in q_low:
        return f"callback oauth error: {query[:120]}"
    path = urlparse(start_url).path or ""
    if path == CALLBACK_PATH and not is_chatgpt_callback(start_url):
        return "callback missing oauth code"
    if not is_safe_http_url(start_url, allowed_hosts=AUTH_LOGIN_HOSTS):
        return "unsafe continue url"
    return None


def _jar_has_session_token(session: Any) -> bool:
    return bool(session_token_from_cookies(snapshot_session(session)))


def _resolve_relative(current: str, location: str) -> str:
    loc = location.strip()
    if loc.startswith("//"):
        scheme = urlparse(current).scheme or "https"
        return f"{scheme}:{loc}"
    return urljoin(current, loc)
