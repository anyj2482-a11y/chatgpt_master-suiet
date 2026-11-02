"""Cloudflare soft-retry helpers (rust auth_gpt login/revalidate parity)."""

from __future__ import annotations

import time

from change2fa.protocol.login.errors import has_cf_marker
from change2fa.protocol.login.timings import GET_ATTEMPTS, WARM_CF

HTTP_RETRY_ATTEMPTS = GET_ATTEMPTS
# Ref login_one has no outer restart. Proxy fallback rotates instead.
LOGIN_PIPELINE_ATTEMPTS = 1


def is_cf_challenge(
    status: int, cf_mitigated: str | None, body: str
) -> bool:
    """Detect CF interstitial — used by offer/revalidate, not authorize login."""
    if (cf_mitigated or "").lower() == "challenge":
        return True
    return status == 403 and has_cf_marker(body or "")


def is_oauth_bootstrap_retryable(error: str | None) -> bool:
    """Outer login restart — rust ``is_oauth_bootstrap_retryable`` (narrow)."""
    if not error:
        return False
    m = error.lower()
    # Match rust is_oauth_bootstrap_retryable — do NOT restart client+prime
    # for Python-only csrf jar deep-check (amplifies CF 403 on shared IPs).
    return (
        "invalid_state" in m
        or "authorize/continue http 409" in m
        or "csrf http 403" in m
        or "providers http 403" in m
        or "signin http 403" in m
        or "signin url not auth.openai.com" in m
        or "csrf=true" in m
        or "signin csrf rejected" in m
        or "cf: authorize" in m
        or "authorize http 403" in m
        or "cloudflare 403 during bootstrap" in m
        or "cloudflare 403 during login_with" in m
    )


# Back-compat alias used by older tests / callers
def is_cf_session_retryable(error: str | None) -> bool:
    return is_oauth_bootstrap_retryable(error)


def backoff_sleep(attempt: int, *, unit: float = 5.0) -> None:
    """Sleep (attempt+1)*unit seconds (attempt is 0-based)."""
    time.sleep((attempt + 1) * unit)


def bootstrap_backoff_sleep(attempt: int) -> None:
    """Outer oauth bootstrap wait — rust (attempt+1) seconds (1s, 2s)."""
    time.sleep(float(attempt + 1))


def warm_cf(session, url: str, headers: dict) -> None:
    """Best-effort GET warm — soft-accept any status (offer/revalidate only)."""
    try:
        session.get(url, headers=headers, allow_redirects=True, timeout=WARM_CF)
    except Exception:
        pass
