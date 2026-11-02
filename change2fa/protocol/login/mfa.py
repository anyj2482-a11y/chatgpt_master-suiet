"""MFA issue + verify — ref credentials.py / mfa.py."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.headers import LOGIN_UA, auth_api_headers
from change2fa.protocol.login.timings import HOP
from change2fa.protocol.sentinel_pow import get_sentinel_token_pow
from change2fa.protocol.totp import totp

_MFA_CHALLENGE_RE = re.compile(r"/mfa-challenge/([a-fA-F0-9]+)")


@dataclass(frozen=True)
class MfaFactor:
    factor_id: str
    factor_type: str = "totp"


def extract_continue_url(payload: dict | None, location: str = "") -> str:
    """Ref extract_callback_url — continue_url / url / redirect_* (page.payload)."""
    if isinstance(payload, dict):
        srcs: list[Any] = []
        page = payload.get("page")
        if isinstance(page, dict) and isinstance(page.get("payload"), dict):
            srcs.append(page["payload"])
        if isinstance(payload.get("payload"), dict):
            srcs.append(payload["payload"])
        srcs.append(payload)
        for src in srcs:
            for key in ("continue_url", "url", "redirect_url", "redirect_uri"):
                v = src.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return (location or "").strip()


def extract_mfa_factor(
    payload: dict | None, continue_url: str = ""
) -> MfaFactor | None:
    """Ref parse_mfa_challenge: factor_id or factors[0].id + factor_type."""
    srcs: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        page = payload.get("page")
        if isinstance(page, dict) and isinstance(page.get("payload"), dict):
            srcs.append(page["payload"])
        if isinstance(payload.get("payload"), dict):
            srcs.append(payload["payload"])
        srcs.append(payload)
    for src in srcs:
        factors = src.get("factors") if isinstance(src.get("factors"), list) else []
        first = factors[0] if factors and isinstance(factors[0], dict) else {}
        fid = src.get("factor_id") or first.get("id") or src.get("id") or src.get(
            "challenge_id"
        )
        ftype = first.get("factor_type") or first.get("type") or "totp"
        if isinstance(fid, str) and fid:
            return MfaFactor(factor_id=fid, factor_type=str(ftype or "totp"))
    m = _MFA_CHALLENGE_RE.search(continue_url or "")
    return MfaFactor(factor_id=m.group(1), factor_type="totp") if m else None


def extract_mfa_factor_id(payload: dict | None, continue_url: str = "") -> str | None:
    factor = extract_mfa_factor(payload, continue_url)
    return factor.factor_id if factor else None


@dataclass
class MfaVerifyResult:
    ok: bool
    continue_url: str = ""
    error: str | None = None
    fatal: bool = False


def step_mfa_verify(
    session: Any,
    *,
    factor_id: str,
    totp_secret: str,
    device_id: str,
    factor_type: str = "totp",
) -> MfaVerifyResult:
    """POST issue then verify — guide: fresh Sentinel flow=mfa_verify."""
    kind = (factor_type or "totp").strip() or "totp"
    try:
        issued = session.post(
            ep.URL_MFA_ISSUE,
            headers=auth_api_headers(device_id, accept="*/*"),
            json={
                "id": factor_id,
                "type": kind,
                "force_fresh_challenge": False,
            },
            timeout=HOP,
        )
    except Exception as e:
        return MfaVerifyResult(
            ok=False, error=f"mfa/issue_challenge: {e}", fatal=False
        )
    try:
        status = int(getattr(issued, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    if status >= 400:
        return MfaVerifyResult(
            ok=False,
            error=f"mfa/issue_challenge HTTP {status}",
            fatal=status in (400, 401, 403),
        )

    mfa_tok = get_sentinel_token_pow(session, device_id, "mfa_verify", LOGIN_UA)
    if not mfa_tok:
        return MfaVerifyResult(
            ok=False, error="sentinel token empty for mfa/verify", fatal=False
        )
    code = totp(totp_secret)
    r = session.post(
        ep.URL_MFA_VERIFY,
        headers=auth_api_headers(
            device_id,
            {"openai-sentinel-token": mfa_tok},
            referer=f"{ep.AUTH_BASE}/mfa-challenge/{factor_id}",
        ),
        json={"id": factor_id, "type": kind, "code": code},
        allow_redirects=False,
        timeout=HOP,
    )
    if r.status_code in (400, 401, 403):
        import time as _t
        # Retry with +/- 30s clock skew tolerance
        for delta in (-30, 30):
            alt_code = totp(totp_secret, for_time=int(_t.time() + delta))
            r_alt = session.post(
                ep.URL_MFA_VERIFY,
                headers=auth_api_headers(
                    device_id,
                    {"openai-sentinel-token": mfa_tok},
                    referer=f"{ep.AUTH_BASE}/mfa-challenge/{factor_id}",
                ),
                json={"id": factor_id, "type": kind, "code": alt_code},
                allow_redirects=False,
                timeout=HOP,
            )
            if r_alt.status_code < 400:
                r = r_alt
                break
        else:
            return MfaVerifyResult(ok=False, error="mfa verify failed (invalid 2FA code or secret)", fatal=True)
    if r.status_code >= 400:
        return MfaVerifyResult(
            ok=False, error=f"mfa verify HTTP {r.status_code}", fatal=False
        )
    try:
        mj = r.json() or {}
    except Exception:
        mj = {}
    loc = ""
    try:
        loc = r.headers.get("Location") or ""
    except Exception:
        loc = ""
    return MfaVerifyResult(ok=True, continue_url=extract_continue_url(mj, loc))
