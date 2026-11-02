"""Inbox-OTP (passwordless) login for Check GPT.

Landing on ``/email-verification`` means the account signs in with an emailed
6-digit code (not a password). Some passwordless accounts additionally enroll
an authenticator, so the full flow is:

    email → email OTP → (optional) authenticator OTP (TOTP)

This module drives:

    email-otp/send → poll public cf-mail OTP URL → email-otp/validate
    (openai-sentinel-token, flow=email_otp_validate) → optional mfa/verify →
    finalize session.

Runs synchronously inside the login probe thread (curl_cffi), same as the
password path.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.errors import annotate_login_error, classify_password_body
from change2fa.protocol.login.headers import LOGIN_IMPERSONATE, LOGIN_UA, auth_api_headers
from change2fa.protocol.login.mfa import extract_continue_url, extract_mfa_factor, step_mfa_verify
from change2fa.protocol.login.result import LoginResult
from change2fa.protocol.login.session_finish import finalize_session
from change2fa.protocol.login.timings import HOP
from change2fa.protocol.sentinel_pow import get_sentinel_token_pow
from change2fa.protocol.progress import CheckProgress
from change2fa.protocol.http_session import create_session

log = logging.getLogger(__name__)

SENTINEL_FLOW_OTP = "email_otp_validate"
_OTP_POLL_TIMEOUT_S = 75.0
_OTP_POLL_INTERVAL_S = 3.0
_OTP_INITIAL_DELAY_S = 3.0
_OTP_MAX_VALIDATE = 4


@dataclass
class _ValidateResult:
    ok: bool
    continue_url: str = ""
    error: str | None = None
    fatal: bool = False
    wrong_code: bool = False
    needs_mfa: bool = False
    factor_id: str | None = None
    factor_type: str = "totp"


def _err(error: str, *, fatal: bool = False) -> LoginResult:
    return LoginResult(ok=False, error=annotate_login_error(error), fatal=fatal)


def step_email_otp_send(session: Any, device_id: str) -> None:
    """Trigger the emailed code. Best-effort — landing may have sent it already."""
    try:
        session.get(
            ep.URL_EMAIL_OTP_SEND,
            headers=auth_api_headers(
                device_id, {"Referer": f"{ep.AUTH_BASE}/email-verification"}
            ),
            allow_redirects=True,
            timeout=HOP,
        )
    except Exception as e:  # noqa: BLE001 - send is advisory; poll drives correctness
        log.debug("email-otp/send transport: %s", e)


def _fetch_otp_codes(otp_url: str, proxy_url: str | None) -> list[tuple[str, float]]:
    """GET public cf-mail OTP JSON → [(code, ts_ms)] newest first."""
    session = create_session(
        proxy_url=proxy_url, impersonate=LOGIN_IMPERSONATE, timeout=20.0
    )
    try:
        r = session.get(otp_url, timeout=20)
        if r.status_code >= 400:
            return []
        body = r.json() or {}
    except Exception as e:  # noqa: BLE001
        log.debug("otp poll transport: %s", e)
        return []
    finally:
        try:
            session.close()
        except Exception:
            pass
    if not isinstance(body, dict):
        return []
    out: list[tuple[str, float]] = []
    seen: set[str] = set()
    for msg in body.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        code = str(msg.get("code") or "").strip()
        if not code.isdigit() or len(code) != 6 or code in seen:
            continue
        raw_ts = msg.get("ts")
        ts = float(raw_ts) if isinstance(raw_ts, (int, float)) else 0.0
        out.append((code, ts))
        seen.add(code)
    for code in body.get("codes") or []:
        c = str(code or "").strip()
        if c.isdigit() and len(c) == 6 and c not in seen:
            out.append((c, 0.0))
            seen.add(c)
    out.sort(key=lambda x: x[1], reverse=True)
    return out


def step_email_otp_validate(session: Any, code: str, device_id: str) -> _ValidateResult:
    """POST email-otp/validate with sentinel token; classify the outcome."""
    tok = get_sentinel_token_pow(session, device_id, SENTINEL_FLOW_OTP, LOGIN_UA)
    if not tok:
        return _ValidateResult(ok=False, error="sentinel token empty for email-otp/validate")
    headers = auth_api_headers(
        device_id,
        {
            "openai-sentinel-token": tok,
            "Referer": f"{ep.AUTH_BASE}/email-verification",
        },
    )
    try:
        r = session.post(
            ep.URL_EMAIL_OTP_VALIDATE,
            headers=headers,
            json={"code": code},
            allow_redirects=False,
            timeout=HOP,
        )
    except Exception as e:  # noqa: BLE001
        return _ValidateResult(ok=False, error=f"email-otp/validate transport: {e}")

    text = r.text or ""
    lower = text.lower()
    try:
        payload = r.json() or {}
    except Exception:
        payload = {}
    err_obj = payload.get("error") if isinstance(payload, dict) else None
    err_code = str((err_obj or {}).get("code") or "") if isinstance(err_obj, dict) else ""
    log.debug(
        "email-otp/validate status=%s err_code=%s body=%s",
        r.status_code,
        err_code,
        text[:200],
    )

    # Deleted / deactivated / locked account → fatal, no point retrying.
    deactivated = classify_password_body(text)
    if deactivated and deactivated.fatal:
        return _ValidateResult(ok=False, error=deactivated.error, fatal=True)
    if err_code in ("account_deactivated", "account_disabled", "account_deleted"):
        return _ValidateResult(ok=False, error="account locked/disabled", fatal=True)

    if r.status_code in (400, 401, 403):
        if any(m in lower for m in ("invalid", "incorrect", "expired", "wrong")):
            return _ValidateResult(ok=False, wrong_code=True, error="otp rejected")
        return _ValidateResult(
            ok=False, error=f"email-otp/validate HTTP {r.status_code}: {text[:200]}"
        )
    if r.status_code >= 400:
        return _ValidateResult(ok=False, error=f"email-otp/validate HTTP {r.status_code}")

    loc = ""
    try:
        loc = r.headers.get("Location") or ""
    except Exception:
        loc = ""
    cont = extract_continue_url(payload, loc if isinstance(loc, str) else "")
    if isinstance(err_obj, dict) and not cont:
        cont = str(err_obj.get("redirect_uri") or "")

    # Passwordless account may still require an authenticator (TOTP) step:
    # email → email OTP → authenticator OTP.
    page = ""
    if isinstance(payload, dict):
        page = str((payload.get("page") or {}).get("type") or payload.get("type") or "")
    needs_mfa = "mfa" in page.lower() or "mfa" in lower or "/mfa-challenge/" in cont
    factor = extract_mfa_factor(payload, cont) if needs_mfa else None
    return _ValidateResult(
        ok=True,
        continue_url=cont,
        needs_mfa=needs_mfa,
        factor_id=factor.factor_id if factor else None,
        factor_type=factor.factor_type if factor else "totp",
    )


def run_otp_finish(
    session: Any,
    *,
    email: str,
    otp_url: str,
    device_id: str,
    logging_id: str,
    proxy_url: str | None,
    totp_secret: str | None = None,
    progress: CheckProgress | None = None,
) -> LoginResult:
    """Send + poll + validate the inbox OTP, then finalize the ChatGPT session.

    Flow: email → email OTP → (optional) authenticator OTP. The public cf-mail
    OTP URL is our own worker, so it is polled directly (not through the account
    proxy, which is often a flaky residential exit). Codes are tried newest-first:
    a still-valid existing code is used right away; only when it is rejected or
    expired do we wait for a freshly sent one. If the account then challenges for
    an authenticator (TOTP), ``totp_secret`` answers it before finalizing.
    """
    prog = progress or CheckProgress(email)
    if not otp_url:
        return _err("email-verification: inbox OTP required but no otp_url", fatal=True)

    prog.note("otp", "POST email-otp/send")
    step_email_otp_send(session, device_id)
    time.sleep(_OTP_INITIAL_DELAY_S)

    deadline = time.monotonic() + _OTP_POLL_TIMEOUT_S
    tried: set[str] = set()
    last_err: LoginResult | None = None
    while len(tried) < _OTP_MAX_VALIDATE and time.monotonic() < deadline:
        codes = _fetch_otp_codes(otp_url, None)
        code = next((c for c, _ in codes if c not in tried), None)
        if code is None:
            prog.note("otp", "waiting for inbox code")
            time.sleep(_OTP_POLL_INTERVAL_S)
            continue
        tried.add(code)
        prog.note("otp", f"POST email-otp/validate {code[:2]}****")
        res = step_email_otp_validate(session, code, device_id)
        if res.ok:
            return _finish_after_otp(
                session,
                email=email,
                otp_url=otp_url,
                device_id=device_id,
                logging_id=logging_id,
                res=res,
                totp_secret=totp_secret,
                progress=prog,
            )
        if res.fatal:
            return _err(res.error or "otp validate failed", fatal=True)
        if res.wrong_code:
            last_err = _err(res.error or "otp rejected")
            time.sleep(_OTP_POLL_INTERVAL_S)
            continue
        return _err(res.error or "otp validate failed")
    return last_err or _err("otp timeout: no inbox code")


def _finish_after_otp(
    session: Any,
    *,
    email: str,
    otp_url: str,
    device_id: str,
    logging_id: str,
    res: _ValidateResult,
    totp_secret: str | None,
    progress: CheckProgress,
) -> LoginResult:
    """After a valid email OTP: answer an authenticator (TOTP) challenge if any,
    then follow the continue and read the session."""
    cont = res.continue_url or None
    if res.needs_mfa:
        if not totp_secret:
            return _err("authenticator (totp) required after email otp", fatal=True)
        if not res.factor_id:
            return _err("mfa required, missing factor_id")
        progress.note("mfa", "POST mfa/issue + verify")
        mfa = step_mfa_verify(
            session,
            factor_id=res.factor_id,
            totp_secret=totp_secret,
            device_id=device_id,
            factor_type=res.factor_type,
        )
        if not mfa.ok:
            return _err(mfa.error or "mfa verify failed", fatal=mfa.fatal)
        cont = mfa.continue_url or cont

    return finalize_session(
        session,
        email=email,
        device_id=device_id,
        logging_id=logging_id,
        cont=cont,
        totp_secret=totp_secret,
        otp_url=otp_url,
        progress=progress,
    )
