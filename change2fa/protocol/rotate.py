"""Strict ChatGPT TOTP replacement: disable old factor, enroll+activate server secret."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from change2fa.protocol.login.net_retry import is_aborted_session, is_transient_transport_error
from change2fa.protocol.login.timings import HOP
from change2fa.protocol.probe import run_probe
from change2fa.protocol.mfa_urls import MFA_ACTIVATE, MFA_DISABLE, MFA_ENROLL, MFA_INFO
from change2fa.protocol.http_session import create_session
from change2fa.protocol.totp import totp

OnStep = Callable[[str, str], None]
HOP_RETRY = 3
HOP_RETRY_SLEEP_S = 60.0


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _note(on_step: OnStep | None, step: str, message: str) -> None:
    if on_step is not None:
        on_step(step, message)


def _hop_ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


class MfaRotateError(Exception):
    pass


@dataclass
class RotateResult:
    totp_secret: str


def _headers(access_token: str, url: str, *, device_id: str | None) -> dict[str, str]:
    path = url.removeprefix("https://chatgpt.com")
    h = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "oai-language": "en-US",
        "x-openai-target-path": path,
        "x-openai-target-route": path,
    }
    if device_id:
        h["oai-device-id"] = device_id
    return h


def _json(resp) -> dict | None:
    try:
        data = resp.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _http_err(label: str, status: int, body_text: str = "") -> MfaRotateError:
    msg = f"{label} HTTP {status}"
    if body_text:
        msg += f" - {body_text}"
    return MfaRotateError(msg)


def _hop_retryable(status: int, *, empty: bool = False) -> bool:
    if status == 429 or status >= 500:
        return True
    return empty and status < 400


def _retry_send(
    send,
    *,
    on_step: OnStep | None,
    step: str,
    http_label: str,
    method: str,
    require_body: bool,
    ok_statuses: frozenset[int] | None = None,
):
    last = None
    for attempt in range(HOP_RETRY):
        if attempt > 0:
            _sleep(HOP_RETRY_SLEEP_S)
            _note(
                on_step, step,
                f"retry {attempt + 1}/{HOP_RETRY} wait {int(HOP_RETRY_SLEEP_S)}s",
            )
        t0 = time.perf_counter()
        try:
            last = send()
        except Exception as exc:
            if is_aborted_session(exc):
                raise MfaRotateError("cancelled") from exc
            _note(on_step, step, f"{type(exc).__name__} {_hop_ms(t0)}ms")
            if not is_transient_transport_error(exc) or attempt == HOP_RETRY - 1:
                raise MfaRotateError(f"{step} {type(exc).__name__}") from exc
            continue
        _note(
            on_step, step,
            f"{method} {http_label} HTTP {last.status_code} {_hop_ms(t0)}ms",
        )
        body = _json(last)
        ok_http = (
            last.status_code in ok_statuses
            if ok_statuses is not None
            else last.status_code < 400
        )
        if ok_http and (not require_body or body is not None):
            return last, body
        if not _hop_retryable(last.status_code, empty=body is None) or attempt == HOP_RETRY - 1:
            raise _http_err(step, last.status_code, getattr(last, "text", ""))
    raise _http_err(step, last.status_code if last is not None else 0, getattr(last, "text", ""))


def _retry_post(
    session,
    url: str,
    *,
    headers: dict,
    payload: dict,
    on_step: OnStep | None,
    step: str,
    http_label: str,
    require_body: bool,
    ok_statuses: frozenset[int] | None = None,
):
    return _retry_send(
        lambda: session.post(url, headers=headers, json=payload),
        on_step=on_step, step=step, http_label=http_label,
        method="POST", require_body=require_body, ok_statuses=ok_statuses,
    )


def _totp_items(factors) -> list[dict]:
    if isinstance(factors, list):
        return [x for x in factors if isinstance(x, dict)]
    if isinstance(factors, dict):
        totp = factors.get("totp")
        if isinstance(totp, list):
            return [x for x in totp if isinstance(x, dict)]
        if isinstance(totp, dict):
            return [totp]
    return []


def _totp_factor_id(info: dict) -> str:
    if info.get("mfa_enabled_v2") is not True and info.get("mfa_enabled") is not True:
        raise MfaRotateError("MFA info is unavailable")
    for item in _totp_items(info.get("factors")):
        ftype = str(item.get("factor_type") or item.get("type") or "totp").lower()
        if ftype != "totp":
            continue
        fid = item.get("id") or item.get("factor_id")
        if fid is None:
            continue
        text = str(fid).strip()
        if text:
            return text
    native = info.get("native_default_factor_id")
    if isinstance(native, str) and native.strip():
        return native.strip()
    raise MfaRotateError("active TOTP factor id is unavailable")


def _enroll_fields(data: dict) -> tuple[str, str, str]:
    secret = data.get("secret")
    if not isinstance(secret, str) or not secret.strip():
        raise MfaRotateError("enroll secret is unavailable")
    factor = data.get("factor") if isinstance(data.get("factor"), dict) else {}
    factor_id = data.get("factor_id") or factor.get("id")
    session_id = data.get("session_id")
    if not factor_id or not session_id:
        raise MfaRotateError("enroll factor or session is unavailable")
    return secret.strip(), str(factor_id), str(session_id)


def _rotate_sync(
    access_token: str,
    proxy_url: str | None,
    device_id: str | None,
    on_step: OnStep | None,
) -> RotateResult:
    session = create_session(
        proxy_url=proxy_url, impersonate="chrome131", timeout=HOP,
    )
    try:
        _info_r, info = _retry_send(
            lambda: session.get(
                MFA_INFO, headers=_headers(access_token, MFA_INFO, device_id=device_id)
            ),
            on_step=on_step, step="mfa_info", http_label="mfa/info",
            method="GET", require_body=True, ok_statuses=frozenset({200}),
        )
        factor_id = _totp_factor_id(info or {})

        _retry_post(
            session, MFA_DISABLE,
            headers=_headers(access_token, MFA_DISABLE, device_id=device_id),
            payload={"factor_id": factor_id},
            on_step=on_step, step="disable_old_totp", http_label="mfa/disable",
            require_body=False, ok_statuses=frozenset({200, 204}),
        )

        _enroll_r, enroll = _retry_post(
            session, MFA_ENROLL,
            headers=_headers(access_token, MFA_ENROLL, device_id=device_id),
            payload={"factor_type": "totp"},
            on_step=on_step, step="enroll_new_totp", http_label="mfa/enroll",
            require_body=True,
        )
        secret, _fid, session_id = _enroll_fields(enroll or {})

        _act_r, act = _retry_post(
            session, MFA_ACTIVATE,
            headers=_headers(access_token, MFA_ACTIVATE, device_id=device_id),
            payload={
                "code": totp(secret),
                "factor_type": "totp",
                "session_id": session_id,
            },
            on_step=on_step, step="activate_new_totp", http_label="mfa/activate",
            require_body=False,
        )
        if act is not None and act.get("success") is False:
            raise MfaRotateError("activate_new_totp failed")
        return RotateResult(totp_secret=secret)
    except MfaRotateError:
        raise
    except Exception as exc:
        raise MfaRotateError(type(exc).__name__) from exc
    finally:
        try:
            session.close()
        except Exception:
            pass


async def rotate(
    *,
    access_token: str,
    proxy_url: str | None,
    device_id: str | None,
    on_step: OnStep | None = None,
) -> RotateResult:
    return await run_probe(_rotate_sync, access_token, proxy_url, device_id, on_step)
