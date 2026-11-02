"""Pure-HTTP ChatGPT login (simple_check + full MFA path)."""

from __future__ import annotations

import logging
import uuid

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.cf_retry import (
    LOGIN_PIPELINE_ATTEMPTS,
    bootstrap_backoff_sleep,
    is_oauth_bootstrap_retryable,
)
from change2fa.protocol.login.csrf import step_csrf
from change2fa.protocol.login.errors import (
    EMAIL_VERIFICATION_MSG,
    annotate_login_error,
    classify_password_body,
    classify_push_auth,
)
from change2fa.protocol.login.headers import (
    LOGIN_IMPERSONATE,
    LOGIN_UA,
    apply_browser_session_headers,
    auth_api_headers,
)
from change2fa.protocol.login.landing import (
    AuthorizeContinueResult,
    LandingFlow,
    detect_flow,
    needs_reauthorize,
    read_device_id_from_jar,
    step_authorize,
    step_authorize_continue,
)
from change2fa.protocol.login.mfa import (
    extract_continue_url,
    extract_mfa_factor,
    step_mfa_verify,
)
from change2fa.protocol.login.net_retry import is_aborted_session, is_transient_transport_error
from change2fa.protocol.login.otp import run_otp_finish
from change2fa.protocol.login.prime import (
    PrimeTransportError,
    seed_chatgpt_bootstrap_cookies,
    step_prime,
)
from change2fa.protocol.login.result import LoginResult, SessionBundle
from change2fa.protocol.login.session_finish import finalize_session, finish_authed_landing
from change2fa.protocol.login.signin import post_signin, step_reauthorize
from change2fa.protocol.login.ssl_recover import open_login_session
from change2fa.protocol.login.timings import HOP
from change2fa.protocol.sentinel_pow import get_sentinel_token_pow
from change2fa.protocol.probe import run_probe
from change2fa.protocol.progress import CheckProgress

log = logging.getLogger(__name__)

__all__ = ["LoginResult", "SessionBundle", "run_login"]


def _err(error: str, *, fatal: bool = False) -> LoginResult:
    return LoginResult(ok=False, error=annotate_login_error(error), fatal=fatal)


async def run_login(
    *,
    email: str,
    password: str,
    totp_secret: str | None,
    proxy_url: str | None,
    simple_check: bool,
    otp_url: str = "",
    progress: CheckProgress | None = None,
) -> LoginResult:
    return await run_probe(
        _run_login_sync,
        email,
        password,
        totp_secret,
        proxy_url,
        simple_check,
        progress,
        otp_url,
    )


def _run_login_sync(
    email: str,
    password: str,
    totp_secret: str | None,
    proxy_url: str | None,
    simple_check: bool,
    progress: CheckProgress | None = None,
    otp_url: str = "",
) -> LoginResult:
    """Outer oauth bootstrap — new client + jar (rust OAUTH_BOOTSTRAP_ATTEMPTS)."""
    prog = progress or CheckProgress(email)
    last: LoginResult | None = None
    for attempt in range(LOGIN_PIPELINE_ATTEMPTS):
        result = _login_once_sync(
            email, password, totp_secret, proxy_url, simple_check, prog, otp_url
        )
        if result.ok or result.fatal:
            return result
        if (
            attempt + 1 < LOGIN_PIPELINE_ATTEMPTS
            and is_oauth_bootstrap_retryable(result.error)
        ):
            prog.note(
                "bootstrap",
                f"oauth retry {attempt + 1}/{LOGIN_PIPELINE_ATTEMPTS}: {result.error}",
                level="warn",
            )
            bootstrap_backoff_sleep(attempt)
            last = result
            continue
        return result
    return last or _err("login pipeline exhausted")


def _login_once_sync(
    email: str,
    password: str,
    totp_secret: str | None,
    proxy_url: str | None,
    simple_check: bool,
    progress: CheckProgress | None = None,
    otp_url: str = "",
) -> LoginResult:
    prog = progress or CheckProgress(email)
    device_id = str(uuid.uuid4())
    logging_id = str(uuid.uuid4())
    prog.note("bootstrap", "GET chatgpt.com/ + /auth/login_with")
    session = open_login_session(
        proxy_url=proxy_url, impersonate=LOGIN_IMPERSONATE, timeout=HOP
    )
    apply_browser_session_headers(session, device_id, logging_id)

    try:
        primed = step_prime(
            session,
            email,
            device_id,
            logging_id,
            proxy_url=proxy_url,
            progress=prog,
        )
        if isinstance(primed, LoginResult):
            return _err(primed.error or "bootstrap failed", fatal=primed.fatal)
        login_referer = primed

        prog.note("csrf", "GET providers + csrf")
        csrf_or_err = step_csrf(session, device_id, logging_id, referer=login_referer)
        if isinstance(csrf_or_err, LoginResult):
            return _err(csrf_or_err.error or "csrf failed", fatal=csrf_or_err.fatal)
        csrf = csrf_or_err

        prog.note("signin", "POST signin/openai")
        authorize_url = post_signin(
            session,
            csrf=csrf,
            device_id=device_id,
            logging_id=logging_id,
            referer=login_referer,
            login_hint=email,
        )
        if isinstance(authorize_url, LoginResult):
            return _err(authorize_url.error or "signin failed", fatal=authorize_url.fatal)

        prog.note("authorize", "GET authorize")
        auth_or_err = step_authorize(session, authorize_url, referer=login_referer)
        if isinstance(auth_or_err, LoginResult):
            return auth_or_err
        landing = auth_or_err
        device_id = read_device_id_from_jar(session, device_id)
        seed_chatgpt_bootstrap_cookies(session, device_id, logging_id)
        flow = detect_flow(landing)
        level = "warn" if flow == LandingFlow.UNKNOWN else "info"
        prog.note("authorize", f"landed {flow.value} {landing[:80]}", level=level)

        if flow == LandingFlow.SUCCESS:
            prog.note("session", "already authenticated")
            return finish_authed_landing(
                session,
                email=email,
                password=password,
                totp_secret=totp_secret,
                device_id=device_id,
                logging_id=logging_id,
                landing=landing,
                simple_check=simple_check,
                progress=prog,
            )

        if flow == LandingFlow.EMAIL_CONTINUE:
            prog.note("continue", "POST authorize/continue")
            ac = step_authorize_continue(session, email, device_id)
            if isinstance(ac, str):
                return _err(ac)
            assert isinstance(ac, AuthorizeContinueResult)
            if ac.page_type == "login_password" or "/log-in/password" in ac.continue_url:
                flow = LandingFlow.PASSWORD
            elif (
                ac.page_type == "email_otp_verification"
                or "/email-verification" in ac.continue_url
            ):
                flow = LandingFlow.OTP_PASSWORDLESS
            else:
                return _err(
                    f"not ready for password after authorize/continue "
                    f"(path={ac.continue_url[:200]})"
                )

        if flow == LandingFlow.OTP_PASSWORDLESS:
            if not otp_url:
                return _err(EMAIL_VERIFICATION_MSG, fatal=True)
            return run_otp_finish(
                session,
                email=email,
                otp_url=otp_url,
                device_id=device_id,
                logging_id=logging_id,
                proxy_url=proxy_url,
                totp_secret=totp_secret,
                progress=prog,
            )
        if flow != LandingFlow.PASSWORD:
            return _err(f"unexpected authorize landing path={landing[:200]}")
        if not password:
            return _err(
                "account requires password but only otp_url provided", fatal=True
            ) if otp_url else _err("no password for password login", fatal=True)

        return _password_and_finish(
            session,
            email=email,
            password=password,
            totp_secret=totp_secret,
            device_id=device_id,
            logging_id=logging_id,
            simple_check=simple_check,
            progress=prog,
        )
    except Exception as e:
        if is_aborted_session(e):
            return _err("cancelled")
        if isinstance(e, PrimeTransportError) or is_transient_transport_error(e):
            kind = "prime transport" if isinstance(e, PrimeTransportError) else "transport"
            log.warning("login %s: %s", kind, e)
        else:
            log.exception("login failed")
        return _err(str(e))
    finally:
        try:
            session.close()
        except Exception:
            pass


def _password_and_finish(
    session,
    *,
    email: str,
    password: str,
    totp_secret: str | None,
    device_id: str,
    logging_id: str = "",
    simple_check: bool,
    progress: CheckProgress | None = None,
) -> LoginResult:
    prog = progress or CheckProgress(email)
    prog.note("password", "POST password/verify")
    pw_tok = get_sentinel_token_pow(session, device_id, "password_verify", LOGIN_UA)
    if not pw_tok:
        return _err("sentinel token empty for password/verify")
    pw_headers = auth_api_headers(
        device_id, {"openai-sentinel-token": pw_tok}
    )
    r = session.post(
        ep.URL_PASSWORD_VERIFY,
        headers=pw_headers,
        json={"password": password},
        allow_redirects=False,
        timeout=HOP,
    )
    text = r.text or ""
    try:
        ctype = str((getattr(r, "headers", None) or {}).get("content-type") or "")
    except Exception:
        ctype = ""
    if r.status_code == 200 and "json" not in ctype.lower() and "html" in ctype.lower():
        return _err("password invalid response")
    classified = classify_password_body(text)
    if classified:
        return _err(classified.error, fatal=classified.fatal)
    if r.status_code >= 500:
        return _err(f"password HTTP {r.status_code}")
    lower = text.lower()
    if r.status_code >= 400 and "mfa" not in lower and "/mfa-challenge/" not in lower:
        return _err(f"password HTTP {r.status_code}: {text[:200]}")

    pw_json: dict = {}
    try:
        pw_json = r.json() or {}
    except Exception:
        pw_json = {}
    try:
        loc = r.headers.get("Location") or ""
    except Exception:
        loc = ""
    cont = extract_continue_url(pw_json, loc if isinstance(loc, str) else "")
    push = classify_push_auth(pw_json, cont)
    if push:
        return _err(push, fatal=True)
    page = (pw_json.get("page") or {}).get("type") or pw_json.get("type") or ""
    needs_mfa = "mfa" in str(page).lower() or "mfa" in lower or "/mfa-challenge/" in cont
    factor = extract_mfa_factor(pw_json, cont)
    return _finish_after_password(
        session,
        email=email,
        password=password,
        totp_secret=totp_secret,
        device_id=device_id,
        logging_id=logging_id,
        simple_check=simple_check,
        needs_mfa=needs_mfa,
        factor_id=factor.factor_id if factor else None,
        factor_type=factor.factor_type if factor else "totp",
        cont=cont,
        pw_status=r.status_code,
        progress=prog,
    )


def _finish_after_password(
    session,
    *,
    email: str,
    password: str,
    totp_secret: str | None,
    device_id: str,
    logging_id: str = "",
    simple_check: bool,
    needs_mfa: bool,
    factor_id: str | None,
    factor_type: str = "totp",
    cont: str,
    pw_status: int,
    progress: CheckProgress | None = None,
) -> LoginResult:
    """Simple returns after password; full path does MFA + session + /me."""
    prog = progress or CheckProgress(email)
    if simple_check:
        if pw_status < 500:
            return LoginResult(
                ok=True,
                simple=True,
                needs_mfa=needs_mfa,
                bundle=SessionBundle(
                    email=email,
                    device_id=device_id,
                    password=password,
                    totp_secret=totp_secret,
                ),
            )
        return _err(f"password HTTP {pw_status}")

    if needs_mfa:
        if not totp_secret:
            return _err("mfa required, no totp", fatal=True)
        if not factor_id:
            return _err("mfa required, missing factor_id")
        prog.note("mfa", "POST mfa/issue + verify")
        mfa = step_mfa_verify(
            session,
            factor_id=factor_id,
            totp_secret=totp_secret,
            device_id=device_id,
            factor_type=factor_type,
        )
        if not mfa.ok:
            return _err(mfa.error or "mfa verify failed", fatal=mfa.fatal)
        cont = mfa.continue_url or cont

    if needs_reauthorize(cont):
        prog.note("signin", "reauthorize without login_hint")
        landed = step_reauthorize(
            session,
            device_id=device_id,
            logging_id=logging_id,
            referer=f"{ep.CHATGPT_BASE}/",
        )
        if isinstance(landed, LoginResult):
            return _err(landed.error or "reauthorize failed", fatal=landed.fatal)
        cont = landed

    return finalize_session(
        session,
        email=email,
        device_id=device_id,
        logging_id=logging_id,
        cont=cont or None,
        password=password,
        totp_secret=totp_secret,
        progress=prog,
    )
