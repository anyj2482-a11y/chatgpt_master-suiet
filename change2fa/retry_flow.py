"""Login and MFA-replace retries. Max 3 attempts, 60s apart."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from change2fa.protocol.login.net_retry import is_aborted_session

LOGIN_ATTEMPTS = 3
VERIFY_SLEEP_S = 1.0
RETRY_WAIT_S = 60.0
TIMEOUT_ATTEMPTS = 3


@dataclass
class _EnsFail:
    error: str
    ok: bool = False
    bundle: object = None


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def _unused_proxy(pool, skip: set[int]) -> bool:
    return any(int(r.id) not in skip for r in pool.rows)


def _is_cancelled(ens) -> bool:
    err = (ens.error if ens else None) or ""
    return "cancelled" in err.lower() or is_aborted_session(err)


def is_login_mfa_nonretryable(err: str) -> bool:
    """Login MFA issue/verify failed — do not rotate proxy or wait 60s."""
    m = (err or "").lower()
    if not m or "cancelled" in m or is_aborted_session(err):
        return False
    return (
        m.startswith("mfa/")
        or m.startswith("mfa verify")
        or m.startswith("mfa required")
        or "sentinel token empty for mfa" in m
    )


def is_rotate_proxy_retryable(err: str) -> bool:
    """Retry whole MFA replace only before disable — mfa_info transport."""
    m = (err or "").lower()
    if not m or "cancelled" in m or is_aborted_session(err):
        return False
    if m.startswith("enroll_") or m.startswith("activate_") or m.startswith("disable_"):
        return False
    return (
        m.startswith("mfa_info")
        or m in {"timeout", "timeouterror"}
        or "curl: (28)" in m
        or "timed out" in m
    )


async def login_with_proxy_retries(
    *,
    login,
    pool,
    url_for_row,
    refresh_rows,
    progress,
    skip: set[int],
    is_stopped,
    step: str = "login",
    sleep_s: float = 0.0,
    used: set[int] | None = None,
    retry_mfa: bool = False,
) -> tuple:
    phase = skip if used is None else used
    ens = proxy = last_row = None
    for attempt in range(LOGIN_ATTEMPTS):
        if is_stopped():
            return ens, proxy
        if attempt > 0:
            await _sleep(RETRY_WAIT_S)
            live = await refresh_rows()
            if live:
                pool.replace(live)
        elif sleep_s:
            await _sleep(sleep_s)
        exclude = set(phase) | set(skip)
        row = pool.pick(exclude)
        if row is None:
            row = pool.pick(set())
        reused = row is None or (
            last_row is not None and int(row.id) == int(last_row.id)
        )
        if row is not None:
            last_row = row
            proxy = url_for_row(row)
            phase.add(int(row.id))
            skip.add(int(row.id))
        if attempt > 0:
            kind = "retry same egress" if reused else "rotate proxy"
            await progress.anote(
                step,
                f"{kind} {attempt + 1}/{LOGIN_ATTEMPTS} wait {int(RETRY_WAIT_S)}s",
                level="warn",
            )
        try:
            ens = await login(proxy)
        except Exception as e:
            err = "cancelled" if is_aborted_session(e) else (str(e) or type(e).__name__)
            ens = _EnsFail(err)
        if ens and ens.ok and getattr(ens, "bundle", None):
            return ens, proxy
        err = (ens.error if ens else None) or "login failed"
        if _is_cancelled(ens):
            break
        if is_login_mfa_nonretryable(err) and not retry_mfa:
            await progress.anote("mfa", err, level="error")
            break
    return ens, proxy


async def rotate_with_proxy_retries(
    *,
    rotate,
    pool,
    url_for_row,
    refresh_rows,
    progress,
    skip: set[int],
    is_stopped,
    proxy: str | None,
) -> tuple:
    """Retry MFA replace on mfa_info transport; keep login proxy on first shot."""
    last_err = "rotate failed"
    for attempt in range(LOGIN_ATTEMPTS):
        if is_stopped():
            return None, proxy, "cancelled"
        if attempt > 0:
            await _sleep(RETRY_WAIT_S)
            live = await refresh_rows()
            if live:
                pool.replace(live)
            row = pool.pick(skip)
            reused = row is None
            if row is not None:
                proxy = url_for_row(row)
                skip.add(int(row.id))
            kind = "retry same egress" if reused else "rotate proxy"
            await progress.anote(
                "mfa_info",
                f"{kind} {attempt + 1}/{LOGIN_ATTEMPTS} wait {int(RETRY_WAIT_S)}s",
                level="warn",
            )
        try:
            return await rotate(proxy), proxy, None
        except Exception as e:
            last_err = str(e) or type(e).__name__
            if is_aborted_session(e) or "cancelled" in last_err.lower():
                return None, proxy, "cancelled"
            if not is_rotate_proxy_retryable(last_err) or attempt + 1 >= LOGIN_ATTEMPTS:
                return None, proxy, last_err
    return None, proxy, last_err


async def verify_new_totp(
    *,
    login,
    pool,
    url_for_row,
    refresh_rows,
    progress,
    skip: set[int],
    is_stopped,
) -> tuple:
    """Confirm login after rotate — up to 3 tries, 60s apart, rotate proxy when possible.

    Unlike the old-TOTP login, MFA/transport/login errors on this step all retry
    (``retry_mfa=True``) because the new factor may need a fresh window or egress.
    """
    return await login_with_proxy_retries(
        login=login, pool=pool, url_for_row=url_for_row,
        refresh_rows=refresh_rows, progress=progress, skip=skip,
        is_stopped=is_stopped, step="verify_new_totp", sleep_s=VERIFY_SLEEP_S,
        used=set(), retry_mfa=True,
    )


async def run_with_timeout_retries(
    *,
    run,
    await_timeout,
    timeout: int,
    abort_key: str,
    progress,
    pool,
    refresh_rows,
    is_stopped,
    fail,
):
    skip: set[int] = set()
    for attempt in range(TIMEOUT_ATTEMPTS):
        if is_stopped():
            return fail("cancelled")
        if attempt > 0:
            await progress.anote(
                "login",
                f"timeout → rotate proxy {attempt + 1}/{TIMEOUT_ATTEMPTS}",
                level="warn",
            )
            live = await refresh_rows()
            if live:
                pool.replace(live)
            if pool.rows and not _unused_proxy(pool, skip):
                break
        o, timed_out = await await_timeout(
            run(skip), timeout=timeout, abort_key=abort_key,
        )
        if not timed_out:
            return fail("timeout") if o is None else o
        if pool.rows and not _unused_proxy(pool, skip):
            break
    return fail("timeout")
