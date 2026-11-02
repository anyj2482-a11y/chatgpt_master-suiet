"""One account: login with the old TOTP, replace it, login with the new one."""

from __future__ import annotations

from dataclasses import dataclass

from change2fa.protocol.job_timeout import await_or_timeout
from change2fa.protocol.live_curl import using_abort_key
from change2fa.retry_flow import (
    login_with_proxy_retries,
    rotate_with_proxy_retries,
    run_with_timeout_retries,
    verify_new_totp,
)


@dataclass
class Outcome:
    email: str
    ok: bool
    error: str = ""
    new_totp: str = ""
    verified: bool = False


def _fail(email: str, error: str, *, new_totp: str = "") -> Outcome:
    return Outcome(email=email, ok=False, error=error, new_totp=new_totp)


async def replace_totp(
    account,
    *,
    login,
    rotate,
    pool,
    refresh_rows,
    url_for_row,
    progress,
    is_stopped,
    on_new_secret,
    timeout: int,
    abort_key: str,
) -> Outcome:
    email = account.email

    async def once(skip: set[int]) -> Outcome:
        await progress.anote("login", "login with old totp")
        await pool.ensure(refresh_rows)
        ens, proxy = await login_with_proxy_retries(
            login=lambda p: login(p, account.totp_secret),
            pool=pool,
            url_for_row=url_for_row,
            refresh_rows=refresh_rows,
            progress=progress,
            skip=skip,
            is_stopped=is_stopped,
        )
        if not ens or not ens.ok or not getattr(ens, "bundle", None):
            err = (getattr(ens, "error", None) if ens else None) or "login failed"
            return _fail(email, err)
        bundle = ens.bundle

        async def do_rotate(p):
            return await rotate(
                p,
                access_token=bundle.access_token,
                device_id=getattr(bundle, "device_id", None) or None,
                on_step=lambda step, message: progress.note(step, message),
            )

        rotated, _proxy, rot_err = await rotate_with_proxy_retries(
            rotate=do_rotate,
            pool=pool,
            url_for_row=url_for_row,
            refresh_rows=refresh_rows,
            progress=progress,
            skip=skip,
            is_stopped=is_stopped,
            proxy=proxy,
        )
        if rot_err or rotated is None:
            return _fail(email, rot_err or "rotate failed")
        secret = rotated.totp_secret
        # The account already has the new factor. Keep the secret before verify.
        await on_new_secret(secret)
        if is_stopped():
            return _fail(email, "cancelled", new_totp=secret)
        await progress.anote("verify_new_totp", "login with new totp")
        verify, _proxy = await verify_new_totp(
            login=lambda p: login(p, secret),
            pool=pool,
            url_for_row=url_for_row,
            refresh_rows=refresh_rows,
            progress=progress,
            skip=skip,
            is_stopped=is_stopped,
        )
        if not verify or not verify.ok or not getattr(verify, "bundle", None):
            err = (getattr(verify, "error", None) if verify else None) or "login failed"
            return _fail(
                email,
                f"new TOTP verification failed: {err}",
                new_totp=secret,
            )
        return Outcome(email=email, ok=True, new_totp=secret, verified=True)

    with using_abort_key(abort_key):
        return await run_with_timeout_retries(
            run=once,
            await_timeout=await_or_timeout,
            timeout=timeout,
            abort_key=abort_key,
            progress=progress,
            pool=pool,
            refresh_rows=refresh_rows,
            is_stopped=is_stopped,
            fail=lambda msg: _fail(email, msg),
        )
