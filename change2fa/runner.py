"""Start, stop, and persist one bulk TOTP replacement."""

from __future__ import annotations

import asyncio
import time

from change2fa.account_flow import replace_totp
from change2fa.export_text import error_text, verified_text
from change2fa.hub import Hub
from change2fa.limits import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
    MAX_ACCOUNTS,
    MAX_CONCURRENCY,
    MAX_PROXIES,
    MAX_TIMEOUT,
    MIN_TIMEOUT,
)
from change2fa.parse_accounts import count_account_lines, parse_accounts
from change2fa.protocol.live_curl import abort_prefix
from change2fa.protocol.login.flow import run_login
from change2fa.protocol.progress import CheckProgress
from change2fa.protocol.rotate import rotate as rotate_mfa
from change2fa.proxy_pool import ProxyPool, count_proxy_lines, parse_proxy_text
from change2fa.store import Store


class RunError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        self.message = message
        self.status = status


def clamp_concurrency(n: int) -> int:
    return max(1, min(MAX_CONCURRENCY, int(n or DEFAULT_CONCURRENCY)))


def clamp_timeout(n: int) -> int:
    return max(MIN_TIMEOUT, min(MAX_TIMEOUT, int(n or DEFAULT_TIMEOUT)))


class Runner:
    def __init__(self, store: Store, hub: Hub) -> None:
        self.store = store
        self.hub = hub
        self.stop_event = asyncio.Event()
        self.task: asyncio.Task | None = None
        self.running = False

    async def state(self) -> dict:
        draft = await self.store.load_draft()
        jobs = await self.store.list_jobs()
        return {
            "draft": draft,
            "running": self.running,
            "jobs": jobs,
            "verified_text": verified_text(jobs),
            "error_text": error_text(jobs),
        }

    async def save_draft(self, body: dict) -> dict:
        draft = await self._write_draft(body)
        return await self.state() | {"draft": draft}

    async def start(self, body: dict) -> dict:
        if self.running:
            raise RunError("A run is already active. Press Stop first.", 409)
        accounts = str(body.get("accounts") or "")
        proxies = str(body.get("proxies") or "")
        n_accounts = count_account_lines(accounts)
        if n_accounts == 0:
            raise RunError("No accounts. Each line: email|password|totp")
        if n_accounts > MAX_ACCOUNTS:
            raise RunError(f"At most {MAX_ACCOUNTS} lines per run.")
        n_proxies = count_proxy_lines(proxies)
        if n_proxies > MAX_PROXIES:
            raise RunError(f"At most {MAX_PROXIES} proxies.")
        rows, proxy_errors = parse_proxy_text(proxies)
        if n_proxies and not rows:
            raise RunError("Could not read proxies. Use host:port:user:pass")
        if proxy_errors and not rows:
            raise RunError(proxy_errors[0])
        ok, bad = parse_accounts(accounts)
        concurrency = clamp_concurrency(int(body.get("concurrency") or DEFAULT_CONCURRENCY))
        timeout = clamp_timeout(int(body.get("timeout_secs") or DEFAULT_TIMEOUT))
        await self._write_draft(
            {
                "accounts": accounts,
                "proxies": proxies,
                "concurrency": concurrency,
                "timeout_secs": timeout,
            }
        )
        jobs = []
        idx = 0
        for email, message in bad:
            jobs.append(_row(idx, email, "", "", "invalid", message))
            idx += 1
        work = []
        for account in ok:
            jobs.append(_row(idx, account.email, account.password, account.totp_secret, "queued", ""))
            work.append((idx, account))
            idx += 1
        await self.store.replace_jobs(jobs)
        self.stop_event = asyncio.Event()
        if not work:
            self.running = False
            self.hub.publish("run", {"running": False})
            return await self.state()
        self.running = True
        self.hub.publish("run", {"running": True})
        self.task = asyncio.create_task(
            self._run(work, rows, concurrency, timeout),
            name="change-2fa",
        )
        return await self.state()

    async def stop(self) -> dict:
        self.stop_event.set()
        abort_prefix("c2fa:")
        return await self.state()

    async def clear(self, which: str) -> dict:
        if which not in {"done", "failed", "all"}:
            raise RunError("invalid filter")
        if which == "all":
            self.stop_event.set()
            abort_prefix("c2fa:")
            if self.task is not None and not self.task.done():
                self.task.cancel()
                try:
                    await self.task
                except asyncio.CancelledError:
                    pass
            self.running = False
        await self.store.clear_jobs(which)
        self.hub.publish("run", {"running": self.running})
        return await self.state()

    async def _write_draft(self, body: dict) -> dict:
        return await self.store.save_draft(
            str(body.get("accounts") or ""),
            str(body.get("proxies") or ""),
            clamp_concurrency(int(body.get("concurrency") or DEFAULT_CONCURRENCY)),
            clamp_timeout(int(body.get("timeout_secs") or DEFAULT_TIMEOUT)),
        )

    async def _run(self, work, proxy_rows, concurrency: int, timeout: int) -> None:
        pool = ProxyPool()
        pool.rows = list(proxy_rows)
        cursor = 0
        lock = asyncio.Lock()
        n = max(1, min(concurrency, len(work)))

        async def refresh():
            draft = await self.store.load_draft()
            rows, _err = parse_proxy_text(str(draft.get("proxies") or ""))
            return rows or list(proxy_rows)

        async def worker() -> None:
            nonlocal cursor
            while True:
                async with lock:
                    if cursor >= len(work):
                        return
                    idx, account = work[cursor]
                    cursor += 1
                if self.stop_event.is_set():
                    await self._finish(idx, status="cancelled", message="cancelled")
                    continue
                await self._mark_running(idx)
                try:
                    outcome = await self._one(idx, account, pool, refresh, timeout)
                except asyncio.CancelledError:
                    await self._finish(idx, status="cancelled", message="cancelled")
                    raise
                except Exception as exc:
                    await self._finish(idx, status="failed", message=str(exc) or type(exc).__name__)
                    continue
                if outcome.ok and outcome.verified:
                    await self._finish(
                        idx, status="done", message="done",
                        new_totp=outcome.new_totp, verified=True,
                    )
                else:
                    status = "cancelled" if outcome.error == "cancelled" else "failed"
                    await self._finish(
                        idx, status=status, message=outcome.error or "failed",
                        new_totp=outcome.new_totp,
                    )

        tasks = [asyncio.create_task(worker()) for _ in range(n)]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        finally:
            self.running = False
            self.hub.publish("run", {"running": False})

    async def _one(self, idx: int, account, pool: ProxyPool, refresh, timeout: int):
        async def emit(payload: dict) -> None:
            job = await self.store.note(
                idx,
                str(payload.get("step") or ""),
                str(payload.get("message") or ""),
                str(payload.get("level") or "info"),
            )
            self.hub.publish("log", {"idx": idx, **payload})
            if job:
                self.hub.publish("job", job)

        progress = CheckProgress(account.email, emit)

        async def login(proxy, secret):
            return await run_login(
                email=account.email,
                password=account.password,
                totp_secret=secret,
                proxy_url=proxy,
                simple_check=False,
                progress=progress,
            )

        async def rotate(proxy, *, access_token, device_id, on_step):
            return await rotate_mfa(
                access_token=access_token,
                proxy_url=proxy,
                device_id=device_id,
                on_step=on_step,
            )

        async def on_new_secret(secret: str) -> None:
            job = await self.store.update_job(idx, new_totp=secret, step="enrolled")
            if job:
                self.hub.publish("job", job)

        return await replace_totp(
            account,
            login=login,
            rotate=rotate,
            pool=pool,
            refresh_rows=refresh,
            url_for_row=lambda row: row.url,
            progress=progress,
            is_stopped=self.stop_event.is_set,
            on_new_secret=on_new_secret,
            timeout=timeout,
            abort_key=f"c2fa:{idx}",
        )

    async def _mark_running(self, idx: int) -> None:
        job = await self.store.update_job(
            idx, status="running", step="login", started_ms=int(time.time() * 1000),
        )
        if job:
            self.hub.publish("job", job)

    async def _finish(self, idx: int, *, status: str, message: str, new_totp: str = "", verified: bool = False) -> None:
        current = await self.store.get_job(idx)
        secret = new_totp or (current or {}).get("new_totp") or ""
        job = await self.store.update_job(
            idx,
            status=status,
            message=message,
            new_totp=secret,
            verified=verified,
            finished_ms=int(time.time() * 1000),
        )
        if job:
            self.hub.publish("job", job)


def _row(idx: int, email: str, password: str, totp: str, status: str, message: str) -> dict:
    return {
        "idx": idx,
        "email": email,
        "password": password,
        "old_totp": totp,
        "status": status,
        "message": message,
        "step": "",
    }
