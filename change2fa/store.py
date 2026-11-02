"""SQLite draft, jobs, and hop logs. Reload reads this file."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import aiosqlite

from change2fa.limits import DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT, MAX_CONCURRENCY

_SCHEMA = """
CREATE TABLE IF NOT EXISTS draft (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  accounts TEXT NOT NULL DEFAULT '',
  proxies TEXT NOT NULL DEFAULT '',
  concurrency INTEGER NOT NULL DEFAULT 3,
  timeout_secs INTEGER NOT NULL DEFAULT 120
);
CREATE TABLE IF NOT EXISTS jobs (
  idx INTEGER PRIMARY KEY,
  email TEXT NOT NULL,
  password TEXT NOT NULL,
  old_totp TEXT NOT NULL,
  status TEXT NOT NULL,
  step TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  new_totp TEXT NOT NULL DEFAULT '',
  verified INTEGER NOT NULL DEFAULT 0,
  started_ms INTEGER,
  finished_ms INTEGER
);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_idx INTEGER NOT NULL,
  ts_ms INTEGER NOT NULL,
  level TEXT NOT NULL,
  step TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_job ON logs(job_idx, id);
"""


def _now() -> int:
    return int(time.time() * 1000)


def _clamp_concurrency(n: int) -> int:
    return max(1, min(MAX_CONCURRENCY, int(n or DEFAULT_CONCURRENCY)))


def _job(row: aiosqlite.Row) -> dict:
    d = dict(row)
    d["verified"] = bool(d["verified"])
    return d


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.execute("INSERT INTO draft (id) VALUES (1) ON CONFLICT DO NOTHING")
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("store is closed")
        return self._db

    async def _one(self, idx: int) -> dict | None:
        cur = await self._conn().execute("SELECT * FROM jobs WHERE idx = ?", (idx,))
        row = await cur.fetchone()
        return _job(row) if row else None

    async def load_draft(self) -> dict:
        async with self._lock:
            cur = await self._conn().execute(
                "SELECT accounts, proxies, concurrency, timeout_secs FROM draft WHERE id = 1"
            )
            row = await cur.fetchone()
            if row is None:
                return {
                    "accounts": "",
                    "proxies": "",
                    "concurrency": DEFAULT_CONCURRENCY,
                    "timeout_secs": DEFAULT_TIMEOUT,
                }
            draft = dict(row)
            draft["concurrency"] = _clamp_concurrency(draft.get("concurrency", DEFAULT_CONCURRENCY))
            return draft

    async def save_draft(
        self, accounts: str, proxies: str, concurrency: int, timeout_secs: int
    ) -> dict:
        async with self._lock:
            await self._conn().execute(
                """
                UPDATE draft
                SET accounts = ?, proxies = ?, concurrency = ?, timeout_secs = ?
                WHERE id = 1
                """,
                (accounts, proxies, concurrency, timeout_secs),
            )
            await self._conn().commit()
            cur = await self._conn().execute(
                "SELECT accounts, proxies, concurrency, timeout_secs FROM draft WHERE id = 1"
            )
            row = await cur.fetchone()
            draft = dict(row)
            draft["concurrency"] = _clamp_concurrency(draft.get("concurrency", DEFAULT_CONCURRENCY))
            return draft if row else {}

    async def replace_jobs(self, rows: list[dict]) -> None:
        async with self._lock:
            db = self._conn()
            await db.execute("DELETE FROM logs")
            await db.execute("DELETE FROM jobs")
            await db.executemany(
                """
                INSERT INTO jobs (
                  idx, email, password, old_totp, status, step, message,
                  new_totp, verified, started_ms, finished_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        r["idx"], r["email"], r["password"], r["old_totp"], r["status"],
                        r.get("step") or "", r.get("message") or "",
                        r.get("new_totp") or "",
                        1 if r.get("verified") else 0,
                        r.get("started_ms"), r.get("finished_ms"),
                    )
                    for r in rows
                ],
            )
            await db.commit()

    async def list_jobs(self) -> list[dict]:
        async with self._lock:
            cur = await self._conn().execute("SELECT * FROM jobs ORDER BY idx")
            return [_job(r) for r in await cur.fetchall()]

    async def get_job(self, idx: int) -> dict | None:
        async with self._lock:
            return await self._one(idx)

    async def update_job(self, idx: int, **fields: object) -> dict | None:
        allowed = {
            "status", "step", "message", "new_totp", "verified",
            "started_ms", "finished_ms",
        }
        keys = [k for k in fields if k in allowed]
        async with self._lock:
            if not keys:
                return await self._one(idx)
            if "verified" in fields:
                fields["verified"] = 1 if fields["verified"] else 0
            sets = ", ".join(f"{k} = ?" for k in keys)
            values = [fields[k] for k in keys]
            await self._conn().execute(
                f"UPDATE jobs SET {sets} WHERE idx = ?",
                (*values, idx),
            )
            await self._conn().commit()
            return await self._one(idx)

    async def note(self, idx: int, step: str, message: str, level: str) -> dict | None:
        async with self._lock:
            db = self._conn()
            text = message[:500]
            await db.execute(
                "UPDATE jobs SET step = ?, message = ? WHERE idx = ?",
                (step, text, idx),
            )
            await db.execute(
                """
                INSERT INTO logs (job_idx, ts_ms, level, step, message)
                VALUES (?, ?, ?, ?, ?)
                """,
                (idx, _now(), level, step, text),
            )
            await db.execute(
                """
                DELETE FROM logs WHERE job_idx = ? AND id NOT IN (
                  SELECT id FROM logs WHERE job_idx = ? ORDER BY id DESC LIMIT 40
                )
                """,
                (idx, idx),
            )
            await db.commit()
            return await self._one(idx)

    async def logs(self, idx: int) -> list[dict]:
        async with self._lock:
            cur = await self._conn().execute(
                """
                SELECT ts_ms, level, step, message FROM logs
                WHERE job_idx = ? ORDER BY id
                """,
                (idx,),
            )
            return [dict(r) for r in await cur.fetchall()]

    async def clear_jobs(self, which: str) -> None:
        async with self._lock:
            db = self._conn()
            if which == "all":
                await db.execute("DELETE FROM logs")
                await db.execute("DELETE FROM jobs")
            elif which == "done":
                await db.execute(
                    "DELETE FROM logs WHERE job_idx IN "
                    "(SELECT idx FROM jobs WHERE verified = 1)"
                )
                await db.execute("DELETE FROM jobs WHERE verified = 1")
            elif which == "failed":
                await db.execute(
                    """
                    DELETE FROM logs WHERE job_idx IN (
                      SELECT idx FROM jobs
                      WHERE status IN ('failed', 'invalid', 'cancelled')
                    )
                    """
                )
                await db.execute(
                    "DELETE FROM jobs WHERE status IN ('failed', 'invalid', 'cancelled')"
                )
            await db.commit()

    async def mark_interrupted(self) -> None:
        async with self._lock:
            await self._conn().execute(
                """
                UPDATE jobs
                SET status = 'failed',
                    step = 'interrupted',
                    message = CASE
                      WHEN message = '' THEN 'previous run stopped'
                      ELSE message
                    END,
                    finished_ms = ?
                WHERE status IN ('queued', 'running')
                """,
                (_now(),),
            )
            await self._conn().commit()
