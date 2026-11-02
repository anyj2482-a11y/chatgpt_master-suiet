"""Parse proxy lines and pick the next unused row."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from change2fa.protocol.proxy_parse import normalize_proxy_url, parse_proxy_line, to_url

Loader = Callable[[], Awaitable[list["ProxyRow"]]]


@dataclass
class ProxyRow:
    id: int
    url: str


def parse_proxy_text(text: str) -> tuple[list[ProxyRow], list[str]]:
    rows: list[ProxyRow] = []
    errors: list[str] = []
    n = 0
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        n += 1
        try:
            parsed = parse_proxy_line(raw)
            url = normalize_proxy_url(to_url(parsed))
            if not url:
                raise ValueError("empty proxy")
            rows.append(ProxyRow(id=n, url=url))
        except ValueError as exc:
            errors.append(str(exc))
    return rows, errors


def count_proxy_lines(text: str) -> int:
    n = 0
    for line in text.splitlines():
        raw = line.strip()
        if raw and not raw.startswith("#"):
            n += 1
    return n


def pick_row(rows: list[ProxyRow], tried: set[int], start: int) -> tuple[ProxyRow | None, int]:
    n = len(rows)
    if n == 0:
        return None, start
    for i in range(n):
        row = rows[(start + i) % n]
        if row.id not in tried:
            return row, start + i + 1
    return None, start + n


class ProxyPool:
    def __init__(self) -> None:
        self.rows: list[ProxyRow] = []
        self._cursor = 0
        self._load: asyncio.Task[list[ProxyRow]] | None = None

    async def ensure(self, loader: Loader) -> list[ProxyRow]:
        if self.rows:
            return self.rows
        if self._load is None:
            self._load = asyncio.create_task(loader())
        try:
            self.rows = list(await self._load)
        except Exception:
            self._load = None
            raise
        return self.rows

    def pick(self, tried: set[int]) -> ProxyRow | None:
        row, self._cursor = pick_row(self.rows, tried, self._cursor)
        return row

    def replace(self, rows: list[ProxyRow]) -> None:
        self.rows = list(rows)
        self._cursor = 0
        self._load = None
