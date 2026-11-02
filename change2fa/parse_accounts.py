"""Parse `email|password|old_totp` lines."""

from __future__ import annotations

import re
from dataclasses import dataclass

_B32 = re.compile(r"^[A-Z2-7]+=*$")
HINT = "use email|password|totp"


@dataclass(frozen=True)
class Account:
    email: str
    password: str
    totp_secret: str


def _norm_totp(raw: str) -> str:
    s = raw.strip().replace(" ", "").replace("-", "").upper()
    if not s:
        raise ValueError("missing totp")
    pad = "=" * ((8 - len(s) % 8) % 8)
    if not _B32.match(s + pad):
        raise ValueError("invalid totp")
    return s


def parse_account_line(line: str) -> Account | None:
    """Return None for blank lines and comments."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    parts = raw.split("|")
    if len(parts) != 3:
        raise ValueError(HINT)
    email = parts[0].strip().lower()
    if not email or "@" not in email:
        raise ValueError("invalid email")
    password = parts[1]
    if password == "":
        raise ValueError("missing password")
    if parts[2].strip().lower().startswith("http"):
        raise ValueError(HINT)
    return Account(email=email, password=password, totp_secret=_norm_totp(parts[2]))


def parse_accounts(text: str) -> tuple[list[Account], list[tuple[str, str]]]:
    ok: list[Account] = []
    bad: list[tuple[str, str]] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            account = parse_account_line(line)
        except ValueError as exc:
            email = raw.split("|", 1)[0].strip().lower() or "invalid"
            bad.append((email, str(exc)))
            continue
        if account is not None:
            ok.append(account)
    return ok, bad


def count_account_lines(text: str) -> int:
    n = 0
    for line in text.splitlines():
        raw = line.strip()
        if raw and not raw.startswith("#"):
            n += 1
    return n
