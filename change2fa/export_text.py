"""Clipboard text. Verified lines are the only success export."""

from __future__ import annotations


def _email_key(email: str) -> tuple[str, str]:
    e = (email or "").lower()
    if "@" not in e:
        return ("\uffff", e)
    local, domain = e.split("@", 1)
    return (domain, local)


def verified_text(jobs: list[dict]) -> str:
    rows = [j for j in jobs if j.get("verified") and j.get("new_totp")]
    rows.sort(key=lambda j: _email_key(str(j.get("email") or "")))
    return "\n".join(
        f"{j['email']}|{j['password']}|{j['new_totp']}" for j in rows
    )


def error_text(jobs: list[dict]) -> str:
    rows = [
        j for j in jobs
        if j.get("status") in {"failed", "invalid", "cancelled"}
    ]
    lines = []
    for j in rows:
        msg = str(j.get("message") or "")
        secret = str(j.get("new_totp") or "")
        if secret and not j.get("verified"):
            msg = f"{msg} | secret: {secret}"
        lines.append(f"{j.get('email') or 'invalid'}  →  {msg}")
    return "\n".join(lines)
