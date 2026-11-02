"""Login result types — shared to avoid import cycles."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SessionBundle:
    email: str
    access_token: str = ""
    session_token: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    device_id: str = ""
    password: str = ""
    totp_secret: str | None = None
    otp_url: str = ""
    session_payload: dict = field(default_factory=dict)


@dataclass
class LoginResult:
    ok: bool
    simple: bool = False
    needs_mfa: bool = False
    bundle: SessionBundle | None = None
    error: str | None = None
    fatal: bool = False  # invalid credential / locked / me mismatch
