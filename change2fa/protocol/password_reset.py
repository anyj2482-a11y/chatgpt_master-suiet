"""OpenAI Password Reset & Rotation Protocol.

Handles requesting email verification code and applying new password.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

from change2fa.protocol.login import endpoints as ep
from change2fa.protocol.login.csrf import step_csrf
from change2fa.protocol.login.headers import (
    LOGIN_IMPERSONATE,
    LOGIN_UA,
    apply_browser_session_headers,
    auth_api_headers,
)
from change2fa.protocol.login.otp import step_email_otp_validate
from change2fa.protocol.login.prime import step_prime
from change2fa.protocol.login.signin import post_signin
from change2fa.protocol.login.ssl_recover import open_login_session
from change2fa.protocol.login.timings import HOP
from change2fa.protocol.login.flow import run_login
from change2fa.protocol.sentinel_pow import get_sentinel_token_pow

log = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 900  # 15 minutes


class PasswordResetSession:
    def __init__(
        self,
        session_id: str,
        email: str,
        session: Any,
        device_id: str,
        logging_id: str,
        proxy_url: str | None = None,
    ):
        self.session_id = session_id
        self.email = email
        self.session = session
        self.device_id = device_id
        self.logging_id = logging_id
        self.proxy_url = proxy_url
        self.created_at = time.time()

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > SESSION_TTL_SECONDS

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass


class PasswordResetManager:
    def __init__(self):
        self._sessions: dict[str, PasswordResetSession] = {}
        self._lock = threading.Lock()

    def _cleanup_expired(self):
        with self._lock:
            expired_ids = [sid for sid, s in self._sessions.items() if s.is_expired()]
            for sid in expired_ids:
                s = self._sessions.pop(sid, None)
                if s:
                    s.close()

    def request_reset_otp(self, email: str, proxy_url: str | None = None) -> dict[str, Any]:
        """Start login flow and dispatch password reset verification code to account's email."""
        self._cleanup_expired()
        email = email.strip().lower()
        if not email or "@" not in email:
            return {"ok": False, "error": "Invalid email address format."}

        device_id = str(uuid.uuid4())
        logging_id = str(uuid.uuid4())
        session = open_login_session(
            proxy_url=proxy_url, impersonate=LOGIN_IMPERSONATE, timeout=HOP
        )
        apply_browser_session_headers(session, device_id, logging_id)

        try:
            # 1. Step prime
            ref = step_prime(session, email, device_id, logging_id, proxy_url=proxy_url)
            if hasattr(ref, "ok") and not ref.ok:
                session.close()
                return {"ok": False, "error": ref.error or "Bootstrap initialization failed"}

            # 2. Step CSRF
            csrf_or_err = step_csrf(session, device_id, logging_id, referer=ref)
            if hasattr(csrf_or_err, "ok") and not csrf_or_err.ok:
                session.close()
                return {"ok": False, "error": csrf_or_err.error or "CSRF setup failed"}
            csrf = csrf_or_err

            # 3. Post signin
            auth_url = post_signin(
                session,
                csrf=csrf,
                device_id=device_id,
                logging_id=logging_id,
                referer=ref,
                login_hint=email,
            )
            if hasattr(auth_url, "ok") and not auth_url.ok:
                session.close()
                return {"ok": False, "error": auth_url.error or "Signin initiation failed"}

            # 4. Visit auth_url to initialize session cookies
            r_auth = session.get(auth_url, allow_redirects=True, timeout=HOP)
            log.info("Auth URL landed at: %s", r_auth.url)

            # 5. Dispatch OTP code via password/send-otp
            headers = auth_api_headers(device_id)
            headers["Referer"] = f"{ep.AUTH_BASE}/reset-password"
            r_send = session.post(
                f"{ep.AUTH_BASE}/api/accounts/password/send-otp",
                headers=headers,
                json={},
                timeout=HOP,
            )

            if r_send.status_code != 200:
                err_text = r_send.text or ""
                session.close()
                return {
                    "ok": False,
                    "error": f"Failed to send reset code (HTTP {r_send.status_code}): {err_text[:200]}",
                }

            # Store session
            reset_id = str(uuid.uuid4())
            with self._lock:
                self._sessions[reset_id] = PasswordResetSession(
                    session_id=reset_id,
                    email=email,
                    session=session,
                    device_id=device_id,
                    logging_id=logging_id,
                    proxy_url=proxy_url,
                )

            return {
                "ok": True,
                "reset_id": reset_id,
                "email": email,
                "message": f"Verification code sent to {email}! Please check your email inbox and enter the 6-digit code.",
            }
        except Exception as e:
            try:
                session.close()
            except Exception:
                pass
            log.exception("Password reset request error")
            return {"ok": False, "error": str(e)}

    async def confirm_reset_and_verify(
        self,
        reset_id: str,
        code: str,
        new_password: str,
        totp_secret: str | None = None,
    ) -> dict[str, Any]:
        """Validate email OTP code, submit new password to OpenAI, and verify login."""
        self._cleanup_expired()
        with self._lock:
            reset_sess = self._sessions.get(reset_id)

        if not reset_sess or reset_sess.is_expired():
            return {
                "ok": False,
                "error": "Reset session expired or invalid. Please request a new verification code.",
            }

        code = code.strip().replace(" ", "").replace("-", "")
        new_password = new_password.strip()
        if len(new_password) < 8:
            return {"ok": False, "error": "New password must be at least 8 characters long."}

        session = reset_sess.session
        device_id = reset_sess.device_id
        email = reset_sess.email
        proxy_url = reset_sess.proxy_url

        try:
            # 1. Validate email OTP code
            val_res = step_email_otp_validate(session, code, device_id)
            if not val_res.ok:
                err_msg = val_res.error or "Invalid verification code"
                if val_res.wrong_code:
                    err_msg = "Incorrect 6-digit code. Please check your email and try again."
                return {"ok": False, "error": err_msg}

            # 2. Submit new password
            headers = auth_api_headers(
                device_id,
                {
                    "Referer": f"{ep.AUTH_BASE}/email-verification",
                    "Content-Type": "application/json",
                },
            )
            # Add sentinel token for password reset
            pw_tok = get_sentinel_token_pow(session, device_id, "password_reset", LOGIN_UA)
            if pw_tok:
                headers["openai-sentinel-token"] = pw_tok

            r_reset = session.post(
                f"{ep.AUTH_BASE}/api/accounts/password/reset",
                headers=headers,
                json={"password": new_password},
                allow_redirects=False,
                timeout=HOP,
            )

            if r_reset.status_code not in (200, 201, 302):
                err_text = r_reset.text or ""
                return {
                    "ok": False,
                    "error": f"Password update failed (HTTP {r_reset.status_code}): {err_text[:250]}",
                }

            # Successfully set password! Remove session
            with self._lock:
                self._sessions.pop(reset_id, None)
            reset_sess.close()

            # 3. Verify login with new password
            verified = False
            login_err = None
            if totp_secret:
                totp_clean = totp_secret.strip().replace(" ", "").upper()
                login_res = await run_login(
                    email=email,
                    password=new_password,
                    totp_secret=totp_clean,
                    proxy_url=proxy_url,
                    simple_check=False,
                )
                if login_res.ok:
                    verified = True
                else:
                    login_err = login_res.error
            else:
                # Login without TOTP (if account has no 2FA)
                login_res = await run_login(
                    email=email,
                    password=new_password,
                    totp_secret=None,
                    proxy_url=proxy_url,
                    simple_check=False,
                )
                if login_res.ok:
                    verified = True
                else:
                    login_err = login_res.error

            out_line = f"{email}|{new_password}"
            if totp_secret:
                out_line = f"{email}|{new_password}|{totp_secret.strip()}"

            msg = "Password reset successfully!"
            if verified:
                msg = "Password reset and verified! Account logged in successfully with new credentials."
            elif login_err:
                msg = f"Password reset was submitted, but verification check returned: {login_err}"

            return {
                "ok": True,
                "email": email,
                "new_password": new_password,
                "account_line": out_line,
                "verified": verified,
                "message": msg,
            }
        except Exception as e:
            log.exception("Password reset confirm error")
            return {"ok": False, "error": str(e)}


# Singleton instance
password_reset_mgr = PasswordResetManager()
