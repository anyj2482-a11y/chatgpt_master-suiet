"""ChatGPT 2FA Master Server - 5-in-1 Suite with Job History."""

from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import asyncio
import base64
import json
import logging
import os
import re
import sqlite3
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add local path for change2fa imports
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from change2fa.protocol.http_session import create_session
from change2fa.protocol.mfa_urls import MFA_ACTIVATE, MFA_DISABLE, MFA_ENROLL, MFA_INFO
from change2fa.protocol.rotate import rotate
from change2fa.protocol.totp import totp, totp_remaining
from change2fa.protocol.login.flow import run_login
from change2fa.protocol.probe import run_probe
from change2fa.protocol.password_reset import password_reset_mgr
from change2fa.protocol.promo import check_promo_eligibility_with_token
from change2fa.protocol.sentinel_pow import get_checkout_sentinel_token

def stripe_encode_hash(data: dict) -> str:
    """Encode Stripe checkout dynamic hash fragment (XOR 5 + base64 + urlquote)."""
    raw_str = json.dumps(data, separators=(',', ':'))
    pad_len = 3 - (len(raw_str) % 3)
    if pad_len == 3:
        pad_len = 0
    padded = raw_str + (" " * pad_len)
    xored = "".join(chr(5 ^ ord(c)) for c in padded)
    b64 = base64.b64encode(xored.encode("latin1")).decode("ascii")
    return urllib.parse.quote(b64)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("2fa-master")

app = FastAPI(title="ChatGPT 2FA Master Suite")
app.add_middleware(GZipMiddleware, minimum_size=1000)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Layer (Hybrid: Supabase REST, PostgreSQL Direct, or Local SQLite)
DATA_DIR = ROOT_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "jobs.db"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# Check if direct PostgreSQL password was filled
IS_DIRECT_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://")) and "[YOUR-PASSWORD]" not in DATABASE_URL
IS_SUPABASE_REST = bool(SUPABASE_URL and SUPABASE_KEY)

if IS_DIRECT_POSTGRES:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]
    import psycopg2
    from psycopg2.extras import RealDictCursor
    logger.info("Using PostgreSQL Direct database backend")
elif IS_SUPABASE_REST:
    import urllib.request
    logger.info("Using Supabase REST API database backend (%s)", SUPABASE_URL)
else:
    logger.info("Using local SQLite database backend (%s)", DB_PATH)


def init_db():
    if IS_DIRECT_POSTGRES:
        try:
            with psycopg2.connect(DATABASE_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS jobs (
                            id SERIAL PRIMARY KEY,
                            timestamp VARCHAR(64) NOT NULL,
                            action VARCHAR(128) NOT NULL,
                            account VARCHAR(255) NOT NULL,
                            status VARCHAR(32) NOT NULL,
                            result TEXT,
                            error TEXT
                        );
                        CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
                        CREATE INDEX IF NOT EXISTS idx_jobs_timestamp ON jobs(timestamp);
                        CREATE INDEX IF NOT EXISTS idx_jobs_action ON jobs(action);
                        """
                    )
                conn.commit()
            logger.info("PostgreSQL database initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize PostgreSQL: %s", e)
    else:
        with sqlite3.connect(DB_PATH) as _c:
            _c.execute("PRAGMA journal_mode = WAL;")
            _c.execute("PRAGMA synchronous = NORMAL;")
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    account TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result TEXT,
                    error TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_timestamp ON jobs(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_action ON jobs(action);")
            conn.commit()


init_db()


def log_job(action: str, account: str, status: str, result: str = "", error: str = ""):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # 1. Try Supabase REST if configured
    if IS_SUPABASE_REST:
        try:
            url = f"{SUPABASE_URL}/rest/v1/jobs"
            headers = {
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal"
            }
            payload = json.dumps({
                "timestamp": now,
                "action": action,
                "account": account or "Unknown Account",
                "status": status,
                "result": result or "",
                "error": error or ""
            }).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 201):
                    return
        except Exception as e:
            logger.warning("Supabase REST log_job error: %s (falling back to local SQLite)", e)

    # 2. Try Direct PostgreSQL if configured
    if IS_DIRECT_POSTGRES:
        try:
            with psycopg2.connect(DATABASE_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO jobs (timestamp, action, account, status, result, error) VALUES (%s, %s, %s, %s, %s, %s)",
                        (now, action, account or "Unknown Account", status, result, error),
                    )
                conn.commit()
            return
        except Exception as e:
            logger.error("PostgreSQL log_job error: %s", e)

    # 3. Always log to local SQLite
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO jobs (timestamp, action, account, status, result, error) VALUES (?, ?, ?, ?, ?, ?)",
                (now, action, account or "Unknown Account", status, result, error),
            )
            conn.commit()
    except Exception as e:
        logger.error("Failed to log job to SQLite: %s", e)


def get_jobs(limit: int = 500, status: str | None = None):
    # 1. Try Supabase REST
    if IS_SUPABASE_REST:
        try:
            query = f"?select=*&order=id.desc&limit={limit}"
            if status:
                query += f"&status=eq.{status.upper()}"
            url = f"{SUPABASE_URL}/rest/v1/jobs{query}"
            headers = {
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
            }
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if isinstance(data, list):
                        return data
        except Exception as e:
            logger.warning("Supabase REST get_jobs error: %s (falling back to local SQLite)", e)

    # 2. Try Direct PostgreSQL
    if IS_DIRECT_POSTGRES:
        try:
            with psycopg2.connect(DATABASE_URL) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    if status:
                        cur.execute("SELECT * FROM jobs WHERE status = %s ORDER BY id DESC LIMIT %s", (status.upper(), limit))
                    else:
                        cur.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT %s", (limit,))
                    return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            logger.error("PostgreSQL get_jobs error: %s", e)

    # 3. Fall back to local SQLite
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            if status:
                cur.execute("SELECT * FROM jobs WHERE status = ? ORDER BY id DESC LIMIT ?", (status.upper(), limit))
            else:
                cur.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        logger.error("SQLite get_jobs error: %s", e)
        return []


def extract_token_device_and_email(raw: str) -> tuple[str, str | None, str | None]:
    """Auto-detect token, device ID, and account email from raw input or JSON."""
    cleaned = raw.strip()
    device_id = None
    email = None
    token = ""

    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            data = json.loads(cleaned)
            token = data.get("accessToken") or data.get("sessionToken") or ""
            statsig = data.get("statsigContext")
            if isinstance(statsig, dict):
                device_id = statsig.get("deviceId")
            u = data.get("user")
            if isinstance(u, dict) and u.get("email"):
                email = u.get("email")
        except Exception:
            pass

    if not token:
        jwt_match = re.search(r"eyJ[a-zA-Z0-9_\-\.]+", cleaned)
        if jwt_match:
            token = jwt_match.group(0)
        else:
            token = cleaned

    # Try extracting email from JWT payload if not found
    if not email and "." in token:
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                pad = "=" * ((4 - len(parts[1]) % 4) % 4)
                payload_json = base64.b64decode(parts[1] + pad).decode("utf-8")
                payload = json.loads(payload_json)
                prof = payload.get("https://api.openai.com/profile")
                if isinstance(prof, dict) and prof.get("email"):
                    email = prof.get("email")
                elif payload.get("email"):
                    email = payload.get("email")
        except Exception:
            pass

    return token.strip(), device_id, email


class SessionSetupRequest(BaseModel):
    session_data: str
    device_id: str | None = None
    proxy: str | None = None


class SessionRotateRequest(BaseModel):
    session_data: str
    device_id: str | None = None
    proxy: str | None = None


class CredentialRotateRequest(BaseModel):
    account_line: str  # email|password|old_totp
    proxy: str | None = None


class LogoutAllRequest(BaseModel):
    account_line: str  # email|password|2fa_secret
    proxy: str | None = None


class FastLoginRequest(BaseModel):
    account_line: str  # email|password|2fa_secret
    proxy: str | None = None


class LaunchBrowserRequest(BaseModel):
    session_token: str
    device_id: str | None = None
    email: str | None = None
    target_url: str | None = None




class PromoCheckoutRequest(BaseModel):
    account_input: str  # email|pass|2fa OR session JSON OR access token
    coupon: str | None = "plus-1-month-free"
    proxy: str | None = None
    country: str | None = "IN"
    currency: str | None = "INR"

class PromoStatusRequest(BaseModel):
    account_input: str
    proxy: str | None = None

class PromoCheckRequest(BaseModel):
    account_input: str  # email|pass|2fa OR session JSON OR access token
    custom_coupon: str | None = None
    proxy: str | None = None


class TotpRequest(BaseModel):
    secret: str

class PasswordResetRequest(BaseModel):
    account_input: str  # email OR email|pass|2fa OR session JSON
    proxy: str | None = None


class PasswordResetConfirmRequest(BaseModel):
    reset_id: str
    code: str
    new_password: str
    totp_secret: str | None = None


def extract_email_from_any(raw: str) -> str | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    # Check if JSON
    if raw.startswith("{") and raw.endswith("}"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                user = data.get("user")
                if isinstance(user, dict) and user.get("email"):
                    return str(user["email"]).strip()
                profile = data.get("https://api.openai.com/profile")
                if isinstance(profile, dict) and profile.get("email"):
                    return str(profile["email"]).strip()
                if data.get("email"):
                    return str(data["email"]).strip()
        except Exception:
            pass
    # Check if pipeline format: email|pass|2fa
    if "|" in raw:
        first = raw.split("|")[0].strip()
        if "@" in first:
            return first
    # Check if regex email
    match = re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", raw)
    if match:
        return match.group(0).strip()
    return None



@app.post("/api/fast_login")
async def fast_login_endpoint(req: FastLoginRequest):
    """Fast Login with email|password|2fa_secret in seconds."""
    line = req.account_line.strip()
    parts = line.split("|")
    if len(parts) < 3:
        err = "Format must be: email|password|2fa_secret"
        log_job("Fast Login", line, "FAILED", error=err)
        return {"ok": False, "error": err}

    email = parts[0].strip()
    password = parts[1].strip()
    totp_sec = parts[2].strip().replace(" ", "").upper()

    t0 = time.time()
    try:
        login_res = await run_login(
            email=email,
            password=password,
            totp_secret=totp_sec,
            proxy_url=req.proxy,
            simple_check=False,
        )
        elapsed = round(time.time() - t0, 2)

        if not login_res.ok or not login_res.bundle:
            err = login_res.error or "Login failed"
            log_job("Fast Login", email, "FAILED", error=f"{err} ({elapsed}s)")
            return {"ok": False, "error": err, "elapsed_seconds": elapsed}

        bundle = login_res.bundle
        access_token = bundle.access_token
        session_token = bundle.session_token
        device_id = getattr(bundle, "device_id", None)
        session_payload = bundle.session_payload or {}

        user_info = session_payload.get("user") or {}
        account_info = session_payload.get("account") or {}
        plan_type = account_info.get("planType") or "free"
        expires = session_payload.get("expires") or "N/A"

        out_line = f"{email}|{password}|{totp_sec}"
        log_job("Fast Login", email, "SUCCESS", result=f"{out_line} [Plan: {plan_type.upper()}] ({elapsed}s)")
        return {
            "ok": True,
            "email": email,
            "name": user_info.get("name") or "User",
            "plan_type": plan_type,
            "expires": expires,
            "elapsed_seconds": elapsed,
            "access_token": access_token,
            "session_token": session_token,
            "device_id": device_id,
            "session_payload": session_payload,
            "account_line": f"{email}|{password}|{totp_sec}",
            "message": f"Successfully authenticated in {elapsed}s!",
        }
    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        logger.exception("Fast login error")
        err = str(e)
        log_job("Fast Login", email, "FAILED", error=f"{err} ({elapsed}s)")
        return {"ok": False, "error": err, "elapsed_seconds": elapsed}


@app.post("/api/accounts/logout_all")
async def logout_all_endpoint(req: LogoutAllRequest):
    """Log out account from all devices using email|password|2fa_secret."""
    line = req.account_line.strip()
    parts = line.split("|")
    if len(parts) < 3:
        err = "Format must be: email|password|2fa_secret"
        log_job("Clear Sessions", line, "FAILED", error=err)
        return {"ok": False, "error": err}

    email = parts[0].strip()
    password = parts[1].strip()
    totp_sec = parts[2].strip().replace(" ", "").upper()
    proxy_url = req.proxy
    if len(parts) >= 4 and (parts[3].startswith("http://") or parts[3].startswith("https://") or parts[3].startswith("socks5://")):
        proxy_url = parts[3].strip()

    t0 = time.time()
    try:
        # Step 1: Authenticate with credentials + 2FA
        login_res = await run_login(
            email=email,
            password=password,
            totp_secret=totp_sec,
            proxy_url=proxy_url,
            simple_check=False,
        )
        if not login_res.ok or not login_res.bundle:
            err = login_res.error or "Login failed"
            elapsed = round(time.time() - t0, 2)
            log_job("Clear Sessions", email, "FAILED", error=f"{err} ({elapsed}s)")
            return {"ok": False, "error": err, "elapsed_seconds": elapsed}

        bundle = login_res.bundle
        access_token = bundle.access_token
        device_id = getattr(bundle, "device_id", None)

        # Step 2: Call OpenAI's logout_all endpoint via sync session in thread
        def _do_logout_all():
            s = create_session(proxy_url=proxy_url, impersonate="chrome131")
            try:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Accept": "*/*",
                    "Origin": "https://chatgpt.com",
                    "Referer": "https://chatgpt.com/",
                    "oai-language": "en-US",
                }
                if device_id:
                    headers["oai-device-id"] = device_id

                # 1. Fetch active devices count
                devices_list = []
                try:
                    info_resp = s.get("https://chatgpt.com/backend-api/accounts/sessions", headers=headers)
                    if info_resp.status_code == 200:
                        dev_data = info_resp.json()
                        devices_list = dev_data.get("devices") or []
                except Exception:
                    pass

                # 2. Trigger global logout
                resp = s.post("https://chatgpt.com/backend-api/accounts/logout_all", headers=headers, json={})
                if resp.status_code != 200:
                    raise RuntimeError(f"OpenAI logout_all returned HTTP {resp.status_code}: {resp.text}")

                return len(devices_list)
            finally:
                s.close()

        revoked_count = await asyncio.to_thread(_do_logout_all)
        elapsed = round(time.time() - t0, 2)
        res_msg = f"Logged out from everywhere ({revoked_count} active sessions revoked) in {elapsed}s"
        log_job("Clear Sessions", email, "SUCCESS", result=res_msg)

        return {
            "ok": True,
            "email": email,
            "devices_revoked": revoked_count,
            "elapsed_seconds": elapsed,
            "message": f"Successfully logged out from everywhere! {revoked_count} active session(s) revoked in {elapsed}s.",
        }
    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        logger.exception("Logout all error")
        err = str(e)
        log_job("Clear Sessions", email, "FAILED", error=f"{err} ({elapsed}s)")
        return {"ok": False, "error": err, "elapsed_seconds": elapsed}


@app.post("/api/launch_session_browser")
async def launch_session_browser_endpoint(req: LaunchBrowserRequest):
    """Launch Brave/Chrome with session cookies and navigate to ChatGPT."""
    if not req.session_token:
        return {"ok": False, "error": "No sessionToken provided."}

    import subprocess
    import urllib.request
    import websockets

    brave_path = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
    chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    edge_path_alt = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"

    browser_path = None
    browser_name = "Browser"
    if os.path.exists(brave_path):
        browser_path = brave_path
        browser_name = "Brave"
    elif os.path.exists(chrome_path):
        browser_path = chrome_path
        browser_name = "Chrome"
    elif os.path.exists(edge_path):
        browser_path = edge_path
        browser_name = "Edge"
    elif os.path.exists(edge_path_alt):
        browser_path = edge_path_alt
        browser_name = "Edge"
    else:
        return {"ok": False, "error": "Neither Brave, Chrome, nor Edge browser was found on this system."}

    port = 9225
    user_data = str(DATA_DIR / "browser_session_profile")

    # Generate quick desktop launcher batch file
    try:
        bat_file = ROOT_DIR / "open_active_chatgpt.bat"
        with open(bat_file, "w", encoding="utf-8") as f:
            f.write(f'@echo off\nstart "" "{browser_path}" --user-data-dir="{user_data}" https://chatgpt.com\n')
    except Exception:
        pass

    cmd = [
        browser_path,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data}",
        "--no-first-run",
        "--no-default-browser-check",
        "about:blank",
    ]

    try:
        need_spawn = True
        try:
            req_check = urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1.0)
            if req_check.status == 200:
                need_spawn = False
        except Exception:
            pass

        if need_spawn:
            subprocess.Popen(cmd)
            await asyncio.sleep(2.0)

        req_targets = urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=3.0)
        targets = json.loads(req_targets.read().decode())
        if not targets:
            raise RuntimeError(f"No {browser_name} browser targets found.")

        page_target = next((t for t in targets if t.get("type") == "page"), targets[0])
        ws_url = page_target["webSocketDebuggerUrl"]

        async with websockets.connect(ws_url) as ws:
            # 1. Clear old cookies
            await ws.send(json.dumps({"id": 1, "method": "Network.clearBrowserCookies"}))
            await ws.recv()

            # 2. Set chunked cookies
            CHUNK_SIZE = 3900
            token = req.session_token
            if len(token) > CHUNK_SIZE:
                chunk_count = (len(token) + CHUNK_SIZE - 1) // CHUNK_SIZE
                for i in range(chunk_count):
                    chunk_val = token[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
                    cookie_cmd = {
                        "id": 10 + i,
                        "method": "Network.setCookie",
                        "params": {
                            "name": f"__Secure-next-auth.session-token.{i}",
                            "value": chunk_val,
                            "url": "https://chatgpt.com",
                            "secure": True,
                            "httpOnly": True,
                            "sameSite": "Lax",
                        },
                    }
                    await ws.send(json.dumps(cookie_cmd))
                    await ws.recv()
            else:
                cookie_cmd = {
                    "id": 10,
                    "method": "Network.setCookie",
                    "params": {
                        "name": "__Secure-next-auth.session-token",
                        "value": token,
                        "url": "https://chatgpt.com",
                        "secure": True,
                        "httpOnly": True,
                        "sameSite": "Lax",
                    },
                }
                await ws.send(json.dumps(cookie_cmd))
                await ws.recv()

            # 3. Set oai-did
            if req.device_id:
                did_cmd = {
                    "id": 20,
                    "method": "Network.setCookie",
                    "params": {
                        "name": "oai-did",
                        "value": req.device_id,
                        "url": "https://chatgpt.com",
                        "secure": True,
                        "sameSite": "Lax",
                    },
                }
                await ws.send(json.dumps(did_cmd))
                await ws.recv()

            # 4. Navigate directly to ChatGPT or custom target URL
            dest_url = req.target_url or "https://chatgpt.com/"
            nav_cmd = {
                "id": 30,
                "method": "Page.navigate",
                "params": {"url": dest_url},
            }
            await ws.send(json.dumps(nav_cmd))
            await ws.recv()

        acc = req.email or "Fast Login Account"
        log_job("Fast Login (Browser)", acc, "SUCCESS", result=f"Opened in {browser_name}")

        return {
            "ok": True,
            "browser": browser_name,
            "message": f"{browser_name} launched! ChatGPT opened with this account authenticated.",
        }
    except Exception as e:
        logger.exception("Failed to launch browser for session")
        return {"ok": False, "error": f"Failed to launch browser: {e}"}


@app.get("/api/history")
async def fetch_history(status: str | None = None):
    jobs = get_jobs(limit=500, status=status)
    total, success_count, failed_count = 0, 0, 0
    try:
        if IS_SUPABASE_REST:
            # Calculate from jobs list or fetch stats
            total = len(jobs)
            success_count = sum(1 for j in jobs if str(j.get("status", "")).upper() == "SUCCESS")
            failed_count = sum(1 for j in jobs if str(j.get("status", "")).upper() == "FAILED")
        elif IS_DIRECT_POSTGRES:
            with psycopg2.connect(DATABASE_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM jobs")
                    total = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'SUCCESS'")
                    success_count = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'FAILED'")
                    failed_count = cur.fetchone()[0]
        else:
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM jobs")
                total = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'SUCCESS'")
                success_count = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM jobs WHERE status = 'FAILED'")
                failed_count = cur.fetchone()[0]
    except Exception as e:
        logger.error("Failed to fetch history stats: %s", e)

    engine_name = "Supabase" if IS_SUPABASE_REST else ("PostgreSQL" if IS_DIRECT_POSTGRES else "SQLite")

    return {
        "ok": True,
        "engine": engine_name,
        "jobs": jobs,
        "stats": {
            "total": total,
            "success": success_count,
            "failed": failed_count,
        },
    }


@app.get("/api/history/export")
async def export_successful():
    """Export all successful job results in a clean text format."""
    jobs = get_jobs(limit=10000, status="SUCCESS")
    lines = []
    for j in reversed(jobs):
        res = (j.get("result") or "").strip()
        acc = (j.get("account") or "").strip()
        ts = j.get("timestamp") or ""
        act = j.get("action") or ""
        lines.append(f"{acc} | {res} [{ts}]")
    return PlainTextResponse("\n".join(lines), media_type="text/plain")


@app.post("/api/history/clear")
async def clear_history():
    if IS_SUPABASE_REST:
        try:
            url = f"{SUPABASE_URL}/rest/v1/jobs?id=gt.0"
            headers = {
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
            }
            req = urllib.request.Request(url, headers=headers, method="DELETE")
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            logger.error("Failed to clear Supabase jobs: %s", e)
    elif IS_DIRECT_POSTGRES:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM jobs")
            conn.commit()
    else:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM jobs")
            conn.commit()
    return {"ok": True, "message": "History cleared"}


@app.post("/api/session/setup")
async def setup_2fa_from_session(req: SessionSetupRequest):
    """Tab 1: Setup 2FA for an account that currently has no 2FA (or fresh enroll)."""
    token, dev_id, account_email = extract_token_device_and_email(req.session_data)
    device_id = req.device_id or dev_id
    acc_label = account_email or "Session Account"

    if not token:
        log_job("Setup 2FA (Session)", acc_label, "FAILED", error="Invalid session token")
        raise HTTPException(status_code=400, detail="Invalid session token.")

    def _sync():
        session = create_session(proxy_url=req.proxy, impersonate="chrome131")
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "*/*",
                "Origin": "https://chatgpt.com",
                "Referer": "https://chatgpt.com/",
            }
            if device_id:
                headers["oai-device-id"] = device_id

            # 1. Check current MFA status
            info_resp = session.get(MFA_INFO, headers=headers)
            if info_resp.status_code != 200:
                raise RuntimeError(f"HTTP {info_resp.status_code}: {info_resp.text}")

            info = info_resp.json()
            if info.get("mfa_enabled") is True or info.get("mfa_enabled_v2") is True:
                msg = "2FA is already enabled on this account. Use Tab 4 to rotate."
                log_job("Setup 2FA (Session)", acc_label, "FAILED", error=msg)
                return {"ok": False, "already_enabled": True, "message": msg}

            # 2. Enroll
            enroll_resp = session.post(MFA_ENROLL, headers=headers, json={"factor_type": "totp"})
            if enroll_resp.status_code != 200:
                raise RuntimeError(f"Enroll HTTP {enroll_resp.status_code}: {enroll_resp.text}")

            enroll_data = enroll_resp.json()
            secret = enroll_data.get("secret")
            session_id = enroll_data.get("session_id")
            factor = enroll_data.get("factor") or {}
            factor_id = enroll_data.get("factor_id") or factor.get("id")

            if not secret or not session_id:
                raise RuntimeError(f"Missing secret or session_id: {enroll_data}")

            # 3. Compute code and activate
            code = totp(secret)
            act_resp = session.post(
                MFA_ACTIVATE,
                headers=headers,
                json={
                    "code": code,
                    "factor_type": "totp",
                    "session_id": session_id,
                },
            )
            if act_resp.status_code != 200:
                raise RuntimeError(f"Activate HTTP {act_resp.status_code}: {act_resp.text}")

            log_job("Setup 2FA (Session)", acc_label, "SUCCESS", result=secret)
            return {
                "ok": True,
                "secret": secret,
                "factor_id": factor_id,
                "activation_code": code,
                "message": "New 2FA enrolled and activated successfully!",
            }
        finally:
            session.close()

    try:
        result = await asyncio.to_thread(_sync)
        return result
    except Exception as e:
        logger.exception("Setup error")
        err_msg = str(e)
        log_job("Setup 2FA (Session)", acc_label, "FAILED", error=err_msg)
        return {"ok": False, "error": err_msg}


@app.post("/api/session/rotate")
async def rotate_2fa_from_session(req: SessionRotateRequest):
    """Tab 4: Change/Rotate 2FA for an account with existing 2FA using active session."""
    token, dev_id, account_email = extract_token_device_and_email(req.session_data)
    device_id = req.device_id or dev_id
    acc_label = account_email or "Session Account"

    if not token:
        log_job("Rotate 2FA (Session)", acc_label, "FAILED", error="Invalid session token")
        raise HTTPException(status_code=400, detail="Invalid session token.")

    try:
        res = await rotate(
            access_token=token,
            proxy_url=req.proxy,
            device_id=device_id,
        )
        log_job("Rotate 2FA (Session)", acc_label, "SUCCESS", result=res.totp_secret)
        return {
            "ok": True,
            "secret": res.totp_secret,
            "message": "Old 2FA was removed, and new 2FA has been activated!",
        }
    except Exception as e:
        logger.exception("Rotate error")
        err_msg = str(e)
        if "re-authenticate" in err_msg.lower() or "disable_old_totp" in err_msg:
            err_msg = (
                "OpenAI Security Policy: Disabling an active 2FA factor requires fresh password re-authentication. "
                "A static session token cannot disable an active 2FA. "
                "Please use Tab 3: Change 2FA via Credentials (email|password|current_2fa) which performs fresh authentication and rotates successfully!"
            )
        log_job("Rotate 2FA (Session)", acc_label, "FAILED", error=err_msg)
        return {"ok": False, "error": err_msg}


@app.post("/api/credentials/rotate")
async def rotate_2fa_from_credentials(req: CredentialRotateRequest):
    """Tab 3: Login with Email + Password + Old TOTP, then rotate to new TOTP."""
    line = req.account_line.strip()
    parts = line.split("|")
    if len(parts) < 3:
        err = "Format must be: email|password|old_totp"
        log_job("Rotate 2FA (Email/Pass)", line, "FAILED", error=err)
        return {"ok": False, "error": err}

    email = parts[0].strip()
    password = parts[1].strip()
    old_totp = parts[2].strip()

    try:
        # Step 1: Login with old TOTP
        login_res = await run_login(
            email=email,
            password=password,
            totp_secret=old_totp,
            proxy_url=req.proxy,
            simple_check=False,
        )
        if not login_res.ok or not login_res.bundle:
            err = login_res.error or "Login with old credentials/2FA failed"
            log_job("Rotate 2FA (Email/Pass)", email, "FAILED", error=err)
            return {"ok": False, "error": err}

        bundle = login_res.bundle
        access_token = bundle.access_token
        device_id = getattr(bundle, "device_id", None)

        # Step 2: Rotate via rotate protocol
        rotate_res = await rotate(
            access_token=access_token,
            proxy_url=req.proxy,
            device_id=device_id,
        )
        new_secret = rotate_res.totp_secret

        # Step 3: Verify login with new secret
        verify_res = await run_login(
            email=email,
            password=password,
            totp_secret=new_secret,
            proxy_url=req.proxy,
            simple_check=False,
        )
        if not verify_res.ok:
            err = f"Rotated, but verification login failed: {verify_res.error}"
            log_job("Rotate 2FA (Email/Pass)", email, "FAILED", error=err, result=new_secret)
            return {"ok": False, "new_secret": new_secret, "error": err}

        out_line = f"{email}|{password}|{new_secret}"
        log_job("Rotate 2FA (Email/Pass)", email, "SUCCESS", result=out_line)
        return {
            "ok": True,
            "new_secret": new_secret,
            "output_line": out_line,
            "message": "Successfully changed 2FA and verified new login!",
        }
    except Exception as e:
        logger.exception("Credential rotate error")
        err = str(e)
        log_job("Rotate 2FA (Email/Pass)", email, "FAILED", error=err)
        return {"ok": False, "error": err}


@app.post("/api/totp/live")
async def get_live_totp(req: TotpRequest):
    """Tab 5: Generate live 6-digit TOTP code and countdown."""
    sec = req.secret.strip().replace(" ", "").upper()
    try:
        code = totp(sec)
        rem = totp_remaining()
        return {
            "ok": True,
            "code": code,
            "remaining": int(rem),
        }
    except Exception as e:
        return {"ok": False, "error": f"Invalid 2FA secret: {e}"}



@app.post("/api/fast_login/launch_browser")
async def launch_browser_endpoint(req: LaunchBrowserRequest):
    """Launch Chrome browser with session cookies pre-injected to target URL."""
    try:
        import urllib.request
        import urllib.parse

        chrome_exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        if not os.path.exists(chrome_exe):
            chrome_exe = r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"

        target_url = req.target_url or "https://chatgpt.com/"
        if not os.path.exists(chrome_exe):
            import webbrowser
            webbrowser.open(target_url)
            return {"ok": True, "message": "Opened in default system browser"}

        import tempfile
        user_data = tempfile.mkdtemp(prefix="chatgpt_chrome_")
        debug_port = 9333

        cmd = [
            chrome_exe,
            f"--user-data-dir={user_data}",
            f"--remote-debugging-port={debug_port}",
            "--no-first-run",
            "--no-default-browser-check",
            target_url
        ]

        proc = subprocess.Popen(cmd)

        if req.session_token:
            async def _inject_cookies():
                await asyncio.sleep(1.5)
                try:
                    r = urllib.request.urlopen(f"http://127.0.0.1:{debug_port}/json/list", timeout=3)
                    tabs = json.loads(r.read().decode("utf-8"))
                    if tabs and "webSocketDebuggerUrl" in tabs[0]:
                        ws_url = tabs[0]["webSocketDebuggerUrl"]
                        import websockets
                        async with websockets.connect(ws_url) as ws:
                            await ws.send(json.dumps({
                                "id": 1,
                                "method": "Network.setCookie",
                                "params": {
                                    "name": "__Secure-next-auth.session-token",
                                    "value": req.session_token,
                                    "domain": "chatgpt.com",
                                    "path": "/",
                                    "secure": True,
                                    "httpOnly": True,
                                }
                            }))
                            if req.device_id:
                                await ws.send(json.dumps({
                                    "id": 2,
                                    "method": "Network.setCookie",
                                    "params": {
                                        "name": "oai-did",
                                        "value": req.device_id,
                                        "domain": "chatgpt.com",
                                        "path": "/",
                                        "secure": True,
                                    }
                                }))
                            await ws.send(json.dumps({
                                "id": 3,
                                "method": "Page.navigate",
                                "params": {"url": target_url}
                            }))
                except Exception as e:
                    logger.warning("CDP cookie injection notice: %s", e)

            asyncio.create_task(_inject_cookies())

        return {
            "ok": True,
            "pid": proc.pid,
            "target_url": target_url,
            "message": "Browser launched with authenticated session!"
        }
    except Exception as e:
        logger.exception("Launch browser error")
        return {"ok": False, "error": str(e)}


@app.post("/api/promo/check_status")
async def promo_check_status_endpoint(req: PromoStatusRequest):
    """Check if the account's plan has activated to Plus / Trial after UPI scan."""
    raw = req.account_input.strip()
    if not raw:
        return {"ok": False, "error": "No account provided"}
    try:
        token = None
        if "|" in raw:
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) >= 3:
                login_res = await run_login(
                    email=parts[0],
                    password=parts[1],
                    totp_secret=parts[2].replace(" ", "").upper(),
                    proxy_url=req.proxy,
                    simple_check=False,
                )
                if login_res.ok and login_res.bundle:
                    token = login_res.bundle.access_token
        else:
            token, _, _ = extract_token_device_and_email(raw)

        if not token:
            return {"ok": False, "error": "Could not extract active access token"}

        def _check_plan():
            s = create_session(proxy_url=req.proxy, impersonate="chrome131")
            try:
                headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
                r = s.get("https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27", headers=headers, timeout=12)
                if r.status_code == 200:
                    data = r.json() or {}
                    accounts = data.get("accounts") or {}
                    first_acc = next(iter(accounts.values()), {}).get("account") or {}
                    plan_type = first_acc.get("plan_type", "free")
                    is_trial = first_acc.get("is_trial", False)
                    return {
                        "ok": True,
                        "plan_type": plan_type,
                        "is_plus": plan_type in ("plus", "team", "pro"),
                        "is_trial": is_trial,
                    }
                return {"ok": False, "error": f"Status check HTTP {r.status_code}"}
            finally:
                s.close()

        return await asyncio.to_thread(_check_plan)
    except Exception as e:
        return {"ok": False, "error": str(e)}


# Mount static assets
STATIC_DIR = ROOT_DIR / "static"
STATIC_DIR.mkdir(exist_ok=True)


@app.post("/api/password/request_otp")
async def request_password_reset_otp(req: PasswordResetRequest):
    """Tab 7: Request 6-digit password reset verification code to account's email."""
    email = extract_email_from_any(req.account_input)
    if not email:
        return {"ok": False, "error": "Could not detect a valid email address. Please enter a valid email or email|pass|2fa."}

    t0 = time.time()
    try:
        res = await asyncio.to_thread(password_reset_mgr.request_reset_otp, email, req.proxy)
        elapsed = round(time.time() - t0, 2)
        if res.get("ok"):
            log_job("Password Reset Request", email, "SUCCESS", result=f"Code dispatched ({elapsed}s)")
        else:
            log_job("Password Reset Request", email, "FAILED", error=res.get("error", "Unknown error"))
        res["elapsed_seconds"] = elapsed
        return res
    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        logger.exception("Password reset request error")
        log_job("Password Reset Request", email, "FAILED", error=str(e))
        return {"ok": False, "error": str(e), "elapsed_seconds": elapsed}


@app.post("/api/password/confirm_reset")
async def confirm_password_reset(req: PasswordResetConfirmRequest):
    """Tab 7: Validate OTP code, set new password in OpenAI, and verify login."""
    t0 = time.time()
    try:
        res = await password_reset_mgr.confirm_reset_and_verify(
            reset_id=req.reset_id,
            code=req.code,
            new_password=req.new_password,
            totp_secret=req.totp_secret,
        )
        elapsed = round(time.time() - t0, 2)
        email = res.get("email") or "Account"
        if res.get("ok"):
            out_line = res.get("account_line", "")
            log_job("Password Reset Complete", email, "SUCCESS", result=f"{out_line} ({elapsed}s)")
        else:
            log_job("Password Reset Complete", email, "FAILED", error=res.get("error", "Failed"))
        res["elapsed_seconds"] = elapsed
        return res
    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        logger.exception("Password reset confirm error")
        log_job("Password Reset Complete", "Account", "FAILED", error=str(e))
        return {"ok": False, "error": str(e), "elapsed_seconds": elapsed}


# Mount static assets


@app.post("/api/promo/check")
async def check_promo_endpoint(req: PromoCheckRequest):
    """Tab 8: Check account promotional campaigns and coupon eligibility."""
    raw = req.account_input.strip()
    if not raw:
        return {"ok": False, "error": "Please provide an account (email|password|2fa, session JSON, or access token)."}

    t0 = time.time()
    try:
        # Check if credential line: email|password|2fa
        if "|" in raw:
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) >= 3:
                email = parts[0]
                password = parts[1]
                totp_sec = parts[2].replace(" ", "").upper()
                proxy_url = req.proxy
                if len(parts) >= 4 and parts[3].startswith(("http://", "https://", "socks5://")):
                    proxy_url = parts[3]

                login_res = await run_login(
                    email=email,
                    password=password,
                    totp_secret=totp_sec,
                    proxy_url=proxy_url,
                    simple_check=False,
                )
                if not login_res.ok or not login_res.bundle:
                    err = login_res.error or "Login failed"
                    return {"ok": False, "error": f"Authentication failed: {err}"}

                bundle = login_res.bundle
                access_token = bundle.access_token
                session_token = bundle.session_token
                device_id = getattr(bundle, "device_id", None)
                payload = bundle.session_payload or {}
                plan_type = (payload.get("account") or {}).get("planType") or "free"

                promo_res = await asyncio.to_thread(
                    check_promo_eligibility_with_token,
                    access_token=access_token,
                    device_id=device_id,
                    proxy_url=proxy_url,
                    custom_coupon=req.custom_coupon,
                )
                elapsed = round(time.time() - t0, 2)
                promo_res["email"] = email
                promo_res["plan_type"] = plan_type
                promo_res["session_token"] = session_token
                promo_res["device_id"] = device_id
                promo_res["account_line"] = f"{email}|{password}|{totp_sec}"
                promo_res["elapsed_seconds"] = elapsed

                log_job("Promo Offer Check", email, "SUCCESS", result=f"Plan: {plan_type.upper()} | Eligible: {promo_res.get('has_eligible_offers')} ({elapsed}s)")
                return promo_res

        # Otherwise treat as session JSON or raw access token
        token, dev_id, account_email = extract_token_device_and_email(raw)
        if not token:
            return {"ok": False, "error": "Could not extract valid access token or login credentials."}

        device_id = dev_id
        email = account_email or "Session Account"
        promo_res = await asyncio.to_thread(
            check_promo_eligibility_with_token,
            access_token=token,
            device_id=device_id,
            proxy_url=req.proxy,
            custom_coupon=req.custom_coupon,
        )
        elapsed = round(time.time() - t0, 2)
        promo_res["email"] = email
        promo_res["plan_type"] = "unknown"
        promo_res["session_token"] = None
        promo_res["device_id"] = device_id
        promo_res["account_line"] = email
        promo_res["elapsed_seconds"] = elapsed

        log_job("Promo Offer Check", email, "SUCCESS", result=f"Eligible: {promo_res.get('has_eligible_offers')} ({elapsed}s)")
        return promo_res

    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        logger.exception("Promo check error")
        return {"ok": False, "error": str(e), "elapsed_seconds": elapsed}


# Mount static assets


@app.post("/api/promo/create_checkout")
async def create_checkout_endpoint(req: PromoCheckoutRequest):
    """Tab 8: Generate Stripe custom checkout session for UPI QR payment."""
    raw = req.account_input.strip()
    if not raw:
        return {"ok": False, "error": "Please provide an account (email|password|2fa, session JSON, or access token)."}

    t0 = time.time()
    try:
        token = None
        device_id = None
        email = "Unknown"
        session_token = None

        if "|" in raw:
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) >= 3:
                email = parts[0]
                password = parts[1]
                totp_sec = parts[2].replace(" ", "").upper()
                proxy_url = req.proxy
                if len(parts) >= 4 and parts[3].startswith(("http://", "https://", "socks5://")):
                    proxy_url = parts[3]

                login_res = await run_login(
                    email=email,
                    password=password,
                    totp_secret=totp_sec,
                    proxy_url=proxy_url,
                    simple_check=False,
                )
                if not login_res.ok or not login_res.bundle:
                    return {"ok": False, "error": login_res.error or "Authentication failed"}

                bundle = login_res.bundle
                token = bundle.access_token
                session_token = bundle.session_token
                device_id = getattr(bundle, "device_id", None)
        else:
            tok, dev_id, acc_email = extract_token_device_and_email(raw)
            token = tok
            device_id = dev_id
            email = acc_email or "Session Account"
            session_token = raw if not raw.startswith("{") else None

        if not token:
            return {"ok": False, "error": "Invalid account credentials or session token."}

        device_id = device_id or str(uuid.uuid4())

        def _do_checkout():
            s = create_session(proxy_url=req.proxy, impersonate="chrome131")
            try:
                sentinel_tok = get_checkout_sentinel_token(s, device_id)
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "*/*",
                    "Origin": "https://chatgpt.com",
                    "Referer": "https://chatgpt.com/",
                    "oai-device-id": device_id,
                }
                if sentinel_tok:
                    headers["openai-sentinel-token"] = sentinel_tok

                import urllib.parse

                url = "https://chatgpt.com/backend-api/payments/checkout"
                payload = {
                    "plan": "chatgptplusplan",
                    "billing_details": {
                        "country": req.country or "IN",
                        "currency": req.currency or "INR"
                    }
                }
                if req.coupon and req.coupon.strip():
                    c_clean = req.coupon.strip()
                    payload["promo_campaign"] = c_clean
                    payload["coupon"] = c_clean

                r = s.post(url, headers=headers, json=payload, timeout=20)
                if r.status_code != 200:
                    return {"ok": False, "error": f"Checkout API failed (HTTP {r.status_code}): {r.text[:200]}"}

                data = r.json() or {}
                cs_id = data.get("checkout_session_id")
                pk = data.get("publishable_key")
                client_secret = data.get("client_secret")
                proc = data.get("processor_entity", "openai_llc")
                if not cs_id or not pk:
                    return {"ok": False, "error": f"Invalid checkout response from OpenAI: {data}"}

                hash_payload = {
                    "apiKey": pk,
                    "sessionId": cs_id,
                    "referrerOrigin": "https://chatgpt.com"
                }
                encoded_hash = stripe_encode_hash(hash_payload)
                checkout_url = f"https://checkout.stripe.com/c/pay/{cs_id}#{encoded_hash}"
                chatgpt_checkout_url = f"https://chatgpt.com/checkout/{proc}/{cs_id}"
                upi_intent_url = f"upi://pay?pa=stripe.chatgpt@icici&pn=OpenAI+LLC&mc=5499&tr={cs_id}&tn=ChatGPT+Plus+Promo&am=0.00&cu=INR"
                qr_image_url = f"https://api.qrserver.com/v1/create-qr-code/?size=440x440&margin=10&format=png&data={urllib.parse.quote_plus(checkout_url)}"
                upi_qr_image_url = f"https://api.qrserver.com/v1/create-qr-code/?size=440x440&margin=10&format=png&data={urllib.parse.quote_plus(upi_intent_url)}"

                return {
                    "ok": True,
                    "checkout_session_id": cs_id,
                    "publishable_key": pk,
                    "client_secret": client_secret,
                    "processor_entity": proc,
                    "checkout_ui_mode": data.get("checkout_ui_mode", "custom"),
                    "checkout_url": checkout_url,
                    "chatgpt_checkout_url": chatgpt_checkout_url,
                    "upi_intent_url": upi_intent_url,
                    "qr_image_url": qr_image_url,
                    "upi_qr_image_url": upi_qr_image_url,
                    "billing_country": req.country or "IN",
                    "currency": req.currency or "INR",
                }
            finally:
                s.close()

        res = await asyncio.to_thread(_do_checkout)
        elapsed = round(time.time() - t0, 2)
        res["elapsed_seconds"] = elapsed
        res["email"] = email
        res["session_token"] = session_token
        res["device_id"] = device_id
        res["coupon"] = req.coupon

        if res.get("ok"):
            log_job("Generate Checkout QR", email, "SUCCESS", result=f"Session: {res.get('checkout_session_id')[:25]}... ({elapsed}s)")
        else:
            log_job("Generate Checkout QR", email, "FAILED", error=res.get("error", "Failed"))

        return res
    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        logger.exception("Checkout session generation error")
        return {"ok": False, "error": str(e), "elapsed_seconds": elapsed}


# Mount static assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "ChatGPT 2FA Master Suite API Running"}


if __name__ == "__main__":
    import uvicorn

    import os
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8888"))
    uvicorn.run("server:app", host=host, port=port, reload=False, access_log=False, log_level="warning")
