"""Pure-Python sentinel PoW (rust sentinel/pow.rs) for login headers."""

from __future__ import annotations

import base64
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from change2fa.protocol.login.headers import LOGIN_UA, SEC_CH_UA, SEC_CH_UA_PLATFORM
from change2fa.protocol.login.timings import HOP

log = logging.getLogger(__name__)

SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
SENTINEL_REFERER = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
SENTINEL_SDK_URL = "https://sentinel.openai.com/sentinel/20260810913b/sdk.js"
# Checkout mint host (HAR 2026-08-26) — not sentinel.openai.com.
CHECKOUT_SENTINEL_REQ_URL = "https://chatgpt.com/backend-api/sentinel/req"
CHECKOUT_SENTINEL_ORIGIN = "https://chatgpt.com"
CHECKOUT_SENTINEL_REFERER = (
    "https://chatgpt.com/backend-api/sentinel/frame.html?sv=20260810913b"
)
FLOW_CHATGPT_CHECKOUT = "chatgpt_checkout"
ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
MAX_ATTEMPTS = 500_000
SENTINEL_MAX_BODY = 1_048_576

FNV_OFFSET = 2_166_136_261
FNV_PRIME = 16_777_619
MIX1 = 2_246_822_507
MIX2 = 3_266_489_909

NAV_PROPS = [
    "vendorSub", "productSub", "vendor", "maxTouchPoints", "scheduling",
    "userActivation", "doNotTrack", "geolocation", "connection", "plugins",
    "mimeTypes", "pdfViewerEnabled", "webkitTemporaryStorage",
    "webkitPersistentStorage", "hardwareConcurrency", "cookieEnabled",
    "credentials", "mediaDevices", "permissions", "locks", "ink",
]
DOC_FIELDS = ["location", "implementation", "URL", "documentURI", "compatMode"]
GLOBAL_FIELDS = ["Object", "Function", "Array", "Number", "parseFloat", "undefined"]
HW = [4, 8, 12, 16]


def fnv1a_32(text: str) -> str:
    """UTF-8 byte FNV — register OS pin. Login PoW uses fnv_mixed."""
    h = FNV_OFFSET
    for b in text.encode("utf-8"):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return _fnv_avalanche(h)


def fnv_mixed(text: str) -> str:
    """Guide Sentinel proof: XOR Unicode code points, then avalanche."""
    h = FNV_OFFSET
    for ch in text:
        h = ((h ^ ord(ch)) * FNV_PRIME) & 0xFFFFFFFF
    return _fnv_avalanche(h)


def _fnv_avalanche(h: int) -> str:
    h ^= h >> 16
    h = (h * MIX1) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * MIX2) & 0xFFFFFFFF
    h ^= h >> 16
    return f"{h:08x}"


def _b64_json(value: Any) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.b64encode(raw).decode("ascii")


def _format_date_utc() -> str:
    now = datetime.now(UTC)
    return now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")


def build_config(user_agent: str) -> list[Any]:
    """19-field fingerprint — login porting guide §6.2."""
    perf_now = random.uniform(1000.0, 50_000.0)
    time_origin = time.time() * 1000.0 - perf_now
    return [
        "1920x1080",
        _format_date_utc(),
        4_294_705_152,
        0,
        user_agent,
        SENTINEL_SDK_URL,
        None,
        None,
        "en-US",
        0,
        random.random(),
        f"{random.choice(NAV_PROPS)}\u2212undefined",
        random.choice(DOC_FIELDS),
        random.choice(GLOBAL_FIELDS),
        perf_now,
        str(uuid.uuid4()),
        "",
        random.choice(HW),
        time_origin,
    ]


def generate_requirements_token(user_agent: str) -> str:
    cfg = build_config(user_agent)
    cfg[3] = 1
    cfg[9] = random.randint(5, 50)
    return "gAAAAAC" + _b64_json(cfg)


def solve_pow(seed: str, difficulty: str, user_agent: str, max_attempts: int = MAX_ATTEMPTS) -> str:
    cfg = build_config(user_agent)
    started = time.perf_counter()
    diff_len = len(difficulty)
    for nonce in range(max_attempts):
        cfg[3] = nonce
        cfg[9] = int((time.perf_counter() - started) * 1000)
        encoded = _b64_json(cfg)
        digest = fnv_mixed(seed + encoded)
        if diff_len == 0 or (len(digest) >= diff_len and digest[:diff_len] <= difficulty):
            return f"gAAAAAB{encoded}~S"
    null_b64 = _b64_json("None")
    return f"gAAAAAB{ERROR_PREFIX}{null_b64}"


def build_token(p: str, t: str, c: str, device_id: str, flow: str) -> str:
    return json.dumps(
        {"p": p, "t": t, "c": c, "id": device_id, "flow": flow},
        separators=(",", ":"),
    )


@dataclass(frozen=True)
class SentinelReqTarget:
    req_url: str
    origin: str
    referer: str


AUTH_SENTINEL_REQ = SentinelReqTarget(
    SENTINEL_REQ_URL,
    "https://sentinel.openai.com",
    SENTINEL_REFERER,
)
CHECKOUT_SENTINEL_REQ = SentinelReqTarget(
    CHECKOUT_SENTINEL_REQ_URL,
    CHECKOUT_SENTINEL_ORIGIN,
    CHECKOUT_SENTINEL_REFERER,
)


@dataclass
class Challenge:
    seed: str
    difficulty: str
    token: str
    pow_required: bool


def _response_bytes(resp: Any) -> bytes | None:
    raw = getattr(resp, "content", None)
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
    else:
        text = getattr(resp, "text", None)
        if not isinstance(text, str):
            return b""
        data = text.encode("utf-8", "replace")
    if len(data) > SENTINEL_MAX_BODY:
        return None
    return data


def fetch_challenge(
    session: Any,
    device_id: str,
    flow: str,
    request_p: str,
    user_agent: str,
    target: SentinelReqTarget | None = None,
) -> Challenge | None:
    body = json.dumps({"p": request_p, "id": device_id, "flow": flow}, separators=(",", ":"))
    req = target or AUTH_SENTINEL_REQ
    r = None
    try:
        r = session.post(
            req.req_url,
            headers={
                "content-type": "text/plain;charset=UTF-8",
                "accept": "*/*",
                "origin": req.origin,
                "referer": req.referer,
                "User-Agent": user_agent or LOGIN_UA,
                "sec-ch-ua": SEC_CH_UA,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            },
            data=body,
            timeout=HOP,
        )
        if r.status_code >= 400:
            log.info("sentinel_http_%s flow=%s", r.status_code, flow)
            return None
        raw = _response_bytes(r)
        if raw is None:
            log.info("sentinel_response_too_large flow=%s", flow)
            return None
        if raw:
            data = json.loads(raw.decode("utf-8"))
        else:
            data = r.json() or {}
        if not isinstance(data, dict):
            return None
        turnstile = data.get("turnstile") or {}
        if isinstance(turnstile, dict) and turnstile.get("required"):
            log.info("sentinel_turnstile_required flow=%s", flow)
        pow_ = data.get("proofofwork") or {}
        return Challenge(
            seed=str(pow_.get("seed") or ""),
            difficulty=str(pow_.get("difficulty") or "0"),
            token=str(data.get("token") or ""),
            pow_required=bool(pow_.get("required")),
        )
    except Exception as e:
        log.debug("sentinel challenge fail: %s", e)
        return None
    finally:
        close = getattr(r, "close", None) if r is not None else None
        if callable(close):
            try:
                close()
            except Exception:
                pass


def get_sentinel_token_pow(
    session: Any,
    device_id: str,
    flow: str,
    user_agent: str,
    target: SentinelReqTarget | None = None,
) -> str:
    """End-to-end PoW token for openai-sentinel-token header."""
    did = device_id or str(uuid.uuid4())
    request_p = generate_requirements_token(user_agent)
    ch = fetch_challenge(session, did, flow, request_p, user_agent, target=target)
    if not ch or not (ch.token or "").strip():
        return ""
    if ch.pow_required and ch.seed:
        p_val = solve_pow(ch.seed, ch.difficulty, user_agent)
    else:
        p_val = request_p
    return build_token(p_val, "", ch.token, did, flow)


def get_checkout_sentinel_token(
    session: Any,
    device_id: str,
    user_agent: str = LOGIN_UA,
) -> str:
    """Mint flow=chatgpt_checkout on chatgpt.com (rust CHECKOUT_SENTINEL_REQ)."""
    return get_sentinel_token_pow(
        session,
        device_id,
        FLOW_CHATGPT_CHECKOUT,
        user_agent,
        target=CHECKOUT_SENTINEL_REQ,
    )
