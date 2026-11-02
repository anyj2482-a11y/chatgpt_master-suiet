"""Login header overlays — curl_cffi chrome145 (login porting guide)."""

from __future__ import annotations

from typing import Any

from change2fa.protocol.login import endpoints as ep

LOGIN_IMPERSONATE = "chrome145"
LOGIN_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
SEC_CH_UA = '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"'
SEC_CH_UA_PLATFORM = '"macOS"'
OAI_CLIENT_VERSION = "prod-e19e9dde1dc2f8240984b529c2e64925ead474f6"
OAI_CLIENT_BUILD_NUMBER = "10617742"
OAI_LANGUAGE = "en-US"


_PROFILE_KEYS = frozenset(
    {"user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}
)


def profile_overlay() -> dict[str, str]:
    return {
        "User-Agent": LOGIN_UA,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
    }


def with_profile(headers: dict[str, str]) -> dict[str, str]:
    """Guide facade: Chrome 145 UA/CH win even if caller used another case."""
    out = {k: v for k, v in headers.items() if k.lower() not in _PROFILE_KEYS}
    out.update(profile_overlay())
    return out


def identity_headers(device_id: str, session_id: str = "") -> dict[str, str]:
    headers: dict[str, str] = {}
    if device_id:
        headers["oai-device-id"] = device_id
    if session_id:
        headers["oai-session-id"] = session_id
    return headers


def browser_session_headers(device_id: str, session_id: str = "") -> dict[str, str]:
    """Session defaults — guide: UA/CH match chrome145 impersonate + proof."""
    headers = {
        "User-Agent": LOGIN_UA,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "Accept-Language": "en-US,en;q=0.9",
        "oai-language": OAI_LANGUAGE,
        "oai-device-id": device_id,
    }
    if session_id:
        headers["oai-session-id"] = session_id
    return headers


def apply_browser_session_headers(
    session: Any, device_id: str, session_id: str = ""
) -> None:
    headers = getattr(session, "headers", None)
    if headers is None:
        return
    update = getattr(headers, "update", None)
    if callable(update):
        update(browser_session_headers(device_id, session_id))


def bootstrap_nav_headers() -> dict[str, str]:
    """GET chatgpt.com/ — document navigation (ref bootstrap)."""
    return with_profile(
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
    )


def login_with_nav_headers() -> dict[str, str]:
    """GET /auth/login_with — same-origin after homepage (HAR)."""
    h = bootstrap_nav_headers()
    h["Sec-Fetch-Site"] = "same-origin"
    h["Referer"] = f"{ep.CHATGPT_BASE}/"
    return h


def authorize_nav_headers(referer: str | None = None) -> dict[str, str]:
    """GET authorize — document navigation (ref follow_authorize)."""
    return with_profile(
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1",
            "Referer": referer or f"{ep.CHATGPT_BASE}/",
        }
    )


def callback_nav_headers() -> dict[str, str]:
    """GET OAuth callback — document navigation (ref follow_callback)."""
    return with_profile(
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1",
            "Referer": "https://auth.openai.com/",
        }
    )


def auth_api_headers(
    device_id: str,
    extra: dict[str, str] | None = None,
    *,
    referer: str | None = None,
    accept: str = "application/json",
) -> dict[str, str]:
    headers = {
        "Accept": accept,
        "Content-Type": "application/json",
        "Origin": "https://auth.openai.com",
        "Referer": referer or f"{ep.AUTH_BASE}/log-in/password",
        "oai-device-id": device_id,
    }
    if extra:
        headers.update(extra)
    return with_profile(headers)


def common_json_headers(referer: str, origin: str) -> dict[str, str]:
    """XHR/CORS shape — UA/CH come from session profile."""
    return {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "origin": origin,
        "referer": referer,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }


def nextauth_headers(
    referer: str | None = None,
    *,
    device_id: str = "",
    session_id: str = "",
) -> dict[str, str]:
    """NextAuth providers/csrf/signin — Accept */*, no oai-client-*."""
    headers = common_json_headers(
        referer or f"{ep.CHATGPT_BASE}/",
        ep.CHATGPT_BASE,
    )
    headers.update(identity_headers(device_id, session_id))
    return with_profile(headers)
