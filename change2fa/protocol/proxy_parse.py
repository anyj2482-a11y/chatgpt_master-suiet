"""Parse proxy bulk lines."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


@dataclass
class ParsedProxy:
    host: str
    port: int
    username: str | None = None
    password: str | None = None
    base_session_template: str = ""


def normalize_proxy_url(proxy_url: str | None) -> str | None:
    """Normalize proxy URL for curl_cffi / httpx → HTTPS origins.

    Supports:
    - http://user:pass@host:port
    - socks5://user:pass@host:port
    - host:port:user:pass (seller format)
    - host:port
    """
    if proxy_url is None:
        return None
    raw = proxy_url.strip()
    if not raw:
        return None

    # Handle colon format: host:port:user:pass or host:port
    if "://" not in raw:
        parts = raw.split(":")
        if len(parts) >= 4:
            try:
                p = parse_proxy_line(raw)
                return to_url(p)
            except Exception:
                pass
        raw = f"http://{raw}"

    try:
        p = urlparse(raw)
    except Exception:
        return raw
    scheme = (p.scheme or "http").lower()
    if scheme == "https":
        return urlunparse(
            ("http", p.netloc, p.path, p.params, p.query, p.fragment)
        )
    return raw


def parse_proxy_line(line: str) -> ParsedProxy:
    raw = line.strip()
    if not raw:
        raise ValueError("empty")

    if "://" in raw:
        u = urlparse(raw)
        if not u.hostname or not u.port:
            raise ValueError(f"bad url: {raw}")
        return ParsedProxy(
            host=u.hostname,
            port=u.port,
            username=u.username,
            password=u.password,
        )

    # host:port:user:pass
    parts = raw.split(":")
    if len(parts) == 2:
        return ParsedProxy(host=parts[0], port=int(parts[1]))
    if len(parts) >= 4:
        host, port, user = parts[0], int(parts[1]), parts[2]
        password = ":".join(parts[3:])
        tmpl = ""
        if "{SID}" in user or "{sid}" in user:
            tmpl = user
        return ParsedProxy(
            host=host, port=port, username=user, password=password, base_session_template=tmpl
        )
    raise ValueError(f"unrecognized proxy format: {raw}")


def proxy_endpoint_hint(proxy_url: str | None) -> str:
    """Host:port (no credentials) for job logs."""
    raw = normalize_proxy_url(proxy_url)
    if not raw:
        return "-"
    try:
        p = urlparse(raw)
    except Exception:
        return "-"
    host = p.hostname or "?"
    port = f":{p.port}" if p.port else ""
    return f"{(p.scheme or 'http').lower()}://{host}{port}"


def to_url(p: ParsedProxy, scheme: str = "http") -> str:
    auth = ""
    if p.username:
        from urllib.parse import quote

        user = quote(p.username, safe="")
        pw = quote(p.password or "", safe="")
        auth = f"{user}:{pw}@"
    return f"{scheme}://{auth}{p.host}:{p.port}"
