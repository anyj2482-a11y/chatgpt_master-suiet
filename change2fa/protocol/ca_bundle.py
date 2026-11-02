"""CA file for curl_cffi (BoringSSL).

Homebrew Python's default CA is ``/opt/homebrew/etc/openssl@3/cert.pem``.
curl_cffi loads that path and curl 77s (``error adding trust anchors``)
when the file is missing, unreadable, or rejected. Every Codex login then
fails at the same step. Use the certifi bundle we already ship. An explicit
``SSL_CERT_FILE`` / ``CURL_CA_BUNDLE`` / ``REQUESTS_CA_BUNDLE`` still wins
when that file exists and is non-empty.
"""

from __future__ import annotations

import os

import certifi

_ENV_KEYS = ("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE")


def curl_ca_bundle() -> str:
    for key in _ENV_KEYS:
        path = (os.environ.get(key) or "").strip()
        if path and os.path.isfile(path) and os.path.getsize(path) > 0:
            return path
    return certifi.where()
