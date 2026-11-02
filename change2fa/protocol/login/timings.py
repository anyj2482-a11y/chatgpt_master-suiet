"""Check GPT hop budget — fail-fast dead proxy, no stacked GET retries.

API/probe hops share ``HOP``. POSTs are one-shot. Bootstrap is the same
short budget as ``warm_cf`` (document CF 403 is not fatal). Session-token
cookie is optional; do not stack callback consumes on this budget.
"""

from __future__ import annotations

# curl_cffi: timeout is float seconds or (connect, read).
CONNECT_S = 12.0
READ_S = 15.0
HOP = (CONNECT_S, READ_S)

GET_ATTEMPTS = 1
RETRY_BACKOFF_S = 0.5

# Dead proxy: one GET, then rotate. Do not 20s×2 URLs on bootstrap.
# ponytail: 4/8 fail-fast; raise if live residential connect >4s.
BOOTSTRAP_CONNECT_S = 4.0
BOOTSTRAP_READ_S = 8.0
BOOTSTRAP_TIMEOUT = (BOOTSTRAP_CONNECT_S, BOOTSTRAP_READ_S)
BOOTSTRAP_HTTP_ATTEMPTS = 1

WARM_CF = BOOTSTRAP_TIMEOUT
AUTHORIZE_DEADLINE_S = 20.0
# create_session wraps float as (factory connect, this read).
SESSION_DEFAULT = 20.0
