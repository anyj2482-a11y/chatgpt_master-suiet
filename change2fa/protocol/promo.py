"""ChatGPT Promotional Campaigns & Offer Auditor Protocol.

Audits account entitlements and checks promotional coupon eligibility.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from change2fa.protocol.http_session import create_session
from change2fa.protocol.login.endpoints import URL_ENTITLEMENT
from change2fa.protocol.login.flow import run_login

log = logging.getLogger(__name__)

KNOWN_COUPONS = [
    ("plus-1-month-free", "ChatGPT Plus 1 Month Free Trial"),
    ("chatgpt-plus-trial", "Plus Special Promotional Trial"),
    ("welcome-plus", "New User Welcome Plus Offer"),
    ("student-plus", "Student Campus Plus Discount"),
]


def check_promo_eligibility_with_token(
    access_token: str,
    device_id: str | None = None,
    proxy_url: str | None = None,
    custom_coupon: str | None = None,
) -> dict[str, Any]:
    """Query OpenAI promo campaign endpoints using an active access token."""
    s = create_session(proxy_url=proxy_url, impersonate="chrome131")
    try:
        headers = {
            "Authorization": f"Bearer {access_token.strip()}",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Origin": "https://chatgpt.com",
            "Referer": "https://chatgpt.com/",
        }
        if device_id:
            headers["oai-device-id"] = device_id

        # 1. Check account entitlements
        entitlements_data = {}
        plan_type = "free"
        is_trial = False
        trial_state = None

        try:
            r_ent = s.get(URL_ENTITLEMENT, headers=headers, timeout=15)
            if r_ent.status_code == 200:
                ent_json = r_ent.json() or {}
                accounts = ent_json.get("accounts") or {}
                if accounts:
                    # Pick first account
                    first_acc = next(iter(accounts.values()), {})
                    acc_info = first_acc.get("account") or {}
                    is_trial = acc_info.get("is_trial", False)
                    trial_state = acc_info.get("trial_state")
                    entitlements_data = acc_info
        except Exception as e:
            log.warning("Entitlements check failed: %s", e)

        # 2. Check coupons list
        coupons_to_check = list(KNOWN_COUPONS)
        if custom_coupon and custom_coupon.strip():
            c_clean = custom_coupon.strip()
            if not any(c[0] == c_clean for c in coupons_to_check):
                coupons_to_check.insert(0, (c_clean, f"Custom Coupon ({c_clean})"))

        coupon_results = []
        has_eligible = False
        best_coupon = None

        for coupon_id, desc in coupons_to_check:
            url = f"https://chatgpt.com/backend-api/promo_campaign/check_coupon?coupon={coupon_id}&is_coupon_from_query_param=true"
            try:
                r_c = s.get(url, headers=headers, timeout=12)
                if r_c.status_code == 200:
                    c_data = r_c.json() or {}
                    state = c_data.get("state") or "unknown"
                    redemption = c_data.get("redemption") or {}
                    promo_days = redemption.get("promotion_length_days")

                    is_elig = state in ("eligible", "active")
                    if is_elig:
                        has_eligible = True
                        if not best_coupon:
                            best_coupon = coupon_id

                    coupon_results.append({
                        "coupon": coupon_id,
                        "description": desc,
                        "state": state,
                        "eligible": is_elig,
                        "promotion_days": promo_days,
                        "claim_url": f"https://chatgpt.com/?promo_campaign={coupon_id}#pricing" if is_elig else None,
                    })
                elif r_c.status_code == 404:
                    coupon_results.append({
                        "coupon": coupon_id,
                        "description": desc,
                        "state": "offline",
                        "eligible": False,
                        "promotion_days": None,
                        "claim_url": None,
                    })
                else:
                    coupon_results.append({
                        "coupon": coupon_id,
                        "description": desc,
                        "state": f"error_{r_c.status_code}",
                        "eligible": False,
                        "promotion_days": None,
                        "claim_url": None,
                    })
            except Exception as e:
                coupon_results.append({
                    "coupon": coupon_id,
                    "description": desc,
                    "state": "network_error",
                    "eligible": False,
                    "error": str(e),
                })

        return {
            "ok": True,
            "is_trial": is_trial,
            "trial_state": trial_state,
            "entitlements": entitlements_data,
            "coupons": coupon_results,
            "has_eligible_offers": has_eligible,
            "best_coupon": best_coupon,
            "claim_url": f"https://chatgpt.com/?promo_campaign={best_coupon}#pricing" if best_coupon else "https://chatgpt.com/#pricing",
        }
    finally:
        s.close()
