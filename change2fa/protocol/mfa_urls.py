"""ChatGPT MFA endpoints used after a full login."""

from __future__ import annotations

CHATGPT_BASE = "https://chatgpt.com"
MFA_INFO = f"{CHATGPT_BASE}/backend-api/accounts/mfa_info"
MFA_ENROLL = f"{CHATGPT_BASE}/backend-api/accounts/mfa/enroll"
MFA_ACTIVATE = f"{CHATGPT_BASE}/backend-api/accounts/mfa/user/activate_enrollment"
MFA_DISABLE = f"{CHATGPT_BASE}/backend-api/accounts/mfa/user/disable_in_house"
