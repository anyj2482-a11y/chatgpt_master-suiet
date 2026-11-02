# ChatGPT 2FA Master Suite (Professional Edition)

A modern, full-featured local dashboard for managing, auditing, and maintaining ChatGPT Multi-Factor Authentication (TOTP), browser sessions, account credentials, and entitlement checks.

---

## 🚀 Key Features (9-in-1 Operations Dashboard)

### 1. ✨ Setup 2FA from Active Session
* Enroll and activate fresh Two-Factor Authentication (TOTP) directly using an active browser session.
* Accepts raw JWT access tokens or full session JSON from `https://chatgpt.com/api/auth/session`.
* Generates a secure TOTP secret key and scannable authenticator QR code.

### 2. ⚡ Fast Login & Browser Launch
* Authenticate accounts using credentials (`email|password|2fa`) or active session tokens.
* Instantly injects authentication cookies and launches a dedicated, authenticated Chrome browser window.

### 3. 🔄 Change Credentials & Rotate 2FA
* Authenticates existing accounts using `email|password|current_2fa`.
* Disables the old factor, provisions a new TOTP secret, and re-verifies authentication in an automated pipeline.
* **Bulk Runner**: Multi-threaded batch processor with concurrency control (1–5 workers), custom delays, and retry exports.

### 4. 🛡️ Rotate 2FA via Active Session
* For accounts with an active browser session where the old 2FA secret is inaccessible.
* Rebinds authentication factors and generates fresh credentials directly from the active session.

### 5. ⏱️ Live OTP Authenticator
* Real-time TOTP generation for any standard base32 secret.
* Dynamic 30-second progress bar, click-to-copy code display, and integrated QR code generator.

### 6. 🚫 Clear All Sessions
* Invalidate and revoke all active login sessions globally across devices.
* Available in both single-account mode and bulk batch processing mode.

### 7. 🔑 Rotate & Reset Password
* Two-step password reset workflow utilizing official email OTP verification codes.
* Generates secure randomized passwords, applies updates, and verifies login immediately.

### 8. 🎁 Promotional Offers & Entitlements
* Audit accounts against official promotional campaign codes (e.g., `plus-1-month-free`, referral vouchers).
* Displays subscription plan states (`FREE`, `PLUS`) and eligibility results.
* Available in single-account audit and high-throughput bulk scanner modes.

### 9. 📜 Operation History
* Centralized audit log tracking recent operations, timestamps, status badges, and output lines.

---

## 📋 Input Formats

The suite flexibly accepts multiple standard input formats across single and bulk modes:

| Format | Example |
| :--- | :--- |
| **Pipeline Line** | `user@example.com\|Password123\|JBSWY3DPEHPK3PXP` |
| **Pipeline Line with Proxy** | `user@example.com\|Password123\|JBSWY3DPEHPK3PXP\|http://user:pass@ip:port` |
| **Session JSON** | Raw payload copied from `https://chatgpt.com/api/auth/session` |
| **Access Token** | Raw JWT string starting with `eyJhbGciOi...` |

---

## 🛠️ Prerequisites & Installation

1. **Python 3.10+** installed on your system.
2. Install the required Python packages:

```bash
pip install fastapi uvicorn curl_cffi pyotp qrcode pydantic
```

---

## 💻 How to Run

### Quick Start (Windows)
Double-click `run.bat` in the project root directory.

### Command Line
```bash
cd "C:\Users\anuj1\Documents\ChatGPT-2FA-Master"
python server.py
```

Once started, open your browser and navigate to:
**http://127.0.0.1:8888**

---

## 📁 Project Structure

```
ChatGPT-2FA-Master/
├── server.py              # FastAPI backend handling 2FA, auth, sessions & promo endpoints
├── static/
│   └── index.html         # Unified single-page responsive dashboard UI
├── run.bat                # Windows 1-click startup script
└── README.md              # Project documentation
```
