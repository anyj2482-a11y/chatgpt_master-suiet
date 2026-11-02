"""Local server entry. Binds to this machine only."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from change2fa.api import ROOT, create_app


def data_dir() -> Path:
    raw = (os.environ.get("CHANGE2FA_DATA") or "").strip()
    path = Path(raw) if raw else ROOT / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


app = create_app(data_dir() / "app.db")


def run() -> None:
    port = int(os.environ.get("CHANGE2FA_PORT") or "19429")
    uvicorn.run(app, host="127.0.0.1", port=port)
