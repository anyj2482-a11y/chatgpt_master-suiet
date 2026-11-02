"""Job history must only ever be visible to the owner who created the jobs.

Every history endpoint is scoped by a signed owner token; without a valid
token the history stays empty and mutating endpoints are refused.
"""
import base64
import hashlib
import hmac
import os

os.environ["HISTORY_TOKEN_SECRET"] = "unit-test-secret"

import sqlite3

import pytest
from fastapi.testclient import TestClient

import server  # noqa: E402  (imports set env-dependent config)


def mint(owner: str, secret: str = "unit-test-secret") -> str:
    uid_b64 = base64.urlsafe_b64encode(owner.encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), uid_b64.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{uid_b64}.{sig}"


@pytest.fixture()
def client():
    # Each test starts from an empty history table.
    with sqlite3.connect(server.DB_PATH) as conn:
        conn.execute("DELETE FROM jobs")
    with TestClient(server.app) as c:
        yield c


def test_history_locked_without_token(client):
    resp = client.get("/api/history")
    assert resp.status_code == 200
    body = resp.json()
    assert body["authorized"] is False
    assert body["jobs"] == []
    assert body["stats"]["total"] == 0


def test_jobs_are_scoped_to_their_owner(client):
    # Running a job with owner A records it under A (a failed run still logs).
    resp = client.post("/api/session/setup", json={"session_data": ""}, headers={"x-user-token": mint("user-a")})
    assert resp.status_code == 400  # invalid input, but the attempt is logged

    mine = client.get("/api/history", headers={"x-user-token": mint("user-a")}).json()
    assert mine["stats"]["total"] == 1
    assert all(j["owner"] == "user-a" for j in mine["jobs"])

    other = client.get("/api/history", headers={"x-user-token": mint("user-b")}).json()
    assert other["stats"]["total"] == 0
    assert other["jobs"] == []


def test_forged_or_garbage_tokens_see_nothing(client):
    body = client.get("/api/history", headers={"x-user-token": "abc.def"}).json()
    assert body["jobs"] == []
    body = client.get("/api/history", params={"u": mint("user-a", secret="wrong-secret")}).json()
    assert body["jobs"] == []


def test_export_and_clear_require_owner(client):
    assert client.get("/api/history/export").status_code == 401
    assert client.post("/api/history/clear").status_code == 401

    # Owner B cannot see owner A's rows: their export is empty and their
    # clear does not touch A's data.
    client.post("/api/session/setup", json={"session_data": ""}, headers={"x-user-token": mint("user-a")})
    assert client.get("/api/history/export", headers={"x-user-token": mint("user-b")}).text == ""
    client.post("/api/history/clear", headers={"x-user-token": mint("user-b")})
    assert client.get("/api/history", headers={"x-user-token": mint("user-a")}).json()["stats"]["total"] == 1

    # Owner A can export their own rows and clear only their own.
    export = client.get("/api/history/export", headers={"x-user-token": mint("user-a")})
    assert export.status_code == 200
    client.post("/api/history/clear", headers={"x-user-token": mint("user-a")})
    assert client.get("/api/history", headers={"x-user-token": mint("user-a")}).json()["stats"]["total"] == 0
