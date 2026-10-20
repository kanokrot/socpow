from __future__ import annotations

from contextlib import nullcontext

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from src.web import auth as auth_core
from src.web.routes import auth as auth_routes
from src.web.security import LoginRateLimiter, api_key_rate_limiter, login_rate_limiter


def _auth_app() -> FastAPI:
    app = FastAPI()
    app.include_router(auth_routes.router, prefix="/api/auth")
    return app


def test_login_rate_limiter_is_keyed_by_identifier_and_ip() -> None:
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=60, clock=lambda: 100)

    assert not limiter.is_limited("Alice", "192.0.2.10")
    limiter.record_failure("Alice", "192.0.2.10")
    limiter.record_failure("alice", "192.0.2.10")
    assert limiter.is_limited("ALICE", "192.0.2.10")
    assert not limiter.is_limited("alice", "192.0.2.11")
    assert not limiter.is_limited("bob", "192.0.2.10")


def test_login_rate_limiter_expires_attempts() -> None:
    now = [100.0]
    limiter = LoginRateLimiter(max_attempts=1, window_seconds=60, clock=lambda: now[0])

    limiter.record_failure("alice", "192.0.2.10")
    assert limiter.is_limited("alice", "192.0.2.10")
    now[0] = 161.0
    assert not limiter.is_limited("alice", "192.0.2.10")


def test_api_key_limiter_is_separate_from_login_limiter() -> None:
    api_key_rate_limiter.clear("keyprefix", "192.0.2.10")
    login_rate_limiter.clear("keyprefix", "192.0.2.10")
    api_key_rate_limiter.record_failure("keyprefix", "192.0.2.10")

    assert api_key_rate_limiter.is_limited("keyprefix", "192.0.2.10") is False
    assert login_rate_limiter.is_limited("keyprefix", "192.0.2.10") is False
    api_key_rate_limiter.clear("keyprefix", "192.0.2.10")


def test_failed_login_is_rate_limited_and_success_sets_strict_cookies(monkeypatch) -> None:
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=60)
    monkeypatch.setattr(auth_routes, "login_rate_limiter", limiter)
    monkeypatch.setattr(auth_routes, "authenticate_user", lambda identifier, password: None)

    with TestClient(_auth_app()) as client:
        assert client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "wrong"},
        ).status_code == 401
        assert client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "wrong"},
        ).status_code == 401
        blocked = client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert blocked.status_code == 429
        assert blocked.headers["retry-after"]

    monkeypatch.setattr(
        auth_routes,
        "authenticate_user",
        lambda identifier, password: {
            "id": 1,
            "email": "alice@example.test",
            "username": "alice",
            "role": "admin",
            "is_active": 1,
        },
    )
    monkeypatch.setattr(auth_routes, "create_access_token", lambda user: "token")
    limiter.clear("alice", "testclient")

    with TestClient(_auth_app()) as client:
        response = client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "correct"},
        )

    assert response.json()["authenticated"] is True
    assert "access_token" not in response.json()
    assert "token_type" not in response.json()
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(cookie for cookie in cookies if cookie.startswith("socpow_session="))
    csrf_cookie = next(cookie for cookie in cookies if cookie.startswith("socpow_csrf="))
    assert "SameSite=strict" in session_cookie
    assert "SameSite=strict" in csrf_cookie
    assert "HttpOnly" in session_cookie
    assert "HttpOnly" not in csrf_cookie


def test_cookie_authenticated_unsafe_request_requires_csrf_header(monkeypatch) -> None:
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=60)
    monkeypatch.setattr(auth_routes, "login_rate_limiter", limiter)
    monkeypatch.setattr(
        auth_routes,
        "authenticate_user",
        lambda identifier, password: {
            "id": 1,
            "email": "alice@example.test",
            "username": "alice",
            "role": "admin",
            "is_active": 1,
        },
    )
    monkeypatch.setattr(auth_routes, "create_access_token", lambda user: "token")
    monkeypatch.setattr(auth_core, "_decode_jwt", lambda token: {"sub": "1", "jti": "jti"})

    class FakeResult:
        def __init__(self, row):
            self.row = row

        def fetchone(self):
            return self.row

    class FakeConnection:
        def execute(self, query, params):
            if "auth_sessions" in query:
                return FakeResult({"expires_at": 4_000_000_000, "revoked_at": None})
            return FakeResult(
                {
                    "id": 1,
                    "email": "alice@example.test",
                    "username": "alice",
                    "role": "admin",
                    "is_active": 1,
                }
            )

    monkeypatch.setattr(auth_core, "_connect", lambda: nullcontext(FakeConnection()))

    app = _auth_app()

    @app.post("/protected")
    def protected(current_user: dict = Depends(auth_core.get_current_user)):
        return {"username": current_user["username"]}

    with TestClient(app) as client:
        login_response = client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "correct"},
        )
        assert login_response.status_code == 200
        assert client.post("/protected").status_code == 403

        csrf_token = client.cookies.get("socpow_csrf")
        protected_response = client.post(
            "/protected",
            headers={"X-CSRF-Token": csrf_token},
        )

    assert protected_response.status_code == 200
    assert protected_response.json() == {"username": "alice"}
