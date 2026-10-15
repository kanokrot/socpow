"""Phase 4 Gmail OAuth negative/security coverage."""

from __future__ import annotations

import importlib.util
import logging
import json
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.gmail_oauth import (
    ALLOWED_SCOPES,
    GMAIL_REDIRECT_URI,
    GmailOAuthConfigurationError,
    GmailOAuthService,
    OAuthStateError,
)
from src.web.routes import gmail_settings as gmail_settings_routes
from src.web.routes.gmail_settings import router
from src.web.token_crypto import TokenCipher


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"


def _load_migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _auth_db(path: Path) -> None:
    _load_migration("001_create_users.py").migrate(str(path))
    _load_migration("002_add_username_and_admin_role.py").migrate(str(path))
    _load_migration("004_add_team_lead_role.py").migrate(str(path))
    with sqlite3.connect(path) as connection:
        connection.executemany(
            "INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)",
            [
                ("a@example.test", "user_a", "hash", "SOC Analyst Tier 1-2"),
                ("b@example.test", "user_b", "hash", "admin"),
            ],
        )
        connection.commit()


def _app(user=None):
    app = FastAPI()
    app.include_router(router, prefix="/api/settings/gmail")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _user(user_id: int = 1, role: str = "SOC Analyst Tier 1-2"):
    return {"id": user_id, "email": f"u{user_id}@example.test", "role": role}


def test_token_cipher_round_trip_and_wrong_key(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", key)
    cipher = TokenCipher.from_environment()
    encrypted = cipher.encrypt("refresh-secret")
    assert encrypted != "refresh-secret"
    assert cipher.decrypt(encrypted) == "refresh-secret"

    wrong = TokenCipher([Fernet.generate_key()])
    with pytest.raises(InvalidToken):
        wrong.decrypt(encrypted)


def test_token_cipher_fails_closed_without_key(monkeypatch):
    monkeypatch.delenv("GMAIL_TOKEN_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GMAIL_TOKEN_ENCRYPTION_KEY"):
        TokenCipher.from_environment()


def test_migration_fresh_idempotent_fk_and_unique(tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    migration = _load_migration("007_add_gmail_oauth.py")
    migration.migrate(str(db_path))
    migration.migrate(str(db_path))

    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"user_gmail_tokens", "gmail_oauth_states", "gmail_oauth_audit"} <= tables
        connection.execute(
            "INSERT INTO user_gmail_tokens "
            "(user_id, google_subject, google_email, refresh_token_ciphertext, "
            "token_key_version, granted_scopes) VALUES (?, ?, ?, ?, ?, ?)",
            (1, "sub-a", "a@gmail.com", "cipher", 1, json.dumps(sorted(ALLOWED_SCOPES))),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO user_gmail_tokens "
                "(user_id, google_subject, google_email, refresh_token_ciphertext, "
                "token_key_version, granted_scopes) VALUES (?, ?, ?, ?, ?, ?)",
                (1, "sub-b", "other@gmail.com", "cipher", 1, "[]"),
            )
        connection.execute("DELETE FROM users WHERE id = 1")
        assert connection.execute(
            "SELECT COUNT(*) FROM user_gmail_tokens WHERE user_id = 1"
        ).fetchone()[0] == 0


def test_oauth_state_expired_replayed_and_user_mismatch(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("GMAIL_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setenv("GMAIL_OAUTH_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    service = GmailOAuthService(db_path=db_path)

    state = service.create_authorization_state(1)
    with pytest.raises(OAuthStateError, match="user"):
        service.consume_authorization_state(state.raw_state, 2)
    service.consume_authorization_state(state.raw_state, 1)
    with pytest.raises(OAuthStateError, match="used"):
        service.consume_authorization_state(state.raw_state, 1)

    expired = service.create_authorization_state(1, ttl_seconds=-1)
    with pytest.raises(OAuthStateError, match="expired"):
        service.consume_authorization_state(expired.raw_state, 1)
    with pytest.raises(OAuthStateError, match="state"):
        service.consume_authorization_state("missing", 1)


def test_unauthenticated_endpoints_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    with TestClient(_app()) as client:
        assert client.get("/api/settings/gmail/connect").status_code == 401
        assert client.get("/api/settings/gmail/status").status_code == 401
        assert client.delete("/api/settings/gmail").status_code == 401


def test_connect_missing_config_redirects_and_logs_without_secrets(monkeypatch, caplog):
    class Service:
        def authorization_url(self, user_id):
            raise GmailOAuthConfigurationError("private config detail")

    monkeypatch.setattr(gmail_settings_routes, "_service", lambda: Service())
    with caplog.at_level(logging.WARNING, logger=gmail_settings_routes.__name__):
        with TestClient(_app(user=_user())) as client:
            response = client.get("/api/settings/gmail/connect", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"] == "/account?gmail=error&reason=configuration"
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert message == "Gmail OAuth start failed: configuration"
    assert "code" not in message.lower()
    assert "state" not in message.lower()
    assert "private config detail" not in message


def test_connect_unexpected_exception_redirects_to_start_failed(monkeypatch, caplog):
    class Service:
        def authorization_url(self, user_id):
            raise RuntimeError("private start detail")

    monkeypatch.setattr(gmail_settings_routes, "_service", lambda: Service())
    with caplog.at_level(logging.WARNING, logger=gmail_settings_routes.__name__):
        with TestClient(_app(user=_user())) as client:
            response = client.get("/api/settings/gmail/connect", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"] == "/account?gmail=error&reason=start_failed"
    assert len(caplog.records) == 1
    assert caplog.records[0].getMessage() == "Gmail OAuth start failed: RuntimeError"
    assert "private start detail" not in caplog.text


def test_callback_exchange_failure_redirects_and_logs_exception_type(monkeypatch, caplog):
    class Service:
        def resolve_pending_state(self, state):
            return 1

        def exchange_code(self, state, user_id, code):
            raise RuntimeError("private exchange detail")

    monkeypatch.setattr(gmail_settings_routes, "_service", lambda: Service())
    with caplog.at_level(logging.WARNING, logger=gmail_settings_routes.__name__):
        with TestClient(_app()) as client:
            response = client.get(
                "/api/settings/gmail/callback?state=state-fixture&code=code-fixture",
                follow_redirects=False,
            )

    assert response.status_code == 302
    assert response.headers["location"] == "/account?gmail=error&reason=exchange_failed"
    assert len(caplog.records) == 1
    assert caplog.records[0].getMessage() == "Gmail OAuth callback failed: RuntimeError"
    assert "private exchange detail" not in caplog.text
    assert "state-fixture" not in caplog.text
    assert "code-fixture" not in caplog.text


@pytest.mark.parametrize(
    "scenario,query,expected_location",
    [
        ("success", "&code=auth-code", "/account?gmail=success"),
        ("consent_denied", "&error=access_denied", "/account?gmail=error&reason=consent_denied"),
        ("invalid_code", "", "/account?gmail=error&reason=invalid_code"),
        ("configuration", "&code=auth-code", "/account?gmail=error&reason=configuration"),
        ("unexpected", "&code=auth-code", "/account?gmail=error&reason=exchange_failed"),
    ],
)
def test_callback_redirects_to_account_for_success_and_redirecting_failures(
    scenario, query, expected_location, monkeypatch
):
    class Service:
        def resolve_pending_state(self, state):
            assert state == "callback-state"
            return 1

        def consume_authorization_state(self, state, user_id):
            assert (state, user_id) == ("callback-state", 1)

        def exchange_code(self, state, user_id, code):
            assert (state, user_id, code) == ("callback-state", 1, "auth-code")
            if scenario == "configuration":
                raise GmailOAuthConfigurationError("missing credentials")
            if scenario == "unexpected":
                raise RuntimeError("exchange failed")

    monkeypatch.setattr(gmail_settings_routes, "_service", lambda: Service())
    with TestClient(_app()) as client:
        response = client.get(
            "/api/settings/gmail/callback?state=callback-state" + query,
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"] == expected_location


@pytest.mark.parametrize(
    "query,expected_location",
    [
        ("", "/account?gmail=error&reason=state_missing"),
        ("?state=invalid-state&code=auth-code", "/account?gmail=error&reason=state_invalid"),
    ],
)
def test_callback_redirects_to_account_for_missing_or_invalid_state(
    query, expected_location, monkeypatch
):
    class Service:
        def resolve_pending_state(self, state):
            raise OAuthStateError("invalid state")

    monkeypatch.setattr(gmail_settings_routes, "_service", lambda: Service())
    with TestClient(_app()) as client:
        response = client.get(
            "/api/settings/gmail/callback" + query,
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"] == expected_location


def test_status_never_exposes_ciphertext_and_is_owner_scoped(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    service = GmailOAuthService(db_path=db_path)
    service.save_token(
        user_id=1,
        google_subject="sub-a",
        google_email="a@gmail.com",
        refresh_token="refresh-secret",
        granted_scopes=sorted(ALLOWED_SCOPES),
    )

    with TestClient(_app(_user(1))) as client:
        response = client.get("/api/settings/gmail/status")
        assert response.status_code == 200
        body = response.json()
        assert body["linked"] is True
        assert body["google_email"] == "a@gmail.com"
        assert "refresh_token" not in response.text
        assert "ciphertext" not in response.text

    with TestClient(_app(_user(2, "admin"))) as client:
        response = client.get("/api/settings/gmail/status")
        assert response.status_code == 200
        assert response.json()["linked"] is False


def test_disconnect_is_idempotent_and_deletes_local_when_remote_revoke_fails(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    service = GmailOAuthService(db_path=db_path)
    service.save_token(1, "sub-a", "a@gmail.com", "refresh-secret", sorted(ALLOWED_SCOPES))
    monkeypatch.setattr(service, "_revoke_remote", lambda token: False)

    result = service.disconnect(1)
    assert result.remote_revoked is False
    assert service.get_status(1)["linked"] is False
    service.disconnect(1)
    with sqlite3.connect(db_path) as connection:
        events = connection.execute(
            "SELECT event FROM gmail_oauth_audit WHERE user_id = 1 ORDER BY id"
        ).fetchall()
    assert [row[0] for row in events] == ["connect", "disconnect"]


def test_connect_requests_exact_scopes_and_stores_hashed_state(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("GMAIL_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setenv("GMAIL_OAUTH_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())

    class FakeFlow:
        def __init__(self):
            self.redirect_uri = None

        def authorization_url(self, **kwargs):
            return "https://accounts.google.test/auth?state=" + kwargs["state"], kwargs["state"]

    monkeypatch.setattr("src.web.gmail_oauth.Flow.from_client_config", lambda *a, **k: FakeFlow())
    service = GmailOAuthService(db_path=db_path)
    url, raw_state = service.authorization_url(1)
    assert GMAIL_REDIRECT_URI in service.get_state_redirect_uri(raw_state, 1)
    assert set(service.requested_scopes) == set(ALLOWED_SCOPES)
    assert "gmail.readonly" not in url
    with sqlite3.connect(db_path) as connection:
        row = connection.execute("SELECT state_hash FROM gmail_oauth_states").fetchone()
    assert row is not None and raw_state not in row[0]
