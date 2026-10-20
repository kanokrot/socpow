from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src.web import auth as auth_core
from src.web.auth import API_KEY_SCOPE, get_current_user, require_role
from src.web.routes import admin as admin_routes
from src.web.routes import auth as auth_routes
from src.web.routes import playbooks as playbook_routes
from src.web.security import api_key_rate_limiter, login_rate_limiter
from src.web import websocket as websocket_routes


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"


def _migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _app(monkeypatch, tmp_path: Path) -> tuple[FastAPI, dict[str, int]]:
    db_path = tmp_path / "auth.db"
    for filename in (
        "001_create_users.py",
        "002_add_username_and_admin_role.py",
        "013_create_api_keys.py",
    ):
        _migration(filename).migrate(str(db_path))
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("AUTH_JWT_SECRET", "api-key-auth-test-secret")
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO users (email, username, password_hash, role, is_active) "
            "VALUES ('admin@example.test', 'admin', 'unused', 'admin', 1)"
        )
        connection.execute(
            "INSERT INTO users (email, username, password_hash, role, is_active) "
            "VALUES ('ir@example.test', 'ir', 'unused', 'Incident Responder', 1)"
        )
        connection.execute(
            "INSERT INTO users (email, username, password_hash, role, is_active) "
            "VALUES ('analyst@example.test', 'analyst', 'unused', 'SOC Analyst Tier 1-2', 1)"
        )
        connection.commit()

    app = FastAPI()
    audit_entries = []
    app.state.agent_store = SimpleNamespace(
        add_audit_entry=lambda **kwargs: audit_entries.append(kwargs)
    )
    app.state.api_key_audit_entries = audit_entries
    app.state.playbook_engine = SimpleNamespace(start=AsyncMock(return_value="session-1"))
    app.include_router(admin_routes.router, prefix="/api/admin")
    app.include_router(playbook_routes.router, prefix="/api/playbooks")
    app.include_router(auth_routes.router, prefix="/api/auth")

    @app.get("/api/playbooks/alert_triage/run")
    def wrong_method(_user: dict = Depends(get_current_user)):
        return {}

    @app.get("/api/chat/test")
    def chat(_user: dict = Depends(get_current_user)):
        return {}

    @app.get("/api/agent/test")
    def agent(_user: dict = Depends(get_current_user)):
        return {}

    return app, {"admin": 1, "ir": 2, "analyst": 3}


def _token(user_id: int, email: str, username: str, role: str) -> str:
    return auth_core.create_access_token(
        {"id": user_id, "email": email, "username": username, "role": role}
    )


def _create_key(client: TestClient, user_id: int, admin_token: str) -> tuple[str, int]:
    response = client.post(
        f"/api/admin/users/{user_id}/api-keys",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={},
    )
    assert response.status_code == 201, response.text
    return response.json()["key"], response.json()["id"]


def test_api_key_is_scoped_to_alert_triage_and_preserves_owner_role(monkeypatch, tmp_path):
    app, ids = _app(monkeypatch, tmp_path)
    admin_token = _token(ids["admin"], "admin@example.test", "admin", "admin")
    with TestClient(app) as client:
        key, _key_id = _create_key(client, ids["ir"], admin_token)
        response = client.post(
            "/api/playbooks/alert_triage/run",
            headers={"X-API-Key": key},
            json={"params": {"alert_id": "a-1"}},
        )
        assert response.status_code == 200, response.text
        assert response.json() == {"session_id": "session-1", "status": "running"}
        call = app.state.playbook_engine.start.call_args
        assert call.kwargs["user_id"] == ids["ir"]
        assert call.kwargs["role"] == "Incident Responder"
        with sqlite3.connect(tmp_path / "auth.db") as connection:
            last_used = connection.execute(
                "SELECT last_used_at FROM api_keys WHERE id = ?", (_key_id,)
            ).fetchone()[0]
        assert last_used is not None

        assert client.post(
            "/api/playbooks/another/run", headers={"X-API-Key": key}, json={}
        ).status_code == 403
        assert client.get(
            "/api/playbooks/alert_triage/run", headers={"X-API-Key": key}
        ).status_code == 403
        assert client.get("/api/chat/test", headers={"X-API-Key": key}).status_code == 403
        assert client.get("/api/agent/test", headers={"X-API-Key": key}).status_code == 403


@pytest.mark.parametrize("failure", ["expired", "revoked", "wrong_secret", "inactive"])
def test_invalid_api_keys_return_401(monkeypatch, tmp_path, failure):
    app, ids = _app(monkeypatch, tmp_path)
    admin_token = _token(ids["admin"], "admin@example.test", "admin", "admin")
    with TestClient(app) as client:
        created = client.post(
            f"/api/admin/users/{ids['ir']}/api-keys",
            headers={"Authorization": f"Bearer {admin_token}"}, json={},
        )
        assert created.status_code == 201
        key, key_id = created.json()["key"], created.json()["id"]
        with sqlite3.connect(tmp_path / "auth.db") as connection:
            if failure == "expired":
                connection.execute("UPDATE api_keys SET expires_at = 1 WHERE id = ?", (key_id,))
            elif failure == "revoked":
                connection.execute("UPDATE api_keys SET revoked_at = 1 WHERE id = ?", (key_id,))
            elif failure == "inactive":
                connection.execute("UPDATE users SET is_active = 0 WHERE id = ?", (ids["ir"],))
            connection.commit()
        bad_key = key
        if failure == "wrong_secret":
            bad_key = key[:-1] + ("A" if key[-1] != "A" else "B")
        response = client.post(
            "/api/playbooks/alert_triage/run", headers={"X-API-Key": bad_key}, json={}
        )
        assert response.status_code == 401
        if failure == "wrong_secret":
            assert not login_rate_limiter.is_limited("8", "testclient")


def test_key_credential_ambiguity_and_keyless_context_rejected(monkeypatch, tmp_path):
    app, ids = _app(monkeypatch, tmp_path)
    admin_token = _token(ids["admin"], "admin@example.test", "admin", "admin")
    with TestClient(app) as client:
        key, _ = _create_key(client, ids["ir"], admin_token)
        assert client.post(
            "/api/playbooks/alert_triage/run",
            headers={"X-API-Key": key},
            cookies={"socpow_session": "stray"},
        ).status_code == 400
        assert client.post(
            "/api/playbooks/alert_triage/run",
            headers={"X-API-Key": key, "Authorization": f"Bearer {admin_token}"},
        ).status_code == 400
        assert client.post(
            "/api/playbooks/alert_triage/run",
            headers={"Authorization": f"Bearer {key}"},
        ).status_code == 200
        with pytest.raises(HTTPException) as exc:
            get_current_user(token=key)
        assert exc.value.status_code == 401
        with pytest.raises(ValueError):
            auth_core.revoke_token(key)
        websocket_app = FastAPI()
        websocket_app.include_router(websocket_routes.router)
        with TestClient(websocket_app) as websocket_client:
            with websocket_client.websocket_connect("/ws/agent/session-1") as websocket:
                websocket.send_json({"type": "auth", "token": key})
                with pytest.raises(WebSocketDisconnect) as disconnect:
                    websocket.receive_json()
                assert disconnect.value.code == 1008
        assert client.post(
            "/api/auth/logout", headers={"Authorization": f"Bearer {key}"}
        ).status_code == 403


def test_api_key_throttling_is_separate_and_bad_prefix_is_401_then_429(monkeypatch, tmp_path):
    app, ids = _app(monkeypatch, tmp_path)
    admin_token = _token(ids["admin"], "admin@example.test", "admin", "admin")
    limiter = auth_core.api_key_rate_limiter
    previous = (limiter.max_attempts, limiter.window_seconds)
    limiter.max_attempts, limiter.window_seconds = 2, 900
    with TestClient(app) as client:
        key, _ = _create_key(client, ids["ir"], admin_token)
        prefix = key.split("_")[2]
        limiter.clear(prefix, "testclient")
        unknown_key = f"socpow_live_{'f' * 8}_{key.rsplit('_', 1)[-1]}"
        assert client.post(
            "/api/playbooks/alert_triage/run", headers={"X-API-Key": unknown_key}
        ).status_code == 401
        assert client.post(
            "/api/playbooks/alert_triage/run", headers={"X-API-Key": unknown_key}
        ).status_code == 401
        assert client.post(
            "/api/playbooks/alert_triage/run", headers={"X-API-Key": unknown_key}
        ).status_code == 429
        assert login_rate_limiter.is_limited(prefix, "testclient") is False
        limiter.clear("f" * 8, "testclient")
    limiter.max_attempts, limiter.window_seconds = previous


def test_admin_key_management_and_secret_free_audit(monkeypatch, tmp_path):
    app, ids = _app(monkeypatch, tmp_path)
    admin_token = _token(ids["admin"], "admin@example.test", "admin", "admin")
    analyst_token = _token(ids["analyst"], "analyst@example.test", "analyst", "SOC Analyst Tier 1-2")
    with TestClient(app) as client:
        response = client.post(
            f"/api/admin/users/{ids['analyst']}/api-keys",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={},
        )
        assert response.status_code == 400

        denied = client.post(
            f"/api/admin/users/{ids['ir']}/api-keys",
            headers={"Authorization": f"Bearer {analyst_token}"}, json={},
        )
        assert denied.status_code == 403

        created = client.post(
            f"/api/admin/users/{ids['ir']}/api-keys",
            headers={"Authorization": f"Bearer {admin_token}"}, json={},
        )
        assert created.status_code == 201
        key, key_id = created.json()["key"], created.json()["id"]
        with sqlite3.connect(tmp_path / "auth.db") as connection:
            key_hash = connection.execute(
                "SELECT key_hash FROM api_keys WHERE id = ?", (key_id,)
            ).fetchone()[0]
        listing = client.get(
            f"/api/admin/users/{ids['ir']}/api-keys",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert listing.status_code == 200
        listed_text = listing.text
        assert key not in listed_text and key_hash not in listed_text
        assert listing.json()["api_keys"][0]["scope"] == API_KEY_SCOPE

        audits = app.state.api_key_audit_entries
        audit_text = repr(audits)
        assert key not in audit_text and key_hash not in audit_text
        assert audits[0]["after_state"]["key_prefix"] == "_".join(key.split("_")[:3])
        assert audits[0]["after_state"]["key_id"] == key_id
        assert audits[0]["after_state"]["scope"] == API_KEY_SCOPE
        assert audits[0]["after_state"]["expires_at"] == created.json()["expires_at"]

        assert client.delete(
            f"/api/admin/users/{ids['ir']}/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).status_code == 204
        assert len(audits) == 2
        assert client.post(
            "/api/playbooks/alert_triage/run", headers={"X-API-Key": key}, json={}
        ).status_code == 401
