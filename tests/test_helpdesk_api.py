from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import auth as auth_core
from src.web import security
from src.web.routes import helpdesk


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"
NON_ADMIN_ROLES = (
    "SOC Analyst Tier 1-2",
    "Incident Responder",
    "Threat Hunter",
    "Team Lead",
)
ADMIN_ENDPOINTS = (
    ("get", "/api/helpdesk/admin/feedback", None),
    ("patch", "/api/helpdesk/admin/feedback/1", {"status": "reviewed"}),
    ("get", "/api/helpdesk/admin/faq", None),
    ("post", "/api/helpdesk/admin/faq", {"question": "Q", "answer": "A"}),
    ("patch", "/api/helpdesk/admin/faq/1", {"question": "Changed"}),
    ("delete", "/api/helpdesk/admin/faq/1", None),
)
ALL_ENDPOINTS = (
    ("post", "/api/helpdesk/feedback", {"type": "bug", "message": "Example"}),
    ("get", "/api/helpdesk/faq", None),
    *ADMIN_ENDPOINTS,
)


def _migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _auth_db(path: Path) -> int:
    for filename in (
        "001_create_users.py",
        "002_add_username_and_admin_role.py",
        "004_add_team_lead_role.py",
    ):
        _migration(filename).migrate(str(path))
    with sqlite3.connect(path) as connection:
        cursor = connection.execute(
            "INSERT INTO users (email, username, password_hash, role, is_active) "
            "VALUES (?, ?, ?, ?, 1)",
            ("helpdesk@example.test", "helpdesk", "hash", "admin"),
        )
        connection.commit()
        return int(cursor.lastrowid)


def _app(user: dict | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(helpdesk.router, prefix="/api/helpdesk")
    if user is not None:
        app.dependency_overrides[auth_core.get_current_user] = lambda: user
    return app


def _call(client: TestClient, method: str, path: str, payload: dict | None = None):
    return getattr(client, method)(path, json=payload) if payload is not None else getattr(client, method)(path)


@pytest.mark.parametrize(("method", "path", "payload"), ALL_ENDPOINTS)
def test_every_endpoint_requires_authentication(method, path, payload):
    with TestClient(_app()) as client:
        response = _call(client, method, path, payload)
    assert response.status_code == 401


@pytest.mark.parametrize("role", NON_ADMIN_ROLES)
@pytest.mark.parametrize(("method", "path", "payload"), ADMIN_ENDPOINTS)
def test_every_non_admin_role_is_forbidden_from_admin_endpoints(
    tmp_path, monkeypatch, role, method, path, payload
):
    user_id = _auth_db(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    with TestClient(_app({"id": user_id, "role": role, "is_active": 1})) as client:
        response = _call(client, method, path, payload)
    assert response.status_code == 403


@pytest.mark.parametrize("role", (*NON_ADMIN_ROLES, "admin"))
def test_any_logged_in_role_can_submit_feedback_and_read_faq(
    tmp_path, monkeypatch, role
):
    user_id = _auth_db(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    user = {"id": user_id, "role": role, "is_active": 1}
    with TestClient(_app(user)) as client:
        posted = client.post(
            "/api/helpdesk/feedback",
            json={"type": "wrong_verdict", "reference": "analysis-1", "message": "Review this"},
        )
        faq = client.get("/api/helpdesk/faq")
    assert posted.status_code == 201
    assert set(posted.json()) == {"id", "status"}
    assert posted.json()["status"] == "new"
    assert faq.status_code == 200
    assert faq.json() == {"items": []}


@pytest.mark.parametrize(
    "payload",
    (
        {"type": "bug", "message": ""},
        {"type": "bug", "message": "   "},
        {"type": "bug", "message": "x" * 2001},
        {"type": "bug", "reference": "r" * 201, "message": "Valid"},
        {"type": "invalid", "message": "Valid"},
    ),
)
def test_feedback_validation_returns_422(tmp_path, monkeypatch, payload):
    user_id = _auth_db(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    with TestClient(_app({"id": user_id, "role": "SOC Analyst Tier 1-2"})) as client:
        response = client.post("/api/helpdesk/feedback", json=payload)
    assert response.status_code == 422


def test_cookie_posts_require_matching_csrf_token(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    user_id = _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("AUTH_JWT_SECRET", "helpdesk-cookie-test-secret")
    token = auth_core.create_access_token(
        {"id": user_id, "role": "SOC Analyst Tier 1-2"}
    )
    with TestClient(_app()) as client:
        client.cookies.set(security.SESSION_COOKIE_NAME, token)
        client.cookies.set(security.CSRF_COOKIE_NAME, "valid-cookie-token")
        body = {"type": "bug", "message": "Cookie authenticated feedback"}
        missing = client.post("/api/helpdesk/feedback", json=body)
        wrong = client.post(
            "/api/helpdesk/feedback",
            json=body,
            headers={"X-CSRF-Token": "wrong-token"},
        )
        accepted = client.post(
            "/api/helpdesk/feedback",
            json=body,
            headers={"X-CSRF-Token": "valid-cookie-token"},
        )
    assert missing.status_code == 403
    assert wrong.status_code == 403
    assert accepted.status_code == 201


def test_submitter_has_no_feedback_list_or_read_route(tmp_path, monkeypatch):
    user_id = _auth_db(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    with TestClient(_app({"id": user_id, "role": "SOC Analyst Tier 1-2"})) as client:
        assert client.get("/api/helpdesk/feedback").status_code == 405
        assert client.get("/api/helpdesk/feedback/1").status_code == 404


def test_feedback_patch_cannot_change_submitter_type_or_message(tmp_path, monkeypatch):
    user_id = _auth_db(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    with TestClient(_app({"id": user_id, "role": "admin", "is_active": 1})) as client:
        created = client.post(
            "/api/helpdesk/feedback", json={"type": "bug", "message": "Original"}
        )
        feedback_id = created.json()["id"]
        changed = client.patch(
            f"/api/helpdesk/admin/feedback/{feedback_id}",
            json={"status": "reviewed", "submitter_id": 999, "type": "suggestion", "message": "Changed"},
        )
        rows = client.get("/api/helpdesk/admin/feedback").json()["items"]
    assert changed.status_code == 422
    assert rows[0]["submitter_id"] == user_id
    assert rows[0]["type"] == "bug"
    assert rows[0]["message"] == "Original"


def test_feedback_admin_status_filter_and_update(tmp_path, monkeypatch):
    user_id = _auth_db(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    with TestClient(_app({"id": user_id, "role": "admin", "is_active": 1})) as client:
        created = client.post(
            "/api/helpdesk/feedback", json={"type": "suggestion", "message": "Please add this"}
        ).json()
        updated = client.patch(
            f"/api/helpdesk/admin/feedback/{created['id']}",
            json={"status": "reviewed", "admin_note": "Reviewed"},
        )
        reviewed = client.get("/api/helpdesk/admin/feedback?status=reviewed")
        new = client.get("/api/helpdesk/admin/feedback?status=new")
    assert updated.status_code == 200
    assert reviewed.json()["items"][0]["admin_note"] == "Reviewed"
    assert new.json()["items"] == []


def test_unpublished_faq_is_hidden_from_users_but_visible_to_admin(tmp_path, monkeypatch):
    user_id = _auth_db(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    with TestClient(_app({"id": user_id, "role": "admin", "is_active": 1})) as client:
        created = client.post(
            "/api/helpdesk/admin/faq",
            json={"question": "Internal question", "answer": "Internal answer", "is_published": 0},
        )
        public_items = client.get("/api/helpdesk/faq").json()["items"]
        admin_items = client.get("/api/helpdesk/admin/faq").json()["items"]
    assert created.status_code == 201
    assert public_items == []
    assert len(admin_items) == 1
    assert admin_items[0]["is_published"] == 0


def test_admin_can_create_update_and_delete_faq(tmp_path, monkeypatch):
    user_id = _auth_db(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    with TestClient(_app({"id": user_id, "role": "admin", "is_active": 1})) as client:
        created = client.post(
            "/api/helpdesk/admin/faq",
            json={"question": "How?", "answer": "Carefully", "sort_order": 4},
        )
        faq_id = created.json()["id"]
        updated = client.patch(
            f"/api/helpdesk/admin/faq/{faq_id}",
            json={"question": "How exactly?", "is_published": 0},
        )
        deleted = client.delete(f"/api/helpdesk/admin/faq/{faq_id}")
        missing = client.get("/api/helpdesk/admin/faq").json()["items"]
    assert created.status_code == 201
    assert updated.json()["question"] == "How exactly?"
    assert deleted.status_code == 200
    assert missing == []


def test_fresh_auth_db_creates_helpdesk_schema_lazily_and_repeated_calls_are_safe(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "fresh-auth.db"
    user_id = _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    user = {"id": user_id, "role": "admin", "is_active": 1}
    with sqlite3.connect(db_path) as connection:
        before = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'helpdesk_%'"
        ).fetchall()
    assert before == []

    with TestClient(_app(user)) as client:
        assert client.get("/api/helpdesk/faq").status_code == 200
        feedback = client.post(
            "/api/helpdesk/feedback", json={"type": "bug", "message": "First use"}
        )
        feedback_id = feedback.json()["id"]
        assert client.get("/api/helpdesk/admin/feedback").status_code == 200
        assert client.patch(
            f"/api/helpdesk/admin/feedback/{feedback_id}",
            json={"status": "resolved"},
        ).status_code == 200
        faq = client.post(
            "/api/helpdesk/admin/faq", json={"question": "Q", "answer": "A"}
        )
        faq_id = faq.json()["id"]
        assert client.get("/api/helpdesk/admin/faq").status_code == 200
        assert client.get("/api/helpdesk/faq").status_code == 200
        assert client.patch(
            f"/api/helpdesk/admin/faq/{faq_id}", json={"answer": "Updated"}
        ).status_code == 200
        assert client.delete(f"/api/helpdesk/admin/faq/{faq_id}").status_code == 200
        assert client.get("/api/helpdesk/admin/feedback?status=resolved").status_code == 200

    with sqlite3.connect(db_path) as connection:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'helpdesk_%'"
            )
        }
    assert table_names == {"helpdesk_feedback", "helpdesk_faq"}


def test_helpdesk_migration_is_idempotent(tmp_path):
    path = tmp_path / "auth.db"
    _auth_db(path)
    migration = _migration("015_add_helpdesk.py")
    migration.migrate(str(path))
    migration.migrate(str(path))
    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'helpdesk_%'"
            )
        }
    assert tables == {"helpdesk_feedback", "helpdesk_faq"}
