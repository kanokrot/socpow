from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import auth as auth_core
from src.web import security
from src.web.app import _register_page_routes
from src.web.routes import auth as auth_routes
from src.web.routes import access_requests, admin as admin_routes


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"


def _load_migration(filename: str):
    spec = importlib.util.spec_from_file_location(
        filename[:-3], MIGRATIONS / filename
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _auth_db(path: Path) -> None:
    _load_migration("001_create_users.py").migrate(str(path))
    _load_migration("002_add_username_and_admin_role.py").migrate(str(path))
    _load_migration("004_add_team_lead_role.py").migrate(str(path))
    _load_migration("010_add_access_requests.py").migrate(str(path))
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO users (email, username, password_hash, role, is_active) "
            "VALUES (?, ?, ?, ?, 1)",
            ("admin@example.test", "admin", "hash", "admin"),
        )
        connection.commit()


def _page_app() -> FastAPI:
    app = FastAPI()
    _register_page_routes(app)
    return app


def _admin_api_app(role: str = "admin") -> FastAPI:
    app = FastAPI()
    app.state.config = {"notifications": {"email": {"enabled": False}}}
    app.include_router(access_requests.router, prefix="/api/admin")
    app.dependency_overrides[auth_core.get_current_user] = lambda: {
        "id": 1,
        "email": f"{role.replace(' ', '-').lower()}@example.test",
        "username": role.replace(" ", "-").lower(),
        "role": role,
        "is_active": 1,
    }
    return app


def _cookie_admin_app() -> FastAPI:
    app = FastAPI()
    app.state.config = {"notifications": {"email": {"enabled": False}}}
    app.include_router(auth_routes.router, prefix="/api/auth")
    app.include_router(admin_routes.router, prefix="/api/admin")
    app.include_router(admin_routes.team_lead_router, prefix="/api/team-lead")
    app.include_router(access_requests.router, prefix="/api/admin")
    return app


def _form(email: str, role: str = "Team Lead") -> dict[str, str]:
    return {
        "name": "Prospective Operator",
        "email": email,
        # This client field is ignored; the public handler stores Team Lead.
        "requested_role": role,
        "reason": "Need access for SOC coordination.",
    }


def test_access_request_migration_is_idempotent_and_has_expected_schema(tmp_path):
    path = tmp_path / "auth.db"
    _auth_db(path)
    _load_migration("010_add_access_requests.py").migrate(str(path))

    with sqlite3.connect(path) as connection:
        columns = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(access_requests)")
        }
        assert set(columns) == {
            "id", "name", "email", "requested_role", "reason", "status",
            "created_at", "decided_at", "decided_by",
        }
        connection.execute(
            "INSERT INTO access_requests (name, email, requested_role, reason) "
            "VALUES (?, ?, ?, ?)",
            ("A", "a@example.test", "Team Lead", "Need access"),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO access_requests (name, email, requested_role, reason) "
                "VALUES (?, ?, ?, ?)",
                ("B", "A@EXAMPLE.TEST", "Team Lead", "Duplicate pending"),
            )


def test_public_request_access_validates_duplicates_and_renders_form(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setattr(
        access_requests,
        "access_request_rate_limiter",
        security.LoginRateLimiter(max_attempts=20, window_seconds=900),
    )

    with TestClient(_page_app()) as client:
        page = client.get("/request-access")
        assert page.status_code == 200
        assert "Request access" in page.text
        assert "Requested role" not in page.text
        assert 'id="request-role"' not in page.text
        login = client.get("/login")
        assert "/request-access" in login.text

        submitted = client.post(
            "/request-access",
            data=_form("lead@example.test"),
            follow_redirects=False,
        )
        assert submitted.status_code == 303
        assert submitted.headers["location"] == "/request-access?submitted=true"

        duplicate = client.post(
            "/request-access",
            data=_form("LEAD@example.test"),
        )
        assert duplicate.status_code == 409
        assert "pending access request" in duplicate.text

        invalid = client.post(
            "/request-access",
            data=_form("not-an-email"),
        )
        assert invalid.status_code == 400
        assert "valid email" in invalid.text

        crafted_emails = []
        for index, role in enumerate(
            ("admin", "SOC Analyst Tier 1-2", "Incident Responder", "Threat Hunter")
        ):
            crafted_email = f"blocked-{index}@example.test"
            crafted_emails.append(crafted_email)
            crafted_role = client.post(
                "/request-access",
                data=_form(crafted_email, role=role),
                follow_redirects=False,
            )
            assert crafted_role.status_code == 303

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT email, requested_role FROM access_requests "
            "WHERE email LIKE 'blocked-%@example.test'"
        ).fetchall()
    assert dict(rows) == {email: "Team Lead" for email in crafted_emails}


def test_public_request_access_is_rate_limited_by_ip(monkeypatch, tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setattr(
        access_requests,
        "access_request_rate_limiter",
        security.LoginRateLimiter(max_attempts=2, window_seconds=900),
    )

    with TestClient(_page_app()) as client:
        for index in range(2):
            response = client.post(
                "/request-access",
                data=_form(f"user-{index}@example.test"),
                follow_redirects=False,
            )
            assert response.status_code == 303
        limited = client.post(
            "/request-access",
            data=_form("user-2@example.test"),
            follow_redirects=False,
        )

    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0


def test_admin_access_request_api_is_protected_and_approves_via_existing_invite(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    access_requests.create_access_request(
        name="Prospective Operator",
        email="approve@example.test",
        requested_role="Team Lead",
        reason="Need access for team coordination.",
    )

    calls = []

    def fake_invite(payload, request, admin_user):
        calls.append((payload.email, payload.role, admin_user["id"]))
        return {
            "email": payload.email,
            "role": payload.role,
            "expires_at": 123,
        }

    monkeypatch.setattr(admin_routes, "invite_user", fake_invite)

    with TestClient(_admin_api_app("SOC Analyst Tier 1-2")) as client:
        assert client.get("/api/admin/access-requests").status_code == 403

    with TestClient(_admin_api_app()) as client:
        listing = client.get("/api/admin/access-requests")
        assert listing.status_code == 200
        request_id = listing.json()["requests"][0]["id"]
        approved = client.post(
            f"/api/admin/access-requests/{request_id}/approve"
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

    assert calls == [("approve@example.test", "Team Lead", 1)]
    with sqlite3.connect(db_path) as connection:
        status_value, decided_by = connection.execute(
            "SELECT status, decided_by FROM access_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
    assert status_value == "approved"
    assert decided_by == 1

    rejected_request = access_requests.create_access_request(
        name="Reject Me",
        email="reject@example.test",
        requested_role="Team Lead",
        reason="No longer needed.",
    )
    with TestClient(_admin_api_app()) as client:
        rejected = client.post(
            f"/api/admin/access-requests/{rejected_request['id']}/reject"
        )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"


def test_management_page_shows_role_specific_content(monkeypatch, tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    access_requests.create_access_request(
        name="Pending User",
        email="pending@example.test",
        requested_role="Team Lead",
        reason="Need team lead access.",
    )

    app = _page_app()
    app.dependency_overrides[auth_core.get_current_user] = lambda: {
        "id": 1,
        "email": "admin@example.test",
        "username": "admin",
        "role": "admin",
        "is_active": 1,
    }
    with TestClient(app) as client:
        response = client.get("/management")

    assert response.status_code == 200
    assert "pending@example.test" in response.text
    assert "Approve" in response.text

    lead_app = _page_app()
    lead_app.dependency_overrides[auth_core.get_current_user] = lambda: {
        "id": 2,
        "email": "lead@example.test",
        "username": "lead",
        "role": "Team Lead",
        "is_active": 1,
    }
    with TestClient(lead_app) as client:
        response = client.get("/management")

    assert response.status_code == 200
    assert "Invite team member" in response.text
    assert "pending@example.test" not in response.text
    assert 'value="admin"' not in response.text
    assert 'value="Team Lead"' not in response.text


def test_team_lead_invite_uses_real_cookie_login_and_scoped_role_checks(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("AUTH_JWT_SECRET", "team-lead-invite-test-secret")
    password = "TeamLeadPassword!2026"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO users "
            "(email, username, password_hash, role, is_active) "
            "VALUES (?, ?, ?, ?, 1)",
            (
                "lead@example.test",
                "team-lead",
                auth_core.hash_password(password),
                "Team Lead",
            ),
        )
        connection.commit()

    class FakeEmailChannel:
        def __init__(self, _config):
            pass

        def send(self, _subject, _body):
            return {"success": True}

    monkeypatch.setattr(admin_routes, "EmailChannel", FakeEmailChannel)
    monkeypatch.setattr(
        auth_routes,
        "login_rate_limiter",
        security.LoginRateLimiter(max_attempts=5, window_seconds=60),
    )
    app = _cookie_admin_app()
    app.state.config = {"notifications": {"email": {"enabled": True}}}

    with TestClient(app) as client:
        login = client.post(
            "/api/auth/login",
            json={"username": "team-lead", "password": password},
        )
        assert login.status_code == 200
        csrf_token = client.cookies.get("socpow_csrf")
        assert csrf_token

        missing_csrf = client.post(
            "/api/team-lead/users/invite",
            json={
                "email": "operator@example.test",
                "role": "SOC Analyst Tier 1-2",
            },
        )
        assert missing_csrf.status_code == 403

        invited = client.post(
            "/api/team-lead/users/invite",
            json={
                "email": "operator@example.test",
                "role": "SOC Analyst Tier 1-2",
            },
            headers={"X-CSRF-Token": csrf_token},
        )
        assert invited.status_code == 202
        assert invited.json()["role"] == "SOC Analyst Tier 1-2"

        for index, role in enumerate(("admin", "Team Lead")):
            forbidden = client.post(
                "/api/team-lead/users/invite",
                json={
                    "email": f"forbidden-{index}@example.test",
                    "role": role,
                },
                headers={"X-CSRF-Token": csrf_token},
            )
            assert forbidden.status_code == 403

    with sqlite3.connect(db_path) as connection:
        invited_row = connection.execute(
            "SELECT role FROM users WHERE email = ?",
            ("operator@example.test",),
        ).fetchone()
    assert invited_row == ("SOC Analyst Tier 1-2",)


def test_cookie_authenticated_access_request_actions_require_csrf(
    monkeypatch, tmp_path
):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("AUTH_JWT_SECRET", "access-request-test-secret")
    password = "AdminPassword!2026"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE username = 'admin'",
            (auth_core.hash_password(password),),
        )
        connection.commit()

    approve_request = access_requests.create_access_request(
        name="Approve Me",
        email="approve-csrf@example.test",
        requested_role="Team Lead",
        reason="Need access.",
    )
    reject_request = access_requests.create_access_request(
        name="Reject Me",
        email="reject-csrf@example.test",
        requested_role="Team Lead",
        reason="No longer needed.",
    )

    def fake_invite(payload, request, admin_user):
        return {
            "email": payload.email,
            "role": payload.role,
            "expires_at": 123,
        }

    monkeypatch.setattr(admin_routes, "invite_user", fake_invite)
    with TestClient(_cookie_admin_app()) as client:
        login = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": password},
        )
        assert login.status_code == 200
        csrf_token = client.cookies.get("socpow_csrf")
        assert csrf_token

        assert client.post(
            f"/api/admin/access-requests/{approve_request['id']}/approve"
        ).status_code == 403
        assert client.post(
            f"/api/admin/access-requests/{approve_request['id']}/approve",
            headers={"X-CSRF-Token": csrf_token},
        ).status_code == 200

        assert client.post(
            f"/api/admin/access-requests/{reject_request['id']}/reject"
        ).status_code == 403
        assert client.post(
            f"/api/admin/access-requests/{reject_request['id']}/reject",
            headers={"X-CSRF-Token": csrf_token},
        ).status_code == 200
