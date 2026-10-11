from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import auth as auth_core
from src.web import security
from src.web import app as app_module
from src.web.page_auth import PageAuthMiddleware


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "soc_operations.html"
CANVAS_SCRIPT = ROOT / "static" / "js" / "soc_operations.js"
HELPDESK_SCRIPT = ROOT / "static" / "js" / "soc_helpdesk.js"
MIGRATIONS = ROOT / "src" / "db" / "migrations"


def _migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    assert spec is not None and spec.loader is not None
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
            ("soc-room@example.test", "soc-room", "hash", "SOC Analyst Tier 1-2"),
        )
        connection.commit()
        return int(cursor.lastrowid)


def _page_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(PageAuthMiddleware)
    app_module._register_page_routes(app)
    return app


def test_template_keeps_canvas_and_required_room_elements():
    template = TEMPLATE.read_text(encoding="utf-8")
    assert 'id="soc-office-canvas"' in template
    assert 'width="832"' in template
    assert 'height="512"' in template
    assert 'data-asset-base="/static/img/soc/pixel-office"' in template
    assert 'id="soc-room-shell"' in template
    assert 'id="soc-status-badge"' in template
    assert 'class="soc-monitor-card"' in template
    assert 'class="soc-operations-page" data-brand="{{ BRAND_NAME }}"' in template
    assert 'id="soc-fullscreen"' in template


def test_template_replaces_demo_controls_and_activity_panel():
    template = TEMPLATE.read_text(encoding="utf-8")
    assert "LIVE: COMING LATER" not in template
    assert "HELP DESK" in template
    assert 'class="soc-live-pill"' in template
    assert "Ask the SOC Room" in template
    assert "Frequently asked questions" in template
    assert "Report a finding" in template
    for demo_marker in (
        'id="soc-start"',
        'id="soc-pause"',
        'id="soc-reset"',
        'id="soc-scenario"',
        'id="soc-event-log"',
        'id="soc-case-id"',
        "ACTIVITY FEED",
        "Start Demo",
        "DEMO MODE",
    ):
        assert demo_marker not in template
    assert 'name="type"' in template
    assert 'value="wrong_verdict"' in template
    assert 'value="bug"' in template
    assert 'value="suggestion"' in template
    assert 'maxlength="200"' in template
    assert 'maxlength="2000"' in template
    assert 'id="soc-message-count"' in template


def test_helpdesk_script_uses_no_html_string_sinks():
    script = HELPDESK_SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "insertAdjacentHTML", "outerHTML"):
        assert forbidden not in script


def test_protected_canvas_script_anchors_remain_present():
    script = CANVAS_SCRIPT.read_text(encoding="utf-8")
    for anchor in (
        'getElementById("soc-office-canvas")',
        "function enterStage(",
        "function update(dt)",
        "function renderFrame(",
        "function frame(",
    ):
        assert anchor in script


def test_soc_operations_page_requires_auth_and_renders_for_authenticated_user(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "auth.db"
    user_id = _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("AUTH_JWT_SECRET", "soc-room-page-test-secret")
    token = auth_core.create_access_token(
        {"id": user_id, "role": "SOC Analyst Tier 1-2"}
    )

    with TestClient(_page_app()) as client:
        unauthenticated = client.get("/soc-operations", follow_redirects=False)
        client.cookies.set(security.SESSION_COOKIE_NAME, token)
        authenticated = client.get("/soc-operations")

    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"].startswith("/login?next=")
    assert authenticated.status_code == 200
    assert "Ask the SOC Room" in authenticated.text
