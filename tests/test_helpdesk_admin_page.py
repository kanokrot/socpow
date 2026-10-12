from __future__ import annotations

import importlib.util
import re
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import app as app_module
from src.web import auth as auth_core
from src.web import security
from src.web.page_auth import PageAuthMiddleware, PAGE_ROLE_REQUIREMENTS


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"
ADMIN_TEMPLATE = ROOT / "templates" / "helpdesk_admin.html"
SOC_TEMPLATE = ROOT / "templates" / "soc_operations.html"
ADMIN_SCRIPT = ROOT / "static" / "js" / "helpdesk_admin.js"
ADMIN_CSS = ROOT / "static" / "css" / "helpdesk_admin.css"
NON_ADMIN_ROLES = (
    "SOC Analyst Tier 1-2",
    "Incident Responder",
    "Threat Hunter",
    "Team Lead",
)


def _migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _auth_db(path: Path, role: str) -> int:
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
            (f"{role.lower().replace(' ', '-')}@example.test", "page-user", "hash", role),
        )
        connection.commit()
        return int(cursor.lastrowid)


def _page_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(PageAuthMiddleware)
    app_module._register_page_routes(app)
    return app


def _set_session(monkeypatch, tmp_path: Path, role: str, client: TestClient) -> None:
    db_path = tmp_path / "auth.db"
    user_id = _auth_db(db_path, role)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("AUTH_JWT_SECRET", "helpdesk-admin-page-test-secret")
    token = auth_core.create_access_token({"id": user_id, "role": role})
    client.cookies.set(security.SESSION_COOKIE_NAME, token)


def test_helpdesk_admin_page_requires_admin_role_and_has_tablist(
    tmp_path, monkeypatch
):
    assert PAGE_ROLE_REQUIREMENTS["/admin/helpdesk"] == frozenset({"admin"})
    with TestClient(_page_app()) as client:
        unauthenticated = client.get("/admin/helpdesk", follow_redirects=False)
        assert unauthenticated.status_code == 303
        assert unauthenticated.headers["location"].startswith("/login?next=")

        _set_session(monkeypatch, tmp_path, "admin", client)
        admin = client.get("/admin/helpdesk", follow_redirects=False)

    assert admin.status_code == 200
    assert 'role="tablist"' in admin.text
    assert "Inbox" in admin.text
    assert "FAQ editor" in admin.text


@pytest.mark.parametrize("role", NON_ADMIN_ROLES)
def test_non_admin_roles_receive_403_on_helpdesk_admin_page(role, tmp_path, monkeypatch):
    with TestClient(_page_app()) as client:
        _set_session(monkeypatch, tmp_path, role, client)
        response = client.get("/admin/helpdesk", follow_redirects=False)
    assert response.status_code == 403


@pytest.mark.parametrize("role", ("admin", *NON_ADMIN_ROLES))
def test_admin_navigation_link_is_visible_only_to_admin(role, tmp_path, monkeypatch):
    with TestClient(_page_app()) as client:
        _set_session(monkeypatch, tmp_path, role, client)
        response = client.get("/soc-operations")
    assert response.status_code == 200
    if role == "admin":
        assert 'href="/admin/helpdesk"' in response.text
        assert "Help Desk Admin" in response.text
    else:
        assert 'href="/admin/helpdesk"' not in response.text


def test_admin_script_uses_no_html_string_sinks():
    script = ADMIN_SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "insertAdjacentHTML", "outerHTML"):
        assert forbidden not in script
    for mapping in (
        'wrong_verdict: "Wrong verdict"',
        'suggestion: "Suggestion"',
        'bug: "Bug"',
    ):
        assert mapping in script


def test_admin_styles_define_light_and_dark_theme_tokens_without_dark_raw_backgrounds():
    css = ADMIN_CSS.read_text(encoding="utf-8")
    assert '[data-theme="light"] .helpdesk-admin-page' in css
    assert '[data-theme="dark"] .helpdesk-admin-page' in css
    assert ':root:not([data-theme="light"]) .helpdesk-admin-page' in css
    for token in ("--hd-page:", "--hd-surface:", "--hd-border:", "--hd-text:", "--hd-muted:", "--hd-accent:"):
        assert css.count(token) >= 2
    # No direct dark hex literal may be used in a background declaration; surfaces use scoped tokens.
    assert not re.search(
        r"(?im)^\s*background(?:-color)?\s*:\s*#(?:0[0-9a-f]{5}|1[0-9a-f]{5})\b",
        css,
    )


def test_admin_action_buttons_have_primary_outline_danger_and_touch_target_styles():
    template = ADMIN_TEMPLATE.read_text(encoding="utf-8")
    script = ADMIN_SCRIPT.read_text(encoding="utf-8")
    css = ADMIN_CSS.read_text(encoding="utf-8")

    assert 'class="helpdesk-admin-button helpdesk-admin-button--primary" type="submit">Create FAQ' in template
    assert 'node("button", "helpdesk-admin-button--primary", "Save")' in script
    assert 'node("button", "helpdesk-admin-button--primary", "Save changes")' in script
    assert '"helpdesk-admin-button helpdesk-admin-button--outline"' in script
    assert 'node("button", "helpdesk-admin-button--danger", "Delete")' in script
    assert ".helpdesk-faq-actions .helpdesk-admin-button--primary" in css
    assert ".helpdesk-feedback-actions .helpdesk-admin-button--outline" in css
    assert ".helpdesk-faq-actions .helpdesk-admin-button--danger" in css
    assert re.search(r"(?s)input\[type=\"checkbox\"\]\s*\{[^}]*width:\s*22px;[^}]*height:\s*22px;", css)
    checkbox_rule = re.search(r"(?s)input\[type=\"checkbox\"\]\s*\{([^}]*)\}", css)
    assert checkbox_rule is not None
    assert "width: 44px" not in checkbox_rule.group(1)
    assert "height: 44px" not in checkbox_rule.group(1)
    checkbox_row = re.search(r"(?s)\.helpdesk-admin-checkbox\s*\{([^}]*)\}", css)
    assert checkbox_row is not None and "min-height: 44px;" in checkbox_row.group(1)


def test_admin_summary_panel_counts_and_sticky_faq_form_are_wired():
    template = ADMIN_TEMPLATE.read_text(encoding="utf-8")
    script = ADMIN_SCRIPT.read_text(encoding="utf-8")
    css = ADMIN_CSS.read_text(encoding="utf-8")

    assert 'id="helpdesk-overview"' in template
    assert 'byId("helpdesk-overview")' in script
    assert '"/api/helpdesk/admin/summary"' in script
    for status in ("all", "new", "reviewed", "resolved"):
        assert f'id="helpdesk-count-{status}"' in template
        assert f'helpdesk-count-${{status}}' in script
    assert 'id="helpdesk-tab-inbox-count"' in template
    assert 'id="helpdesk-tab-faq-count"' in template
    assert re.search(
        r"(?s)\.helpdesk-faq-create\s*\{[^}]*position:\s*sticky;[^}]*top:\s*76px;",
        css,
    )
    assert re.search(
        r"(?s)\.helpdesk-faq-create \.helpdesk-admin-state\s*\{[^}]*min-height:\s*0;[^}]*margin:\s*0;",
        css,
    )


def test_feedback_status_filter_uses_accessible_pills():
    template = ADMIN_TEMPLATE.read_text(encoding="utf-8")
    assert 'id="helpdesk-feedback-filter"' in template
    for value in ("all", "new", "reviewed", "resolved"):
        assert f'data-status="{value}"' in template
    assert template.count('aria-pressed="') == 4


def test_soc_helpdesk_tooltip_text_is_current():
    template = SOC_TEMPLATE.read_text(encoding="utf-8")
    assert "Live Mode will be connected" not in template
    assert 'title="Ask questions or report a finding"' in template
