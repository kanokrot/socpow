from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import page_auth
from src.web.analysis_manager import AnalysisManager
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware


ROLES = [
    "SOC Analyst Tier 1-2",
    "Incident Responder",
    "Threat Hunter",
    "Team Lead",
    "admin",
]

HREFS = {
    "/agent/investigations": {"Threat Hunter", "admin"},
    "/agent/playbooks": {"Incident Responder", "admin"},
    "/analysis/ioc": {"SOC Analyst Tier 1-2", "admin"},
    "/history": set(ROLES),
    "/cases": set(ROLES),
    "/management": {"Team Lead", "admin"},
    "/tickets": set(ROLES),
    "/mcp/servers": {"admin"},
    "/settings": {"admin"},
    "/account": set(ROLES),
    "/": {"Threat Hunter", "admin"},
}


def _build_page_app(tmp_path) -> FastAPI:
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    app.state.analysis_manager = AnalysisManager(db_path=str(tmp_path / "analysis.db"))
    _register_page_routes(app)
    return app


@pytest.mark.parametrize("role", ROLES)
def test_more_menu_role_gates_and_unique_nav_links(tmp_path, monkeypatch, role: str) -> None:
    user = {
        "id": 1,
        "email": "test@example.test",
        "username": "test_user",
        "role": role,
        "is_active": 1,
    }
    monkeypatch.setattr(page_auth, "get_current_user", lambda token, request=None: user)

    with TestClient(_build_page_app(tmp_path)) as client:
        client.cookies.set("cabta_session", "test-token")
        account_response = client.get("/account", follow_redirects=False)
        other_page = client.get("/history")
        if role == "admin":
            assert account_response.status_code == 302
            assert account_response.headers["location"] == "/settings#sources"
            response = client.get("/settings")
        else:
            response = account_response

    assert response.status_code == 200
    if role == "admin":
        assert "account-avatar" not in response.text
    else:
        assert "account-avatar" in response.text
    if role == "admin":
        nav_match = re.search(r'<aside class="settings-side-nav".*?<nav class="settings-nav-list"[^>]*>(.*?)</nav>', response.text, re.S)
        assert nav_match is not None
        assert "My settings" not in nav_match.group(1)
        assert "/account" not in nav_match.group(1)
        assert "Intelligence sources" in nav_match.group(1)
    else:
        assert "Extra evidence only. These keys never change the score or verdict." in response.text
        assert '<h1 class="h3">My settings</h1>' in response.text
        assert "userApiKeysRows" in response.text
        assert "gmailCard" not in response.text
        assert "Connect Gmail" not in response.text
        assert "/static/js/gmail_settings.js" not in response.text
        assert "/static/js/account_api_keys.js?v=3" in response.text
        account_template = (Path(__file__).parents[1] / "templates" / "account.html").read_text(encoding="utf-8")
        assert all(label not in account_template for label in ("gmailCard", "gmailStatusLabel", "gmail_settings.js"))
        assert '<aside class="settings-side-nav"' not in response.text
    nav_start = response.text.index("<nav ")
    nav_end = response.text.index("</nav>", nav_start) + len("</nav>")
    nav_html = response.text[:nav_end]
    capsule_match = re.search(r'<div class="navbar-user-capsule">(.*?)</div>', nav_html, re.S)
    assert capsule_match is not None
    capsule = capsule_match.group(1)
    assert '<span class="navbar-user-identity"' in capsule
    assert '<span class="navbar-user-avatar" aria-hidden="true">TU</span>' in capsule
    assert "navbar-user-name" in capsule
    account_links = re.findall(r'<a\b[^>]*href="/account"[^>]*>.*?</a>', nav_html, re.S)
    assert len(account_links) == (0 if role == "admin" else 1)
    assert len(re.findall(r'href="/account"', nav_html)) == (0 if role == "admin" else 1)
    if role != "admin":
        assert not re.search(r'<a\b', capsule.split('<a href="/account"', 1)[0])
        account_link = account_links[0]
        assert account_link in capsule
        assert 'title="My settings"' in account_link
        assert 'aria-label="My settings"' in account_link
        assert "My settings" in re.sub(r"<[^>]+>", "", account_link)
        assert '<i class="bi bi-person-gear navbar-account-icon"' in account_link
        assert "navbar-account-link active" in account_link
    else:
        assert "navbar-account-link" not in capsule
        assert capsule.count('class="navbar-user-identity"') == 1
    history_nav = other_page.text[:other_page.text.index("</nav>") + len("</nav>")]
    history_links = re.findall(r'<a\b[^>]*href="/account"[^>]*class="([^"]*)"', history_nav)
    assert not any("active" in classes.split() for classes in history_links)

    for href, roles in HREFS.items():
        nav_link_hrefs = []
        for anchor in re.findall(r'<a\b[^>]*>', nav_html):
            if re.search(r'class="[^"]*(?:nav-link|dropdown-item|navbar-user-account|navbar-account-link)[^"]*"', anchor):
                href_match = re.search(r'href="([^"]+)"', anchor)
                if href_match:
                    nav_link_hrefs.append(href_match.group(1))
        expected_count = (0 if role == "admin" else 1) if href == "/account" else (1 if role in roles else 0)
        assert nav_link_hrefs.count(href) == expected_count

    assert len(re.findall(r">\s*More\s*</a>", nav_html)) == 1
    assert nav_html.count('<h6 class="dropdown-header">Agent</h6>') == (
        1 if role in {"Incident Responder", "Threat Hunter", "admin"} else 0
    )
    assert nav_html.count('<h6 class="dropdown-header">Management</h6>') == 1
    assert len(re.findall(r'<h6 class="dropdown-header">(?:<i[^>]*></i>)?System</h6>', nav_html)) == (
        1 if role == "admin" else 0
    )

def test_settings_page_keeps_admin_settings_script_without_gmail_card(tmp_path, monkeypatch) -> None:
    user = {
        "id": 1,
        "email": "admin@example.test",
        "username": "admin-user",
        "role": "admin",
        "is_active": 1,
    }
    monkeypatch.setattr(page_auth, "get_current_user", lambda token, request=None: user)

    with TestClient(_build_page_app(tmp_path)) as client:
        client.cookies.set("cabta_session", "test-token")
        response = client.get("/settings")

    assert response.status_code == 200
    assert "gmail" not in response.text.lower()
    assert "var Settings = (function()" in response.text
    assert "refreshOllamaModels" in response.text
    settings_nav = re.search(r'<aside class="settings-side-nav".*?<nav class="settings-nav-list"[^>]*>(.*?)</nav>', response.text, re.S)
    assert settings_nav is not None
    settings_links = re.findall(r'<a\b[^>]*class="([^"]*settings-nav-link[^"]*)"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', settings_nav.group(1), re.S)
    assert [label.strip() for _classes, _href, label in settings_links] == ["General", "Intelligence sources", "System"]
    assert [href for _classes, href, _label in settings_links] == ["/settings#general", "/settings#sources", "/settings#system"]
    assert "My settings" not in response.text
    assert "active" in settings_links[0][0]
    assert all("active" not in classes for index, (classes, _href, _label) in enumerate(settings_links) if index != 0)
    assert "Admin only" in response.text


@pytest.mark.parametrize("role", [role for role in ROLES if role != "admin"])
def test_non_admin_account_navigation_and_settings_guard_are_unchanged(tmp_path, monkeypatch, role: str) -> None:
    user = {"id": 2, "email": "user@example.test", "username": "user", "role": role, "is_active": 1}
    monkeypatch.setattr(page_auth, "get_current_user", lambda token, request=None: user)
    with TestClient(_build_page_app(tmp_path)) as client:
        client.cookies.set("cabta_session", "test-token")
        account = client.get("/account")
        settings = client.get("/settings")
    assert account.status_code == 200
    assert '<aside class="settings-side-nav"' not in account.text
    assert "Admin only" not in account.text
    assert '<h1 class="h3">My settings</h1>' in account.text
    assert settings.status_code == 403
