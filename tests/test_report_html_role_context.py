from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient

from src.web import page_auth
from src.web.analysis_manager import AnalysisManager
from src.web.auth import get_current_user
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware
from src.web.routes import reports


REPORT_USER = {
    "id": 1,
    "email": "analyst@example.test",
    "username": "analyst-user",
    "is_active": 1,
}


def _build_report_app(tmp_path: Path, role: str) -> tuple[FastAPI, str]:
    # Reuses the FastAPI, AnalysisManager, Jinja2Templates, and TestClient
    # setup pattern from tests/test_report_html_endpoint.py.
    app = FastAPI()
    user = {**REPORT_USER, "role": role}
    app.dependency_overrides[get_current_user] = lambda: user
    app.state.analysis_manager = AnalysisManager(
        db_path=str(tmp_path / f"analysis-{role.replace(' ', '-').lower()}.db")
    )
    app.state.templates = Jinja2Templates(
        directory=str(Path(__file__).resolve().parents[1] / "templates")
    )
    app.include_router(reports.router, prefix="/api/reports")

    job_id = app.state.analysis_manager.create_job("ioc", {"value": "test"})
    app.state.analysis_manager.complete_job(
        job_id,
        {"detection_rules": {"kql": "DeviceEvents | take 10"}},
    )
    return app, job_id


@pytest.mark.parametrize(
    ("role", "can_edit", "has_system_menu"),
    [
        ("admin", True, True),
        ("Threat Hunter", True, False),
        ("SOC Analyst Tier 1-2", False, False),
        ("Incident Responder", False, False),
        ("Team Lead", False, False),
    ],
)
def test_report_html_role_context_controls_edit_and_navbar(
    tmp_path: Path,
    role: str,
    can_edit: bool,
    has_system_menu: bool,
) -> None:
    app, job_id = _build_report_app(tmp_path, role)

    with TestClient(app) as client:
        response = client.get(f"/api/reports/{job_id}/html")

    assert response.status_code == 200
    assert ('data-rule-action="edit"' in response.text) is can_edit
    assert ('<i class="bi bi-gear me-1"></i>System' in response.text) is has_system_menu


def _build_page_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    app.state.analysis_manager = SimpleNamespace(
        get_stats=lambda: {},
        list_jobs=lambda limit=10, **kwargs: [],
    )
    _register_page_routes(app)
    return app


def test_navbar_badge_uses_username_and_public_login_has_no_badge(monkeypatch) -> None:
    user = {
        "id": 2,
        "email": "fallback@example.test",
        "username": "visible-user",
        "role": "Threat Hunter",
        "is_active": 1,
    }
    monkeypatch.setattr(page_auth, "get_current_user", lambda token, request=None: user)

    with TestClient(_build_page_app()) as client:
        client.cookies.set("socpow_session", "test-token")
        dashboard = client.get("/dashboard")

    with TestClient(_build_page_app()) as client:
        login = client.get("/login")

    assert dashboard.status_code == 200
    assert "visible-user" in dashboard.text
    assert "Threat Hunter" in dashboard.text
    assert "fallback@example.test" not in dashboard.text
    assert login.status_code == 200
    assert '<span class="navbar-user-badge"' not in login.text
