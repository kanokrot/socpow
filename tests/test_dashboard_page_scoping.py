from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates

from src.web import app as web_app
from src.web import page_auth
from src.web.analysis_manager import AnalysisManager
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware


SOC_ANALYST = "SOC Analyst Tier 1-2"
INCIDENT_RESPONDER = "Incident Responder"
THREAT_HUNTER = "Threat Hunter"
TEAM_LEAD = "Team Lead"
ADMIN = "admin"


def _user(role: str, user_id: int) -> dict:
    return {
        "id": user_id,
        "email": f"user-{user_id}@example.test",
        "username": f"user-{user_id}",
        "role": role,
        "is_active": 1,
    }


def _page_app(tmp_path: Path) -> FastAPI:
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    app.state.analysis_manager = AnalysisManager(
        db_path=str(tmp_path / "analysis_jobs.db")
    )
    app.state.agent_store = SimpleNamespace(
        add_cross_user_read_audit=lambda **_kwargs: "audit-id"
    )
    _register_page_routes(app)
    return app


def _seed_job(manager: AnalysisManager, user_id: int, indicator: str) -> None:
    job_id = manager.create_job(
        "ioc",
        {"value": indicator, "ioc_type": "ip"},
        user_id=user_id,
    )
    manager.complete_job(job_id, {}, verdict="MALICIOUS", score=80)


def _client_for_page(app: FastAPI, monkeypatch, user: dict) -> TestClient:
    monkeypatch.setattr(
        page_auth,
        "get_current_user",
        lambda token, request=None: user,
    )
    client = TestClient(app)
    client.cookies.set("socpow_session", "test-token")
    return client


def _capture_dashboard_context(monkeypatch, captured: list) -> None:
    original = Jinja2Templates.TemplateResponse

    def capture(self, request, name, context=None, **kwargs):
        if name == "dashboard.html":
            captured.append(context)
        return original(self, request, name, context=context, **kwargs)

    monkeypatch.setattr(Jinja2Templates, "TemplateResponse", capture)


def test_dashboard_page_scopes_recent_jobs_and_keeps_global_stats(
    tmp_path: Path, monkeypatch
) -> None:
    app = _page_app(tmp_path)
    manager = app.state.analysis_manager
    _seed_job(manager, 101, "indicator-soc-a.example")
    _seed_job(manager, 202, "indicator-threat-hunter-b.example")
    _seed_job(manager, 303, "indicator-soc-c.example")
    _seed_job(manager, 404, "indicator-responder-d.example")
    monkeypatch.setattr(
        web_app, "get_user_ids_by_role", lambda role: [101, 303]
    )
    captured = []
    _capture_dashboard_context(monkeypatch, captured)

    with _client_for_page(app, monkeypatch, _user(SOC_ANALYST, 101)) as client:
        analyst_response = client.get("/dashboard")
    analyst_context = captured[-1]

    with _client_for_page(app, monkeypatch, _user(ADMIN, 900)) as client:
        admin_response = client.get("/dashboard")
    admin_context = captured[-1]

    with _client_for_page(app, monkeypatch, _user(TEAM_LEAD, 901)) as client:
        lead_response = client.get("/dashboard")
    lead_context = captured[-1]

    assert analyst_response.status_code == 200
    assert "indicator-soc-a.example" in analyst_response.text
    assert "indicator-threat-hunter-b.example" not in analyst_response.text
    assert "indicator-soc-c.example" not in analyst_response.text
    assert "indicator-responder-d.example" not in analyst_response.text

    assert admin_response.status_code == 200
    for indicator in (
        "indicator-soc-a.example",
        "indicator-threat-hunter-b.example",
        "indicator-soc-c.example",
        "indicator-responder-d.example",
    ):
        assert indicator in admin_response.text

    assert lead_response.status_code == 200
    assert "indicator-soc-a.example" in lead_response.text
    assert "indicator-soc-c.example" in lead_response.text
    assert "indicator-threat-hunter-b.example" not in lead_response.text
    assert "indicator-responder-d.example" not in lead_response.text

    assert analyst_context["stats"]["total_analyses"] == 4
    assert admin_context["stats"]["total_analyses"] == 4
    assert lead_context["stats"]["total_analyses"] == 4
