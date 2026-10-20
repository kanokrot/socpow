from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates

from src.agent.agent_store import AgentStore
from src.web import page_auth
from src.web.auth import get_current_user
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware
from src.web.routes import agent as agent_routes


THREAT_HUNTER = "Threat Hunter"
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
    app.state.agent_store = AgentStore(
        db_path=str(tmp_path / "agent.db")
    )
    app.state.agent_loop = None
    app.state.tool_registry = None
    app.dependency_overrides[get_current_user] = lambda: app.state.current_user
    app.include_router(agent_routes.router, prefix="/api/agent")
    _register_page_routes(app)
    return app


def _client_for_page(app: FastAPI, monkeypatch, user: dict) -> TestClient:
    monkeypatch.setattr(
        page_auth,
        "get_current_user",
        lambda token, request=None: user,
    )
    client = TestClient(app)
    client.cookies.set("socpow_session", "test-token")
    return client


def _capture_investigations_context(monkeypatch, captured: list) -> None:
    original = Jinja2Templates.TemplateResponse

    def capture(self, request, name, context=None, **kwargs):
        if name == "agent_investigations.html":
            captured.append(context)
        return original(self, request, name, context=context, **kwargs)

    monkeypatch.setattr(Jinja2Templates, "TemplateResponse", capture)


def test_agent_investigations_page_scopes_sessions_and_stats(
    tmp_path: Path, monkeypatch
) -> None:
    app = _page_app(tmp_path)
    store = app.state.agent_store
    app.state.current_user = _user(THREAT_HUNTER, 501)
    hunter_session = store.create_session(
        "hunter-owned investigation", user_id=501
    )
    other_session = store.create_session(
        "another user's investigation", user_id=502
    )
    captured = []
    _capture_investigations_context(monkeypatch, captured)

    with _client_for_page(app, monkeypatch, _user(THREAT_HUNTER, 501)) as client:
        hunter_response = client.get("/agent/investigations")
        hunter_sessions_response = client.get("/api/agent/sessions")
    hunter_context = captured[-1]

    app.state.current_user = _user(ADMIN, 900)
    with _client_for_page(app, monkeypatch, _user(ADMIN, 900)) as client:
        admin_response = client.get("/agent/investigations")
        admin_sessions_response = client.get("/api/agent/sessions")
    admin_context = captured[-1]

    assert hunter_response.status_code == 200
    assert "/api/agent/sessions" in hunter_response.text
    hunter_session_ids = {
        session["id"]
        for session in hunter_sessions_response.json()["sessions"]
    }
    assert hunter_session_ids == {hunter_session}
    assert hunter_context["stats"]["total_sessions"] == 1

    assert admin_response.status_code == 200
    admin_session_ids = {
        session["id"]
        for session in admin_sessions_response.json()["sessions"]
    }
    assert admin_session_ids == {hunter_session, other_session}
    assert admin_context["stats"]["total_sessions"] == 2
