"""Extended Team Lead permission tests for approval, cases, and analysis scope."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.agent.agent_store import AgentStore
from src.web.analysis_manager import AnalysisManager
from src.web.auth import get_current_user
from src.web.case_store import CaseStore
from src.web.routes import analysis as analysis_routes
from src.web.routes import cases as cases_routes
from src.web.routes import reports as reports_routes


SOC = "SOC Analyst Tier 1-2"
INCIDENT_RESPONDER = "Incident Responder"
THREAT_HUNTER = "Threat Hunter"
TEAM_LEAD = "Team Lead"
ADMIN = "admin"


def _user(role: str, user_id: int) -> dict:
    return {
        "id": user_id,
        "email": f"{role.lower().replace(' ', '-')}@example.test",
        "username": f"{role.lower().replace(' ', '-')}-{user_id}",
        "role": role,
        "is_active": 1,
    }


def _database_snapshot(db_path: Path) -> dict:
    """Capture schema and every row in each application table in a SQLite DB."""
    with sqlite3.connect(str(db_path)) as connection:
        schema = connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        ).fetchall()
        table_names = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        tables = {}
        for (table_name,) in table_names:
            escaped_name = table_name.replace('"', '""')
            tables[table_name] = connection.execute(
                f'SELECT * FROM "{escaped_name}" ORDER BY rowid'
            ).fetchall()
    return {"schema": schema, "tables": tables}


def _create_auth_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO users (id, email, username, role, is_active) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                (101, "soc-active@example.test", "soc-active", SOC, 1),
                (102, "soc-inactive@example.test", "soc-inactive", SOC, 0),
                (103, "soc-peer@example.test", "soc-peer", SOC, 1),
                (201, "hunter@example.test", "hunter", THREAT_HUNTER, 1),
                (202, "responder@example.test", "responder", INCIDENT_RESPONDER, 1),
                (900, "lead@example.test", "team-lead", TEAM_LEAD, 1),
                (999, "admin@example.test", "admin", ADMIN, 1),
            ],
        )
        connection.commit()


def _report_app(tmp_path: Path, role: str, user_id: int) -> tuple[FastAPI, AnalysisManager, str]:
    app = FastAPI()
    manager = AnalysisManager(str(tmp_path / "analysis_jobs.db"))
    analysis_id = manager.create_job(
        "ioc",
        {"value": "198.51.100.10"},
        user_id=user_id,
    )
    manager.complete_job(
        analysis_id,
        {"detection_rules": {"kql": "DeviceProcessEvents\n| take 1"}},
        verdict="CLEAN",
        score=5,
    )
    app.state.analysis_manager = manager
    app.dependency_overrides[get_current_user] = lambda: _user(role, user_id)
    app.include_router(reports_routes.router, prefix="/api/reports")
    return app, manager, analysis_id


def test_team_lead_can_approve_detection_rule_export(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        reports_routes,
        "validate_rule",
        lambda *_args: {"valid": True},
    )
    app, manager, analysis_id = _report_app(tmp_path, TEAM_LEAD, 900)
    state_key = (analysis_id, "kql")
    reports_routes._rule_export_states.pop(state_key, None)
    before = _database_snapshot(manager._db_path)

    with TestClient(app) as client:
        response = client.post(
            f"/api/reports/{analysis_id}/rules/kql/approve",
            json={},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    assert response.json()["approved_by"] == "team-lead-900"
    assert _database_snapshot(manager._db_path) == before
    reports_routes._rule_export_states.pop(state_key, None)


@pytest.mark.parametrize("role", [SOC, THREAT_HUNTER], ids=["soc-analyst", "threat-hunter"])
def test_soc_and_threat_hunter_cannot_approve_rule_export_without_database_change(
    tmp_path, monkeypatch, role: str
) -> None:
    monkeypatch.setattr(
        reports_routes,
        "validate_rule",
        lambda *_args: {"valid": True},
    )
    user_id = 101 if role == SOC else 201
    app, manager, analysis_id = _report_app(tmp_path, role, user_id)
    state_key = (analysis_id, "kql")
    reports_routes._rule_export_states.pop(state_key, None)
    before = _database_snapshot(manager._db_path)
    state_before = reports_routes._rule_export_states.get(state_key)

    with TestClient(app) as client:
        response = client.post(
            f"/api/reports/{analysis_id}/rules/kql/approve",
            json={},
        )

    assert response.status_code == 403
    assert _database_snapshot(manager._db_path) == before
    assert reports_routes._rule_export_states.get(state_key) == state_before


def test_team_lead_cannot_mark_rule_deployed_without_database_change(tmp_path) -> None:
    app, manager, analysis_id = _report_app(tmp_path, TEAM_LEAD, 900)
    state_key = (analysis_id, "kql")
    reports_routes._rule_export_states[state_key] = {
        "analysis_id": analysis_id,
        "rule_type": "kql",
        "status": "approved",
        "content_sha256": "seeded-approved-content",
        "approved_by": "incident-responder-202",
        "approved_at": "2026-10-19T00:00:00+00:00",
        "deployed_by": None,
        "deployed_at": None,
    }
    state_before = dict(reports_routes._rule_export_states[state_key])
    before = _database_snapshot(manager._db_path)

    with TestClient(app) as client:
        response = client.post(
            f"/api/reports/{analysis_id}/rules/kql/mark-deployed",
            json={},
        )

    assert response.status_code == 403
    assert _database_snapshot(manager._db_path) == before
    assert reports_routes._rule_export_states[state_key] == state_before
    reports_routes._rule_export_states.pop(state_key, None)


def test_team_lead_can_update_case_priority_and_assignee(tmp_path, monkeypatch) -> None:
    auth_db = tmp_path / "auth.db"
    _create_auth_db(auth_db)
    monkeypatch.setenv("AUTH_DB_PATH", str(auth_db))
    store = CaseStore(str(tmp_path / "cases.db"))
    case_id = store.create_case("Team Lead operations")

    app = FastAPI()
    app.state.case_store = store
    app.dependency_overrides[get_current_user] = lambda: _user(TEAM_LEAD, 900)
    app.include_router(cases_routes.router, prefix="/api/cases")

    with TestClient(app) as client:
        response = client.patch(
            f"/api/cases/{case_id}",
            json={"priority": "critical", "assignee": 202},
        )

    assert response.status_code == 200
    assert response.json()["priority"] == "critical"
    assert response.json()["assignee"] == 202
    assert store.get_case(case_id)["priority"] == "critical"
    assert store.get_case(case_id)["assignee"] == 202


@pytest.mark.parametrize(
    "payload",
    [{"priority": "critical"}, {"assignee": 202}],
    ids=["priority", "assignee"],
)
def test_soc_analyst_cannot_update_case_operations_without_database_change(
    tmp_path, monkeypatch, payload: dict
) -> None:
    auth_db = tmp_path / "auth.db"
    _create_auth_db(auth_db)
    monkeypatch.setenv("AUTH_DB_PATH", str(auth_db))
    store = CaseStore(str(tmp_path / "cases.db"))
    case_id = store.create_case("SOC denied operations")
    app = FastAPI()
    app.state.case_store = store
    app.dependency_overrides[get_current_user] = lambda: _user(SOC, 101)
    app.include_router(cases_routes.router, prefix="/api/cases")
    before = _database_snapshot(store._db_path)

    with TestClient(app) as client:
        response = client.patch(f"/api/cases/{case_id}", json=payload)

    assert response.status_code == 403
    assert _database_snapshot(store._db_path) == before


def _analysis_app(
    tmp_path: Path,
    role: str,
    user_id: int,
    *,
    include_agent_store: bool = True,
) -> tuple[FastAPI, AnalysisManager]:
    app = FastAPI()
    manager = AnalysisManager(str(tmp_path / "analysis_jobs.db"))
    app.state.analysis_manager = manager
    if include_agent_store:
        app.state.agent_store = AgentStore(str(tmp_path / "agent_store.db"))
    app.dependency_overrides[get_current_user] = lambda: _user(role, user_id)
    app.include_router(analysis_routes.router, prefix="/api/analysis")
    return app, manager


def _seed_analysis(manager: AnalysisManager, user_id: int, label: str) -> str:
    analysis_id = manager.create_job(
        "ioc",
        {"value": f"{label}.example"},
        user_id=user_id,
    )
    manager.complete_job(
        analysis_id,
        {"summary": f"analysis for {label}"},
        verdict="CLEAN",
        score=1,
    )
    return analysis_id


def test_team_lead_history_contains_active_soc_jobs_only(tmp_path, monkeypatch) -> None:
    auth_db = tmp_path / "auth.db"
    _create_auth_db(auth_db)
    monkeypatch.setenv("AUTH_DB_PATH", str(auth_db))
    app, manager = _analysis_app(tmp_path, TEAM_LEAD, 900)
    agent_store = app.state.agent_store
    active_soc = _seed_analysis(manager, 101, "active-soc")
    inactive_soc = _seed_analysis(manager, 102, "inactive-soc")
    other_role = _seed_analysis(manager, 201, "threat-hunter")
    team_lead_job = _seed_analysis(manager, 900, "team-lead")
    before = _database_snapshot(manager._db_path)

    with TestClient(app) as client:
        response = client.get("/api/analysis/history/")
        repeated_response = client.get("/api/analysis/history/")

    assert response.status_code == 200
    returned_ids = {item["id"] for item in response.json()["items"]}
    assert returned_ids == {active_soc}
    assert inactive_soc not in returned_ids
    assert other_role not in returned_ids
    assert team_lead_job not in returned_ids
    assert repeated_response.status_code == 200
    cross_reads = [
        entry
        for entry in agent_store.get_audit_log()
        if entry["action"] == "cross_user_read"
    ]
    assert len(cross_reads) == 2
    assert {entry["resource_id"] for entry in cross_reads} == {active_soc}
    assert all(entry["actor_role"] == TEAM_LEAD for entry in cross_reads)
    assert all(entry["target_user_id"] == 101 for entry in cross_reads)
    assert all(entry["resource_type"] == "analysis" for entry in cross_reads)
    assert _database_snapshot(manager._db_path) == before


@pytest.mark.parametrize(
    "owner_id,expected_status",
    [
        (101, 200),   # active SOC Analyst
        (102, 404),   # inactive SOC Analyst
        (201, 404),   # role outside the Team Lead scope
        (900, 404),   # Team Lead's own analysis is outside the SOC scope
    ],
    ids=["active-soc-visible", "inactive-soc-hidden", "other-role-hidden", "lead-own-hidden"],
)
def test_team_lead_analysis_result_obeys_active_soc_scope(
    tmp_path, monkeypatch, owner_id: int, expected_status: int
) -> None:
    auth_db = tmp_path / "auth.db"
    _create_auth_db(auth_db)
    monkeypatch.setenv("AUTH_DB_PATH", str(auth_db))
    app, manager = _analysis_app(tmp_path, TEAM_LEAD, 900)
    agent_store = app.state.agent_store
    analysis_id = _seed_analysis(manager, owner_id, f"owner-{owner_id}")
    before = _database_snapshot(manager._db_path)

    with TestClient(app) as client:
        response = client.get(f"/api/analysis/{analysis_id}")
        repeated_response = (
            client.get(f"/api/analysis/{analysis_id}")
            if owner_id == 101
            else None
        )

    assert response.status_code == expected_status
    if expected_status == 200:
        assert response.json()["id"] == analysis_id
        assert response.json()["summary"] == "analysis for owner-101"
        assert repeated_response is not None
        assert repeated_response.status_code == 200
        cross_reads = [
            entry
            for entry in agent_store.get_audit_log()
            if entry["action"] == "cross_user_read"
        ]
        assert len(cross_reads) == 2
        assert {entry["resource_id"] for entry in cross_reads} == {analysis_id}
        assert all(entry["actor_role"] == TEAM_LEAD for entry in cross_reads)
        assert all(entry["target_user_id"] == 101 for entry in cross_reads)
        assert all(entry["resource_type"] == "analysis" for entry in cross_reads)
    assert _database_snapshot(manager._db_path) == before


def test_team_lead_cross_user_analysis_read_fails_closed_without_agent_store(
    tmp_path, monkeypatch
) -> None:
    auth_db = tmp_path / "auth.db"
    _create_auth_db(auth_db)
    monkeypatch.setenv("AUTH_DB_PATH", str(auth_db))
    app, manager = _analysis_app(
        tmp_path,
        TEAM_LEAD,
        900,
        include_agent_store=False,
    )
    analysis_id = _seed_analysis(manager, 101, "active-soc-no-audit-store")
    before = _database_snapshot(manager._db_path)

    with TestClient(app) as client:
        response = client.get(f"/api/analysis/{analysis_id}")

    assert response.status_code == 503
    assert response.json()["detail"] == "Audit logging is unavailable"
    assert _database_snapshot(manager._db_path) == before


def test_soc_analyst_history_and_analysis_result_are_self_scoped(
    tmp_path, monkeypatch
) -> None:
    auth_db = tmp_path / "auth.db"
    _create_auth_db(auth_db)
    monkeypatch.setenv("AUTH_DB_PATH", str(auth_db))
    app, manager = _analysis_app(tmp_path, SOC, 101)
    own_analysis = _seed_analysis(manager, 101, "soc-own")
    peer_analysis = _seed_analysis(manager, 103, "soc-peer")
    other_role_analysis = _seed_analysis(manager, 201, "hunter")
    before = _database_snapshot(manager._db_path)

    with TestClient(app) as client:
        history = client.get("/api/analysis/history/")
        own_result = client.get(f"/api/analysis/{own_analysis}")
        peer_result = client.get(f"/api/analysis/{peer_analysis}")
        other_role_result = client.get(f"/api/analysis/{other_role_analysis}")

    assert history.status_code == 200
    assert {item["id"] for item in history.json()["items"]} == {own_analysis}
    assert own_result.status_code == 200
    assert peer_result.status_code == 404
    assert other_role_result.status_code == 404
    assert _database_snapshot(manager._db_path) == before

