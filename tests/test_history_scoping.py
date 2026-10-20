"""History page visibility tests."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import page_auth
from src.web import app as web_app
from src.web.analysis_manager import AnalysisManager
from src.web.auth import get_current_user
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware
from src.web.routes import analysis as analysis_routes


SOC = "SOC Analyst Tier 1-2"
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


def _page_app(tmp_path) -> FastAPI:
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    app.state.analysis_manager = AnalysisManager(
        db_path=str(tmp_path / "analysis_jobs.db")
    )
    _register_page_routes(app)
    return app


def _seed_jobs(manager: AnalysisManager) -> None:
    manager.create_job("ioc", {"value": "analyst-target"}, user_id=101)
    manager.create_job("ioc", {"value": "other-target"}, user_id=202)
    manager.create_job("ioc", {"value": "outside-team-target"}, user_id=303)


def _client_for_page(app: FastAPI, monkeypatch, user: dict) -> TestClient:
    monkeypatch.setattr(
        page_auth,
        "get_current_user",
        lambda token, request=None: user,
    )
    client = TestClient(app)
    client.cookies.set("socpow_session", "test-token")
    return client


def _summary_app(tmp_path, user: dict | None = None) -> FastAPI:
    app = _page_app(tmp_path)
    app.state.agent_store = SimpleNamespace(
        add_cross_user_read_audit=lambda **kwargs: "audit-id"
    )
    app.include_router(analysis_routes.router, prefix="/api/analysis")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _seed_summary_jobs(manager: AnalysisManager) -> None:
    for user_id, prefix in ((101, "analyst-a"), (202, "analyst-b"), (303, "team-lead")):
        phishing = manager.create_job("email", {"filename": f"{prefix}-phishing.eml"}, user_id=user_id)
        spam = manager.create_job("email", {"filename": f"{prefix}-spam.eml"}, user_id=user_id)
        failed = manager.create_job("file", {"filename": f"{prefix}-failed.bin"}, user_id=user_id)
        manager.create_job("ioc", {"value": f"{prefix}-queued"}, user_id=user_id)
        manager.complete_job(phishing, {}, verdict="PHISHING", score=90)
        manager.complete_job(spam, {}, verdict="SPAM", score=60)
        manager.fail_job(failed, "timeout")

    clean = manager.create_job("file", {"filename": "analyst-a-clean.txt"}, user_id=101)
    unknown = manager.create_job("ioc", {"value": "analyst-a-unknown"}, user_id=101)
    manager.complete_job(clean, {}, verdict="CLEAN", score=5)
    manager.complete_job(unknown, {}, verdict="UNKNOWN", score=0)


def _assert_summary_shape(response, expected: dict) -> None:
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {
        "total",
        "malicious",
        "suspicious",
        "clean",
        "unknown",
        "failed",
        "in_progress",
    }
    assert "analysis_type" not in payload
    assert payload == expected


def test_analyst_history_page_contains_own_job_only(tmp_path, monkeypatch) -> None:
    app = _page_app(tmp_path)
    _seed_jobs(app.state.analysis_manager)

    with _client_for_page(app, monkeypatch, _user(SOC, 101)) as client:
        response = client.get("/history")

    assert response.status_code == 200
    assert 'id="historyPage"' in response.text
    assert 'id="historyLoading"' in response.text
    assert 'id="historyError"' in response.text
    assert 'id="tb"' in response.text
    assert "analyst-target" not in response.text
    assert "other-target" not in response.text
    assert "outside-team-target" not in response.text


def test_admin_history_page_contains_all_jobs(tmp_path, monkeypatch) -> None:
    app = _page_app(tmp_path)
    _seed_jobs(app.state.analysis_manager)

    with _client_for_page(app, monkeypatch, _user(ADMIN, 900)) as client:
        response = client.get("/history")

    assert response.status_code == 200
    assert 'id="historyPage"' in response.text
    assert 'id="historyLoading"' in response.text
    assert 'id="historyError"' in response.text
    assert 'id="tb"' in response.text
    assert "analyst-target" not in response.text
    assert "other-target" not in response.text
    assert "outside-team-target" not in response.text


def test_team_lead_history_page_contains_analyst_jobs_only(tmp_path, monkeypatch) -> None:
    app = _page_app(tmp_path)
    _seed_jobs(app.state.analysis_manager)
    monkeypatch.setattr(web_app, "get_user_ids_by_role", lambda role: [101, 202])

    with _client_for_page(app, monkeypatch, _user(TEAM_LEAD, 900)) as client:
        response = client.get("/history")

    assert response.status_code == 200
    assert 'id="historyPage"' in response.text
    assert 'id="historyLoading"' in response.text
    assert 'id="historyError"' in response.text
    assert 'id="tb"' in response.text
    assert "analyst-target" not in response.text
    assert "other-target" not in response.text
    assert "outside-team-target" not in response.text


def test_unauthenticated_history_page_keeps_normal_redirect(tmp_path) -> None:
    with TestClient(_page_app(tmp_path)) as client:
        response = client.get("/history", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2Fhistory"


def test_history_summary_admin_sees_all_users(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    _seed_summary_jobs(app.state.analysis_manager)

    with TestClient(app) as client:
        response = client.get("/api/analysis/history/summary")

    _assert_summary_shape(
        response,
        {
            "total": 14,
            "malicious": 3,
            "suspicious": 3,
            "clean": 1,
            "unknown": 1,
            "failed": 3,
            "in_progress": 3,
        },
    )


def test_history_summary_team_lead_sees_analysts_only(tmp_path, monkeypatch) -> None:
    app = _summary_app(tmp_path, _user(TEAM_LEAD, 303))
    _seed_summary_jobs(app.state.analysis_manager)
    monkeypatch.setattr(analysis_routes, "get_user_ids_by_role", lambda role: [101, 202])

    with TestClient(app) as client:
        response = client.get("/api/analysis/history/summary")

    # Mirrors /api/analysis/history/: Team Leads see analyst jobs, not their own jobs.
    _assert_summary_shape(
        response,
        {
            "total": 10,
            "malicious": 2,
            "suspicious": 2,
            "clean": 1,
            "unknown": 1,
            "failed": 2,
            "in_progress": 2,
        },
    )


def test_history_summary_analyst_sees_own_jobs_only(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(SOC, 101))
    _seed_summary_jobs(app.state.analysis_manager)

    with TestClient(app) as client:
        response = client.get("/api/analysis/history/summary")

    _assert_summary_shape(
        response,
        {
            "total": 6,
            "malicious": 1,
            "suspicious": 1,
            "clean": 1,
            "unknown": 1,
            "failed": 1,
            "in_progress": 1,
        },
    )


def test_history_summary_unauthenticated_gets_normal_api_denial(tmp_path) -> None:
    with TestClient(_summary_app(tmp_path)) as client:
        response = client.get("/api/analysis/history/summary")

    assert response.status_code == 401


def _history_response(client: TestClient, **params) -> dict:
    response = client.get("/api/analysis/history/", params=params)
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"items", "total", "limit", "offset"}
    return payload


def _assert_history_summary_equivalence(client: TestClient) -> None:
    summary_response = client.get("/api/analysis/history/summary")
    assert summary_response.status_code == 200
    summary = summary_response.json()
    groups = ("malicious", "suspicious", "clean", "unknown", "failed", "in_progress")
    counts = {
        group: _history_response(client, group=group)["total"]
        for group in groups
    }
    assert counts == {group: summary[group] for group in groups}
    assert sum(counts.values()) == summary["total"]


def test_history_list_group_totals_equal_summary_for_admin(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    _seed_summary_jobs(app.state.analysis_manager)

    with TestClient(app) as client:
        _assert_history_summary_equivalence(client)


def test_history_list_group_totals_equal_summary_for_team_lead(tmp_path, monkeypatch) -> None:
    app = _summary_app(tmp_path, _user(TEAM_LEAD, 303))
    _seed_summary_jobs(app.state.analysis_manager)
    monkeypatch.setattr(analysis_routes, "get_user_ids_by_role", lambda role: [101, 202])

    with TestClient(app) as client:
        _assert_history_summary_equivalence(client)


def test_history_list_group_totals_equal_summary_for_analyst(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(SOC, 101))
    _seed_summary_jobs(app.state.analysis_manager)

    with TestClient(app) as client:
        _assert_history_summary_equivalence(client)


def test_history_list_type_and_q_filters_match_target_id_and_type(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    manager = app.state.analysis_manager
    target_job = manager.create_job("ioc", {"value": "literal-target"}, user_id=101)
    manager.create_job("file", {"filename": "other-target.bin"}, user_id=101)

    with TestClient(app) as client:
        assert _history_response(client, type="ioc")["total"] == 1
        assert _history_response(client, q="literal-target")["total"] == 1
        assert _history_response(client, q=target_job)["total"] == 1
        assert _history_response(client, q="file")["total"] == 1
        assert _history_response(client, q="literal_%")["total"] == 0


def test_history_list_date_ranges_use_created_at(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    manager = app.state.analysis_manager
    old_job = manager.create_job("ioc", {"value": "old"}, user_id=101)
    week_job = manager.create_job("ioc", {"value": "week"}, user_id=101)
    recent_job = manager.create_job("ioc", {"value": "recent"}, user_id=101)
    now = datetime.now(timezone.utc)
    with sqlite3.connect(str(manager._db_path)) as connection:
        connection.executemany(
            "UPDATE analysis_jobs SET created_at = ? WHERE id = ?",
            [
                ((now - timedelta(days=8)).isoformat(), old_job),
                ((now - timedelta(days=2)).isoformat(), week_job),
                ((now - timedelta(hours=2)).isoformat(), recent_job),
            ],
        )
        connection.commit()

    with TestClient(app) as client:
        assert _history_response(client, range="all")["total"] == 3
        assert _history_response(client, range="7d")["total"] == 2
        assert _history_response(client, range="24h")["total"] == 1


def test_history_list_sort_and_order_support_all_sort_keys(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    manager = app.state.analysis_manager
    date_old = manager.create_job("email", {"filename": "old"}, user_id=101)
    date_new = manager.create_job("file", {"filename": "new"}, user_id=101)
    score_low = manager.create_job("ioc", {"value": "low"}, user_id=101)
    score_high = manager.create_job("ioc", {"value": "high"}, user_id=101)
    malicious = manager.create_job("ioc", {"value": "malicious"}, user_id=101)
    suspicious = manager.create_job("ioc", {"value": "suspicious"}, user_id=101)
    clean = manager.create_job("ioc", {"value": "clean"}, user_id=101)
    unknown = manager.create_job("ioc", {"value": "unknown"}, user_id=101)
    failed = manager.create_job("ioc", {"value": "failed"}, user_id=101)
    queued = manager.create_job("ioc", {"value": "queued"}, user_id=101)
    manager.complete_job(score_low, {}, verdict="CLEAN", score=10)
    manager.complete_job(score_high, {}, verdict="CLEAN", score=90)
    manager.complete_job(malicious, {}, verdict="PHISHING", score=1)
    manager.complete_job(suspicious, {}, verdict="SPAM", score=2)
    manager.complete_job(clean, {}, verdict="CLEAN", score=3)
    manager.complete_job(unknown, {}, verdict="UNKNOWN", score=4)
    manager.fail_job(failed, "failed")
    with sqlite3.connect(str(manager._db_path)) as connection:
        connection.executemany(
            "UPDATE analysis_jobs SET created_at = ? WHERE id = ?",
            [
                ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(), date_old),
                ((datetime.now(timezone.utc) + timedelta(days=1)).isoformat(), date_new),
            ],
        )
        connection.commit()

    with TestClient(app) as client:
        date_items = _history_response(client, sort="date", order="asc")["items"]
        assert date_items[0]["id"] == date_old
        assert date_items[-1]["id"] == date_new
        date_desc = _history_response(client, sort="date", order="desc")["items"]
        assert date_desc[0]["id"] == date_new
        score_items = _history_response(
            client, sort="score", order="asc", group="clean"
        )["items"]
        assert score_items[0]["id"] == clean
        score_desc = _history_response(client, sort="score", order="desc")["items"]
        assert score_desc[0]["id"] == score_high
        verdict_items = _history_response(client, sort="verdict", order="asc")["items"]
        verdict_order = [
            "malicious", "suspicious", "clean", "unknown", "failed", "in_progress"
        ]
        assert list(dict.fromkeys(item["verdict_group"] for item in verdict_items)) == verdict_order
        verdict_desc = _history_response(client, sort="verdict", order="desc")["items"]
        assert list(dict.fromkeys(item["verdict_group"] for item in verdict_desc)) == list(reversed(verdict_order))
        type_items = _history_response(client, sort="type", order="asc")["items"]
        type_desc = _history_response(client, sort="type", order="desc")["items"]
        assert type_items[0]["analysis_type"] == "email"
        assert type_desc[0]["analysis_type"] == "ioc"
        status_items = _history_response(client, sort="status", order="asc")["items"]
        status_desc = _history_response(client, sort="status", order="desc")["items"]
        assert status_items[0]["status"] == "completed"
        assert status_desc[0]["status"] == "running" or status_desc[0]["status"] == "queued"


def test_history_list_score_sort_puts_nulls_last_for_both_orders(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    manager = app.state.analysis_manager
    low = manager.create_job("ioc", {"value": "score-low"}, user_id=101)
    high = manager.create_job("ioc", {"value": "score-high"}, user_id=101)
    queued = manager.create_job("ioc", {"value": "score-queued"}, user_id=101)
    failed = manager.create_job("ioc", {"value": "score-failed"}, user_id=101)
    manager.complete_job(low, {}, verdict="CLEAN", score=10)
    manager.complete_job(high, {}, verdict="CLEAN", score=90)
    manager.fail_job(failed, "failed")

    with TestClient(app) as client:
        asc = _history_response(client, sort="score", order="asc")["items"]
        desc = _history_response(client, sort="score", order="desc")["items"]

    assert [item.get("score") for item in asc[:2]] == [10, 90]
    assert all(item.get("score") is None for item in asc[2:])
    assert {item["id"] for item in asc[2:]} == {queued, failed}
    assert [item.get("score") for item in desc[:2]] == [90, 10]
    assert all(item.get("score") is None for item in desc[2:])
    assert {item["id"] for item in desc[2:]} == {queued, failed}


def test_history_list_pagination_validation_and_legacy_status(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    manager = app.state.analysis_manager
    failed = manager.create_job("ioc", {"value": "failed"}, user_id=101)
    manager.create_job("ioc", {"value": "queued"}, user_id=101)
    manager.fail_job(failed, "failed")

    with TestClient(app) as client:
        assert _history_response(client, limit=1)["total"] == 2
        beyond = _history_response(client, limit=1, offset=2)
        assert beyond["total"] == 2
        assert beyond["items"] == []
        assert _history_response(client, status="failed")["total"] == 1
        assert client.get("/api/analysis/history/", params={"limit": 101}).status_code == 422
        assert client.get("/api/analysis/history/", params={"limit": 0}).status_code == 422
        for key, value in (
            ("group", "bad"),
            ("type", "bad"),
            ("range", "bad"),
            ("sort", "bad"),
            ("order", "bad"),
        ):
            assert client.get("/api/analysis/history/", params={key: value}).status_code == 422


def test_history_list_invalid_json_row_is_searchable_by_id(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    manager = app.state.analysis_manager
    job_id = manager.create_job("ioc", {"value": "valid"}, user_id=101)
    with sqlite3.connect(str(manager._db_path)) as connection:
        connection.execute(
            "UPDATE analysis_jobs SET params = ? WHERE id = ?",
            ("{invalid-json", job_id),
        )
        connection.commit()

    with TestClient(app) as client:
        payload = _history_response(client, q=job_id)
        assert payload["total"] == 1
        assert payload["items"][0]["id"] == job_id


def test_history_list_filters_keep_role_scoping(tmp_path, monkeypatch) -> None:
    app = _summary_app(tmp_path, _user(SOC, 101))
    _seed_jobs(app.state.analysis_manager)
    with TestClient(app) as client:
        analyst_payload = _history_response(client)
    assert [item["id"] for item in analyst_payload["items"]] == [
        app.state.analysis_manager.list_jobs(user_id=101)[0]["id"]
    ]

    lead_app = _summary_app(tmp_path / "lead", _user(TEAM_LEAD, 900))
    _seed_jobs(lead_app.state.analysis_manager)
    monkeypatch.setattr(analysis_routes, "get_user_ids_by_role", lambda role: [101, 202])
    with TestClient(lead_app) as client:
        lead_payload = _history_response(client)
    assert lead_payload["total"] == 2

    admin_app = _summary_app(tmp_path / "admin", _user(ADMIN, 900))
    _seed_jobs(admin_app.state.analysis_manager)
    with TestClient(admin_app) as client:
        assert _history_response(client)["total"] == 3
