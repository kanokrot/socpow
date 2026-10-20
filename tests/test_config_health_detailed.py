from __future__ import annotations

import asyncio
import json
import sqlite3
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.utils.api_key_validator import get_valid_key
from src.web import health_probes as hp
from src.web.auth import get_current_user
from src.web.routes import config_api


class _FakeApp:
    def __init__(self, **state):
        self.state = SimpleNamespace(**state)


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, *args, **kwargs):
        if self.error:
            raise self.error
        return self.response


def _api_app(user=None):
    app = FastAPI()
    app.include_router(config_api.router, prefix="/api/config")
    app.state.config = {"llm": {"provider": "vllm"}, "api_keys": {}}
    app.state.llm_analyzer = SimpleNamespace(
        provider="vllm",
        vllm_base_url=None,
        vllm_api_key=None,
        ollama_endpoint="http://localhost:11434",
        anthropic_key="",
    )
    app.state.mcp_client = None
    app.state.agent_store = None
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _run(coro):
    return asyncio.run(coro)


def test_detailed_route_requires_admin_and_returns_response(monkeypatch):
    payload = {
        "status": "healthy",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "version": "2.0.0",
        "uptime_seconds": 1.0,
        "cached": False,
        "checked_at": "2026-01-01T00:00:00+00:00",
        "duration_ms": 1.0,
        "summary": {"healthy": 1, "degraded": 0, "unhealthy": 0},
        "checks": {},
    }
    monkeypatch.setattr(config_api, "get_detailed_health", lambda *args, **kwargs: _async_value(payload))

    with TestClient(_api_app()) as client:
        assert client.get("/api/config/health/detailed").status_code == 401

    non_admin = {"id": 1, "email": "user@example.test", "role": "Threat Hunter", "is_active": 1}
    with TestClient(_api_app(non_admin)) as client:
        assert client.get("/api/config/health/detailed").status_code == 403

    admin = {"id": 1, "email": "admin@example.test", "role": "admin", "is_active": 1}
    with TestClient(_api_app(admin)) as client:
        response = client.get("/api/config/health/detailed")
        assert response.status_code == 200
        assert response.json() == payload


async def _async_value(value):
    return value


def test_old_health_endpoint_is_unchanged():
    admin = {"id": 1, "email": "admin@example.test", "role": "admin", "is_active": 1}
    with TestClient(_api_app(admin)) as client:
        response = client.get("/api/config/health")
    assert response.status_code == 200
    data = response.json()
    assert set(data) == {"status", "timestamp", "version"}
    assert data["status"] == "healthy"
    assert data["version"] == "2.0.0"


@pytest.mark.parametrize(
    ("checks", "expected"),
    [
        ({"sqlite": {"status": "unhealthy"}}, "unhealthy"),
        ({"mcp": {"status": "unhealthy"}}, "degraded"),
        ({"disk": {"status": "degraded"}}, "degraded"),
        ({"sqlite": {"status": "not_initialized"}}, "healthy"),
        ({"sqlite": {"status": "healthy"}, "mcp": {"status": "healthy"}}, "healthy"),
    ],
)
def test_aggregation_matrix(checks, expected):
    status, summary = hp.aggregate_status(checks)
    assert status == expected
    assert set(summary) == {"healthy", "degraded", "unhealthy"}


def test_vllm_probe_success_uses_models_endpoint_without_secrets(monkeypatch):
    fake_response = _FakeResponse(200)
    monkeypatch.setattr(hp.aiohttp, "ClientSession", lambda **kwargs: _FakeSession(fake_response))
    analyzer = SimpleNamespace(
        vllm_base_url="https://user:password@example.test/v1",
        vllm_api_key="fake-api-key-value",
    )
    result = _run(hp._probe_vllm(analyzer))
    assert result["status"] == "healthy"
    assert "example.test" not in str(result)
    assert "fake-api-key-value" not in str(result)


def test_vllm_probe_timeout_and_exception_are_sanitized(monkeypatch):
    analyzer = SimpleNamespace(vllm_base_url="https://example.test", vllm_api_key="secret-value")
    monkeypatch.setattr(
        hp.aiohttp,
        "ClientSession",
        lambda **kwargs: _FakeSession(error=asyncio.TimeoutError()),
    )
    timeout_result = _run(hp._probe_vllm(analyzer))
    assert timeout_result["status"] == "unhealthy"
    assert "TimeoutError" in timeout_result["error"]
    assert "secret-value" not in str(timeout_result)

    monkeypatch.setattr(
        hp.aiohttp,
        "ClientSession",
        lambda **kwargs: _FakeSession(error=RuntimeError("https://user:pass@example.test/private")),
    )
    exception_result = _run(hp._probe_vllm(analyzer))
    assert exception_result["status"] == "unhealthy"
    assert exception_result["error"] == "RuntimeError"


def test_ollama_probe_success_and_exception(monkeypatch):
    async def healthy(_endpoint):
        return {"ollama_running": True, "model_available": True, "configured_model": "mock"}

    monkeypatch.setattr(config_api, "_check_ollama_health", healthy)
    analyzer = SimpleNamespace(ollama_endpoint="http://localhost:11434")
    assert _run(hp._probe_ollama(analyzer))["status"] == "healthy"

    async def broken(_endpoint):
        raise TimeoutError()

    monkeypatch.setattr(config_api, "_check_ollama_health", broken)
    with pytest.raises(TimeoutError):
        _run(hp._probe_ollama(analyzer))
    wrapped = _run(hp._run_probe("llm", hp._probe_ollama(analyzer)))
    assert wrapped["status"] == "unhealthy"


def test_sqlite_missing_file_is_read_only(monkeypatch, tmp_path):
    missing = tmp_path / "missing.db"
    monkeypatch.setattr(hp, "_db_paths", lambda: {name: missing for name in hp._DB_NAMES})
    result = _run(hp._probe_sqlite())
    assert result["databases"]["auth"]["status"] == "not_initialized"
    assert not missing.exists()


def test_sqlite_real_file_probe_is_healthy_and_read_only(monkeypatch, tmp_path):
    db_path = tmp_path / "real.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE analysis_jobs (status TEXT)")
    connection.execute("INSERT INTO analysis_jobs VALUES ('queued')")
    connection.commit()
    connection.close()

    monkeypatch.setattr(hp, "_db_paths", lambda: {name: db_path for name in hp._DB_NAMES})
    result = _run(hp._probe_sqlite())

    assert len(result["databases"]) == 7
    assert "analysis_cache" not in result["databases"]
    assert result["databases"]["auth"]["status"] == "healthy"
    assert result["databases"]["analysis_jobs"]["status"] == "healthy"
    assert result["_analysis_counts"] == {"queued": 1}
    assert db_path.exists()


def _sqlite_result_for_statuses(monkeypatch, statuses):
    paths = {name: None for name in hp._DB_NAMES}

    def fake_probe(name, _path):
        return {
            "status": statuses.get(name, "healthy"),
            "summary": "mocked",
            "name": name,
            "tier": hp._DB_TIERS[name],
        }

    monkeypatch.setattr(hp, "_db_paths", lambda: paths)
    monkeypatch.setattr(hp, "_probe_one_database", fake_probe)
    return _run(hp._probe_sqlite())


@pytest.mark.parametrize(
    ("database", "status", "expected"),
    [
        ("ioc_cache", "not_initialized", "healthy"),
        ("agent", "not_initialized", "healthy"),
        ("auth", "not_initialized", "unhealthy"),
        ("ioc_cache", "degraded", "degraded"),
    ],
)
def test_sqlite_database_tiers_and_neutral_missing_files(
    monkeypatch, database, status, expected
):
    result = _sqlite_result_for_statuses(monkeypatch, {database: status})
    assert result["status"] == expected
    assert result["databases"][database]["tier"] == hp._DB_TIERS[database]
    if database == "ioc_cache" and status == "not_initialized":
        assert result["summary"] == "6 of 7 databases open, 1 not initialized (ioc_cache)"


def test_all_seven_sqlite_databases_healthy(monkeypatch):
    result = _sqlite_result_for_statuses(monkeypatch, {})
    assert result["status"] == "healthy"
    assert hp.aggregate_status({"sqlite": result})[0] == "healthy"
    assert len(result["databases"]) == 7
    assert "analysis_cache" not in result["databases"]
    assert {name: item["tier"] for name, item in result["databases"].items()} == {
        "auth": "critical",
        "analysis_jobs": "critical",
        "agent": "important",
        "agent_memory": "important",
        "cases": "important",
        "ioc_cache": "optional",
        "tickets": "important",
    }


def test_concurrent_probe_latency_is_per_probe():
    async def slow_probe():
        await asyncio.sleep(0.1)
        return {"status": "healthy", "summary": "slow"}

    async def instant_probe():
        return {"status": "healthy", "summary": "instant"}

    async def run_probes():
        return await asyncio.gather(
            hp._run_probe("llm", slow_probe()),
            hp._run_probe("mcp", instant_probe()),
        )

    slow, instant = _run(run_probes())
    assert slow["latency_ms"] >= 75
    assert instant["latency_ms"] < slow["latency_ms"] / 2


def test_run_probe_preserves_probe_latency():
    async def fake_probe():
        await asyncio.sleep(0.05)
        return {"status": "healthy", "summary": "x", "latency_ms": 1.2}

    result = _run(hp._run_probe("llm", fake_probe()))
    assert result["latency_ms"] == 1.2


def test_sqlite_success_and_exception_are_mocked(monkeypatch, tmp_path):
    db_path = tmp_path / "ok.db"
    import sqlite3

    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE analysis_jobs (status TEXT)")
    connection.execute("INSERT INTO analysis_jobs VALUES ('queued')")
    connection.commit()
    connection.close()
    monkeypatch.setattr(hp, "_db_paths", lambda: {name: db_path for name in hp._DB_NAMES})
    result = _run(hp._probe_sqlite())
    assert result["databases"]["auth"]["status"] == "healthy"
    assert result["_analysis_counts"] == {"queued": 1}

    monkeypatch.setattr(hp, "_db_paths", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    wrapped = _run(hp._run_probe("sqlite", hp._probe_sqlite()))
    assert wrapped["status"] == "unhealthy"
    assert "RuntimeError" in wrapped["error"]


@pytest.mark.parametrize(
    "message",
    [
        "Cannot connect to host 10.1.2.3:8000 ssl:default",
        "Bearer eyJabc",
        "src/db/auth.db",
        r"\\server\share\x.db",
        "Authorization: abc",
        "sk-abc123",
        "http://user:pass@host/x",
        r"D:\secret\path.db",
    ],
)
def test_safe_error_allowlist_redacts_unapproved_messages(message):
    result = hp._safe_error(RuntimeError(message))
    assert result == "RuntimeError"
    assert message not in result


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("timed out", "RuntimeError: timed out"),
        (" database is locked ", "RuntimeError: database is locked"),
        ("Unable to open database file", "RuntimeError: Unable to open database file"),
    ],
)
def test_safe_error_allowlist_preserves_safe_phrases(message, expected):
    assert hp._safe_error(RuntimeError(message)) == expected


def test_detailed_endpoint_serializes_no_credentials(monkeypatch):
    admin = {"id": 1, "email": "admin@example.test", "role": "admin", "is_active": 1}
    app = _api_app(admin)
    app.state.config = {
        "llm": {
            "provider": "vllm",
            "vllm_base_url": "https://user:password@example.test/v1",
            "vllm_api_key": "fake-vllm-key",
        },
        "api_keys": {
            "virustotal": "fake-virustotal-key",
            "shodan": "fake-shodan-key",
        },
    }

    async def healthy(_value):
        return {"status": "healthy", "summary": "mocked"}

    async def healthy_no_args():
        return {"status": "healthy", "summary": "mocked"}

    async def sqlite():
        return {"status": "healthy", "summary": "mocked", "_analysis_counts": {}}

    async def chroma(_app):
        return {"status": "not_loaded", "summary": "mocked"}

    async def mcp(_app):
        return {"status": "not_initialized", "summary": "mocked"}

    async def threat_intel(_app):
        return {"status": "healthy", "summary": "mocked", "sources": {"virustotal": True}}

    async def background(_counts, _agent):
        return {"status": "healthy", "summary": "mocked"}

    monkeypatch.setattr(hp, "_probe_ollama", healthy)
    monkeypatch.setattr(hp, "_probe_vllm", healthy)
    monkeypatch.setattr(hp, "_probe_sqlite", sqlite)
    monkeypatch.setattr(hp, "_probe_chromadb", chroma)
    monkeypatch.setattr(hp, "_probe_mcp", mcp)
    monkeypatch.setattr(hp, "_probe_threat_intel", threat_intel)
    monkeypatch.setattr(hp, "_probe_disk", healthy_no_args)
    monkeypatch.setattr(hp, "_probe_background", background)
    hp.clear_cache()

    with TestClient(app) as client:
        response = client.get("/api/config/health/detailed?refresh=true")

    serialized = json.dumps(response.json())
    assert response.status_code == 200
    for secret in (
        "user:password@example.test",
        "fake-vllm-key",
        "fake-virustotal-key",
        "fake-shodan-key",
    ):
        assert secret not in serialized


def test_chromadb_mcp_threat_background_and_disk_probes(monkeypatch, tmp_path):
    rag = SimpleNamespace(status=lambda: {"collection": "socpow_knowledge_base", "document_count": 3})
    mcp = SimpleNamespace(
        get_connection_status=lambda: {"one": {"connected": True, "tool_count": 2}}
    )
    agent = SimpleNamespace(get_agent_stats=lambda: {"failed_sessions": 1})
    app = _FakeApp(
        rag_knowledge_base=rag,
        mcp_client=mcp,
        agent_store=agent,
        config={"api_keys": {"virustotal": "fake-valid-key"}},
    )
    assert _run(hp._probe_chromadb(app))["status"] == "healthy"
    assert _run(hp._probe_mcp(app))["connected"] == 1
    threat = _run(hp._probe_threat_intel(app))
    assert threat["sources"]["virustotal"] is True
    assert "fake-valid-key" not in str(threat)
    background = _run(hp._probe_background({"queued": 2}, agent))
    assert background["jobs"]["queued"] == 2
    assert _run(hp._probe_disk())["status"] in {"healthy", "degraded"}

    monkeypatch.setattr(rag, "status", lambda: (_ for _ in ()).throw(RuntimeError("bad")))
    assert _run(hp._probe_chromadb(app))["status"] == "unhealthy"
    monkeypatch.setattr(mcp, "get_connection_status", lambda: (_ for _ in ()).throw(RuntimeError("bad")))
    assert _run(hp._probe_mcp(app))["status"] == "unhealthy"


def test_background_exception_is_informational():
    agent = SimpleNamespace(get_agent_stats=lambda: (_ for _ in ()).throw(RuntimeError("bad")))
    result = _run(hp._probe_background({}, agent))
    assert result["status"] == "healthy"
    assert result["agent_sessions"]["status"] == "unknown"


def test_cache_ttl_and_refresh_interval(monkeypatch):
    hp.clear_cache()
    clock = {"value": 100.0}
    monkeypatch.setattr(hp.time, "monotonic", lambda: clock["value"])
    calls = {"count": 0}

    async def collect(_app, _started_at):
        calls["count"] += 1
        return {
            "status": "healthy",
            "timestamp": "now",
            "version": "2.0.0",
            "uptime_seconds": 1,
            "cached": False,
            "checked_at": "now",
            "duration_ms": 1,
            "summary": {"healthy": 1, "degraded": 0, "unhealthy": 0},
            "checks": {},
        }

    monkeypatch.setattr(hp, "_collect_once", collect)
    app = _FakeApp()
    first = _run(hp.get_detailed_health(app))
    second = _run(hp.get_detailed_health(app))
    assert first["cached"] is False
    assert second["cached"] is True
    assert calls["count"] == 1

    clock["value"] = 102.0
    limited = _run(hp.get_detailed_health(app, refresh=True))
    assert limited["cached"] is True
    assert calls["count"] == 1

    clock["value"] = 106.0
    refreshed = _run(hp.get_detailed_health(app, refresh=True))
    assert refreshed["cached"] is False
    assert calls["count"] == 2


def test_api_key_helper_only_returns_boolean_for_health_use():
    keys = {"virustotal": "fake-valid-key"}
    assert bool(get_valid_key(keys, "virustotal")) is True
    assert bool(get_valid_key(keys, "shodan")) is False
