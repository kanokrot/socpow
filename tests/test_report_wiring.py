"""
Regression tests for HTML report generation wiring in playbook_engine.py
(Flow C). Locks in behavior verified manually in adhoc script
scripts/adhoc/verify_report_wiring.py — see SOCPOW session notes.
"""
import pytest

from src.agent.playbook_engine import PlaybookEngine
from src.agent.agent_store import AgentStore
from src.web.visibility import serialize_agent_session, serialize_chat_session


def test_serialize_agent_session_reports_only_has_report_boolean():
    full_report = {"ioc": "evil.example", "verdict": "MALICIOUS", "secret": "not exposed"}

    serialized = serialize_agent_session({
        "id": "session-with-report",
        "metadata": {"ioc_investigation_result": full_report},
    })

    assert serialized["has_report"] is True
    assert "metadata" not in serialized
    assert "ioc_investigation_result" not in serialized
    assert "not exposed" not in repr(serialized)


@pytest.mark.parametrize(
    "session",
    [
        {"id": "session-without-metadata"},
        {"id": "session-with-null-metadata", "metadata": None},
        {"id": "session-with-invalid-metadata", "metadata": "not-a-dict"},
    ],
)
def test_serialize_agent_session_has_report_false_without_mapping_metadata(session):
    serialized = serialize_agent_session(session)

    assert serialized["has_report"] is False


def test_serialize_chat_session_includes_has_report_boolean():
    serialized = serialize_chat_session({
        "id": "chat-session",
        "metadata": {"ioc_investigation_result": {"verdict": "CLEAN"}},
    })

    assert serialized["has_report"] is True


class _DummyCfg:
    def __init__(self, output_cfg):
        self._output_cfg = output_cfg

    def get(self, key, default=None):
        if key == "output":
            return self._output_cfg
        return default if default is not None else {}


class _DummyAgentLoop:
    def __init__(self, mock_result, report_dir):
        self.mock_result = mock_result
        self.config = _DummyCfg({"save_reports": True, "report_dir": report_dir})

    async def run_tool(self, tool_name, params):
        if tool_name == "investigate_ioc":
            return self.mock_result
        return {"ok": True, "tool": tool_name}

    def _notify(self, session_id, payload):
        pass


@pytest.fixture
def report_dir(tmp_path):
    d = tmp_path / "reports"
    d.mkdir()
    return str(d)


async def _run_playbook(mock_result, report_dir, tmp_path, label):
    db_path = str(tmp_path / f"{label}.db")
    agent_loop = _DummyAgentLoop(mock_result, report_dir)
    store = AgentStore(db_path=db_path)
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)

    pid = engine.register_playbook(
        name=f"report_wiring_test_{label}",
        description="report wiring regression test",
        steps=[
            {
                "name": "threat_intel_lookup",
                "tool": "investigate_ioc",
                "params": {"ioc": "{{ioc}}"},
            },
            {"name": "document", "action": "final_answer", "description": "done"},
        ],
    )

    session_id = await engine.execute(pid, {"ioc": mock_result.get("ioc", "unknown")})

    conn = store._connect()
    cur = conn.execute(
        "SELECT status, summary FROM agent_sessions WHERE id=?", (session_id,)
    )
    row = cur.fetchone()
    conn.close()
    session = store.get_session(session_id)

    return session_id, row, session


@pytest.mark.asyncio
async def test_malicious_ioc_generates_report(tmp_path, report_dir):
    mock_result = {
        "ioc": "50.16.16.211", "ioc_type": "ip",
        "threat_score": 85, "verdict": "MALICIOUS",
        "sources": {"virustotal": {"detections": "12/70"}},
    }
    _, row, session = await _run_playbook(
        mock_result, report_dir, tmp_path, "malicious"
    )

    assert row is not None
    status, summary = row
    assert status == "completed"
    assert "report data available" in summary

    metadata = session["metadata"]
    assert metadata["ioc_investigation_result"]["verdict"] == "MALICIOUS"
    assert metadata["ioc_investigation_result"]["ioc"] == "50.16.16.211"
    assert metadata["report_envelope"]["ioc_investigation"] == metadata["ioc_investigation_result"]


@pytest.mark.asyncio
async def test_clean_ioc_generates_report(tmp_path, report_dir):
    mock_result = {
        "ioc": "8.8.8.8", "ioc_type": "ip",
        "threat_score": 0, "verdict": "CLEAN",
        "sources": {},
    }
    _, row, session = await _run_playbook(
        mock_result, report_dir, tmp_path, "clean"
    )

    assert row is not None
    status, summary = row
    assert status == "completed"
    assert "report data available" in summary

    metadata = session["metadata"]
    assert metadata["ioc_investigation_result"]["verdict"] == "CLEAN"
    assert metadata["report_envelope"]["ioc_investigation"] == metadata["ioc_investigation_result"]


@pytest.mark.asyncio
async def test_report_failure_does_not_fail_session(tmp_path, report_dir):
    """Malformed report data is persisted without generating HTML during
    playbook completion. Any generation failure now occurs only when the
    report endpoint is requested."""
    mock_result = {
        "ioc": "evil.example", "ioc_type": "domain",
        "threat_score": 90, "verdict": "MALICIOUS",
        "sources": "THIS_SHOULD_BE_A_DICT_NOT_A_STRING",  # forces internal AttributeError
    }
    _, row, session = await _run_playbook(
        mock_result, report_dir, tmp_path, "malformed_sources"
    )

    assert row is not None
    status, summary = row
    assert status == "completed", (
        "malformed report data must not fail the whole playbook session"
    )
    assert "report data available" in summary
    assert "highest verdict: MALICIOUS" in summary  # verdict/ticketing unaffected
    assert session["metadata"]["ioc_investigation_result"] == mock_result
    assert session["metadata"]["report_envelope"]["ioc_investigation"] == mock_result


def test_report_endpoint_returns_500_on_generation_failure(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.web.routes import playbooks as playbook_routes

    store = AgentStore(db_path=str(tmp_path / "report_endpoint.db"))
    session_id = store.create_session(goal="Malformed report endpoint test")
    store.update_session_metadata(session_id, {
        "ioc_investigation_result": {
            "ioc": "evil.example",
            "ioc_type": "domain",
            "threat_score": 90,
            "verdict": "MALICIOUS",
            "sources": "THIS_SHOULD_BE_A_DICT_NOT_A_STRING",
        },
        "ioc": "evil.example",
    })

    app = FastAPI()
    from src.web.auth import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1,
        "email": "admin@example.test",
        "username": "admin",
        "role": "admin",
        "is_active": 1,
    }
    app.state.agent_store = store
    app.include_router(playbook_routes.router, prefix="/api/playbooks")
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get(f"/api/playbooks/sessions/{session_id}/report")

    assert response.status_code == 500
