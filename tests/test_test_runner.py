from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.routes import test_runner as runner
from src.web.app import _register_page_routes


@pytest.fixture(autouse=True)
def reset_runner_state():
    with runner._state_lock:
        runner._collection.update(status="empty", files=[], info={}, updated_at=None, output=[])
        runner._collection.pop("process", None)
        runner._run = None
        runner._run_process = None
        if runner._run_lock.locked():
            runner._run_lock.release()
    yield
    with runner._state_lock:
        runner._collection.update(status="empty", files=[], info={}, updated_at=None, output=[])
        runner._collection.pop("process", None)
        runner._run = None
        runner._run_process = None
        if runner._run_lock.locked():
            runner._run_lock.release()


def _client(role="admin"):
    app = FastAPI()
    app.include_router(runner.router, prefix="/api/tests")
    app.dependency_overrides[get_current_user] = lambda: {"id": 1, "role": role}
    return TestClient(app)


def _ready_collection():
    with runner._state_lock:
        runner._collection.update(status="ready", files=[
            {"path": "tests/test_example.py", "nodeids": [
                "tests/test_example.py::test_one", "tests/test_example.py::TestGroup::test_two",
            ], "count": 2, "selectable": True},
            {"path": "tests/test_broken.py", "nodeids": [], "count": 0,
             "error": "missing dependency", "selectable": False},
        ])


class _FakeStdout:
    def __init__(self, lines=(), block=False):
        self.lines = list(lines)
        self.block = block
        self.release = asyncio.Event()

    async def readline(self):
        if self.lines:
            return self.lines.pop(0)
        if self.block:
            await self.release.wait()
            return b""
        return b""


class _FakeProcess:
    pid = 123

    def __init__(self, lines=(), block=False, returncode=0):
        self.stdout = _FakeStdout(lines, block)
        self.returncode = returncode

    async def wait(self):
        return self.returncode or 0


def test_non_admin_is_forbidden_and_admin_can_read_status():
    with _client("SOC Analyst Tier 1-2") as client:
        assert client.get("/api/tests/status").status_code == 403
    with _client("admin") as client:
        response = client.get("/api/tests/status")
    assert response.status_code == 200
    assert response.json()["status"] == "empty"


@pytest.mark.parametrize(("role", "expected"), [("admin", 200), ("Team Lead", 403)])
def test_test_runner_page_is_admin_only(role, expected):
    app = FastAPI()
    _register_page_routes(app)
    app.dependency_overrides[get_current_user] = lambda: {"id": 1, "role": role}
    with TestClient(app) as client:
        response = client.get("/tests")
    assert response.status_code == expected
    if expected == 200:
        assert "Test Runner" in response.text


@pytest.mark.parametrize("target", [
    "tests/test_unknown.py::test_missing",
    "-k",
    "tests/test_example.py; echo bad",
    "tests/test_example.py && whoami",
])
def test_unrecognized_or_option_like_targets_are_rejected(target):
    _ready_collection()
    with _client() as client:
        response = client.post("/api/tests/start", json={"mode": "selected", "targets": [target]})
    assert response.status_code == 422


def test_admin_can_start_and_argv_has_fixed_prefix_and_validated_targets(monkeypatch):
    _ready_collection()
    captured = {}

    async def fake_spawn(argv):
        captured["argv"] = argv
        junit_path = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--junitxml="))
        Path(junit_path).write_text(
            '<testsuite><testcase classname="tests.test_example" name="test_one" time="0.2"/></testsuite>',
            encoding="utf-8",
        )
        return _FakeProcess([b"collected output\n"])

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    with _client() as client:
        response = client.post("/api/tests/start", json={
            "mode": "selected", "targets": ["tests/test_example.py::test_one"],
        })
        assert response.status_code == 200
        for _ in range(30):
            state = client.get("/api/tests/status").json()
            if state["status"] not in {"running", "starting"}:
                break
            import time
            time.sleep(0.01)

    argv = captured["argv"]
    assert argv[:4] == [runner.sys.executable, "-m", "pytest", "-v"]
    assert argv[4].startswith("--junitxml=")
    assert argv[5:] == ["tests/test_example.py::test_one"]
    assert all(";" not in arg and "&&" not in arg for arg in argv)


def test_all_mode_ignores_collection_error_files(monkeypatch):
    _ready_collection()
    captured = {}

    async def fake_spawn(argv):
        captured["argv"] = argv
        return _FakeProcess()

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    with _client() as client:
        response = client.post("/api/tests/start", json={"mode": "all"})
        assert response.status_code == 200
        for _ in range(30):
            if client.get("/api/tests/status").json()["status"] != "running":
                break
            import time
            time.sleep(0.01)
    assert "tests/test_example.py" in captured["argv"]
    assert "--ignore=tests/test_broken.py" in captured["argv"]


def test_second_start_returns_conflict(monkeypatch):
    _ready_collection()
    started = asyncio.Event()

    async def fake_spawn(_argv):
        started.set()
        return _FakeProcess(block=True)

    async def fake_terminate(process):
        process.returncode = -1
        process.stdout.release.set()

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    monkeypatch.setattr(runner, "terminate_process_tree", fake_terminate)
    with _client() as client:
        first = client.post("/api/tests/start", json={"mode": "selected", "targets": ["tests/test_example.py"]})
        assert first.status_code == 200
        assert client.post("/api/tests/start", json={"mode": "all"}).status_code == 409
        client.post("/api/tests/cancel")


def test_start_is_rejected_during_collection():
    with runner._state_lock:
        runner._collection.update(status="collecting")
    with _client() as client:
        response = client.post("/api/tests/start", json={"mode": "all"})
    assert response.status_code == 409


def test_collection_error_is_reported_and_failed_file_is_not_selectable(monkeypatch):
    captured = {}
    output = (
        "tests/test_good.py::test_ok\n"
        "ERROR collecting tests/test_broken.py\nE   ModuleNotFoundError: missing\n"
        "===== 1 error =====\n"
    )

    async def fake_spawn(argv):
        captured["argv"] = argv
        return _FakeProcess([line.encode() + b"\n" for line in output.splitlines()], returncode=2)

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    with _client() as client:
        assert client.get("/api/tests/collect").json()["status"] == "collecting"
        import time
        for _ in range(50):
            state = client.get("/api/tests/collect").json()
            if state["status"] != "collecting":
                break
            time.sleep(0.01)
        assert state["status"] == "ready"
        assert state["error"] is None
        good = next(item for item in state["files"] if item["path"] == "tests/test_good.py")
        broken = next(item for item in state["files"] if item["path"] == "tests/test_broken.py")
        assert good["nodeids"] == ["tests/test_good.py::test_ok"]
        assert broken["selectable"] is False
        assert "ModuleNotFoundError" in broken["error"]
        rejected = client.post("/api/tests/start", json={
            "mode": "selected", "targets": ["tests/test_broken.py"],
        })
    assert rejected.status_code == 422
    assert captured["argv"] == [
        runner.sys.executable, "-m", "pytest", "--collect-only", "-q",
        "-o", "addopts=", "-p", "no:cacheprovider",
    ]


def test_collect_snapshot_hides_active_process(monkeypatch):
    captured = {}

    async def fake_spawn(_argv):
        captured["process"] = _FakeProcess(block=True)
        return captured["process"]

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    with _client() as client:
        assert client.get("/api/tests/collect").json()["status"] == "collecting"
        import time
        time.sleep(0.02)
        response = client.get("/api/tests/collect")
        assert response.status_code == 200
        state = response.json()
        assert state["status"] == "collecting"
        assert "process" not in state
        captured["process"].stdout.release.set()


def test_collect_spawn_error_is_reported_and_not_retried_implicitly(monkeypatch):
    calls = []

    async def fake_spawn(_argv):
        calls.append(True)
        raise OSError("permission denied starting pytest")

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    with _client() as client:
        assert client.get("/api/tests/collect").json()["status"] == "collecting"
        import time
        for _ in range(50):
            state = client.get("/api/tests/collect").json()
            if state["status"] != "collecting":
                break
            time.sleep(0.01)
        assert state["status"] == "error"
        assert state["error"] == "permission denied starting pytest"
        assert client.get("/api/tests/collect").json()["error"] == state["error"]
    assert len(calls) == 1


def test_collect_and_status_return_ast_info_by_nodeid(tmp_path, monkeypatch):
    test_file = tmp_path / "tests" / "test_auth_page.py"
    test_file.parent.mkdir()
    test_file.write_text(
        'def test_login(auth_client):\n'
        '    """Rejects unauthenticated access."""\n'
        '    assert auth_client.status_code == 401\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(runner, "PROJECT_ROOT", tmp_path)
    nodeid = "tests/test_auth_page.py::test_login"

    async def fake_spawn(argv):
        if "--collect-only" in argv:
            return _FakeProcess([nodeid.encode() + b"\n"])
        junit_path = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--junitxml="))
        Path(junit_path).write_text(
            '<testsuite><testcase classname="tests.test_auth_page" name="test_login"/></testsuite>',
            encoding="utf-8",
        )
        return _FakeProcess([b"tests/test_auth_page.py::test_login PASSED [100%]\n"])

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    with _client() as client:
        assert client.get("/api/tests/collect").json()["status"] == "collecting"
        import time
        for _ in range(50):
            collection = client.get("/api/tests/collect").json()
            if collection["status"] != "collecting":
                break
            time.sleep(0.01)
        assert collection["info"][nodeid]["doc"] == "Rejects unauthenticated access."
        assert collection["files"][0]["topic"] == "auth"
        assert collection["topics"]["auth"] == runner.TOPIC_METADATA["auth"]
        assert collection["files"][0]["topic_name"] == "Access and identity"
        assert collection["files"][0]["topic_description"] == runner.TOPIC_METADATA["auth"]["description"]

        started = client.post("/api/tests/start", json={"mode": "selected", "targets": [nodeid]})
        assert started.status_code == 200
        for _ in range(50):
            status = client.get("/api/tests/status").json()
            if status["status"] not in {"running", "starting"}:
                break
            time.sleep(0.01)
    assert status["info"][nodeid]["checks"] == ["assert auth_client.status_code == 401"]


def test_optional_test_descriptions_fall_back_when_file_is_missing(tmp_path, monkeypatch):
    test_file = tmp_path / "tests" / "test_auth_page.py"
    test_file.parent.mkdir()
    test_file.write_text(
        'def test_login(auth_client):\n'
        '    """Rejects unauthenticated access."""\n'
        '    assert auth_client.status_code == 401\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(runner, "PROJECT_ROOT", tmp_path)
    files = [{
        "path": "tests/test_auth_page.py",
        "nodeids": ["tests/test_auth_page.py::test_login"],
        "count": 1,
        "selectable": True,
    }]

    info = runner.enrich_collection(files)

    assert info["tests/test_auth_page.py::test_login"]["doc"] == "Rejects unauthenticated access."
    assert "setup" not in info["tests/test_auth_page.py::test_login"]
    assert "action" not in info["tests/test_auth_page.py::test_login"]
    assert "expected" not in info["tests/test_auth_page.py::test_login"]
    assert files[0]["topic_name"] == runner.TOPIC_METADATA["auth"]["name"]
    assert files[0]["topic_description"] == runner.TOPIC_METADATA["auth"]["description"]


def test_timeout_marks_run_timed_out(monkeypatch):
    _ready_collection()
    monkeypatch.setattr(runner, "TEST_TIMEOUT_SECONDS", 0.01)

    async def fake_spawn(_argv):
        return _FakeProcess(block=True)

    async def fake_terminate(process):
        process.returncode = -9
        process.stdout.release.set()

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    monkeypatch.setattr(runner, "terminate_process_tree", fake_terminate)
    with _client() as client:
        assert client.post("/api/tests/start", json={"mode": "all"}).status_code == 200
        import time
        for _ in range(50):
            state = client.get("/api/tests/status").json()
            if state["status"] == "timed_out":
                break
            time.sleep(0.01)
    assert state["status"] == "timed_out"


def test_cancel_marks_run_cancelled(monkeypatch):
    _ready_collection()

    async def fake_spawn(_argv):
        return _FakeProcess(block=True)

    async def fake_terminate(process):
        process.returncode = -1
        process.stdout.release.set()

    monkeypatch.setattr(runner, "_spawn", fake_spawn)
    monkeypatch.setattr(runner, "terminate_process_tree", fake_terminate)
    with _client() as client:
        assert client.post("/api/tests/start", json={"mode": "all"}).status_code == 200
        assert client.post("/api/tests/cancel").status_code == 200
        import time
        for _ in range(50):
            state = client.get("/api/tests/status").json()
            if state["status"] == "cancelled":
                break
            time.sleep(0.01)
    assert state["status"] == "cancelled"


def test_junit_parses_outcomes_duration_and_first_reason_line(tmp_path):
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuite><testcase classname="tests.test_example.TestGroup" name="test_bad" time="1.25">'
        '<failure message="AssertionError: expected">trace\nmore details</failure></testcase>'
        '<testcase classname="tests.test_example" name="test_skip"><skipped message="not supported"/></testcase>'
        '<testcase classname="tests.test_example" name="test_ok"/></testsuite>',
        encoding="utf-8",
    )
    results = runner.parse_junit(report)
    assert results == [
        {"nodeid": "tests/test_example.py::TestGroup::test_bad", "outcome": "failed",
         "duration": 1.25, "message": "AssertionError: expected"},
        {"nodeid": "tests/test_example.py::test_skip", "outcome": "skipped",
         "duration": 0.0, "message": "not supported"},
        {"nodeid": "tests/test_example.py::test_ok", "outcome": "passed",
         "duration": 0.0, "message": ""},
    ]


def test_junit_failure_body_fallback_and_error_message(tmp_path):
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuite>'
        '<testcase classname="tests.test_example" name="test_body">'
        '<failure message="  ">\n  AssertionError: body fallback\ntraceback</failure>'
        '</testcase>'
        '<testcase classname="tests.test_example" name="test_setup">'
        '<error message="RuntimeError: fixture setup failed">Traceback details</error>'
        '</testcase>'
        '</testsuite>',
        encoding="utf-8",
    )

    results = runner.parse_junit(report)

    assert results == [
        {"nodeid": "tests/test_example.py::test_body", "outcome": "failed",
         "duration": 0.0, "message": "AssertionError: body fallback"},
        {"nodeid": "tests/test_example.py::test_setup", "outcome": "failed",
         "duration": 0.0, "message": "RuntimeError: fixture setup failed"},
    ]


def test_ast_extracts_test_explanation_from_source_string():
    source = '''
import pytest
from unittest.mock import patch

class TestWidget:
    @pytest.mark.parametrize("value", [1, 2, 3])
    @patch("service.load")
    def test_reads_cache(self, value, tmp_path, monkeypatch):
        """Checks cached values are returned."""
        assert value in (1, 2, 3)
        assert tmp_path is not None
'''

    info = runner.extract_test_info_from_source(source, "tests/test_widget.py")

    assert info == {
        "tests/test_widget.py::TestWidget::test_reads_cache": {
            "title": "reads cache",
            "group": "TestWidget",
            "doc": "Checks cached values are returned.",
            "checks": ["assert value in (1, 2, 3)", "assert tmp_path is not None"],
            "uses": ["monkeypatch", "parametrize", "patch", "tmp_path"],
            "param_count": 3,
        },
    }


def test_ast_parse_failure_is_ignored():
    assert runner.extract_test_info_from_source("def test_broken(:\n", "tests/test_broken.py") == {}


@pytest.mark.parametrize(("file_path", "expected"), [
    ("tests/test_agent_loop.py", "agent"),
    ("tests/test_intelligent_scoring.py", "scoring"),
    ("tests/test_page_auth.py", "auth"),
    ("tests/test_web_api.py", "web"),
    ("tests/test_threatfox_client.py", "threat_intel"),
    ("tests/test_mcp_tool.py", "mcp"),
    ("tests/test_misc.py", "other"),
])
def test_topic_mapping_uses_filename(file_path, expected):
    assert runner.topic_for_filename(file_path) == expected
