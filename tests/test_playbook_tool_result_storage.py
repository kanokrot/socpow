"""Regression tests for complete and valid playbook tool-result storage."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

import src.agent.playbook_engine as playbook_engine_module
from src.agent.agent_store import AgentStore
from src.agent.playbook_engine import PlaybookEngine, PlaybookStep


def _build_running_engine(tmp_path, steps, tool_result):
    store = AgentStore(str(tmp_path / "agent.db"))
    agent_loop = MagicMock()
    agent_loop.config = {}
    agent_loop.run_tool = AsyncMock(side_effect=tool_result)
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    playbook_id = engine.register_playbook(
        "Tool result storage", "Tool result storage regression", steps,
    )
    return engine, agent_loop, store, playbook_id


@pytest.mark.asyncio
async def test_single_tool_result_over_10000_chars_is_stored_complete(tmp_path):
    result = {"payload": "x" * 12_000}

    async def tool_result(_tool_name, _params):
        return result

    engine, _agent_loop, store, playbook_id = _build_running_engine(
        tmp_path,
        [{"name": "collect", "tool": "collect_data"}],
        tool_result,
    )

    session_id = await engine.execute(playbook_id, {})

    step = next(step for step in store.get_steps(session_id) if step["tool_name"] == "collect_data")
    assert len(step["tool_result"]) > 10_000
    assert json.loads(step["tool_result"]) == result


@pytest.mark.asyncio
async def test_for_each_iteration_results_over_10000_chars_are_stored_complete(tmp_path):
    async def tool_result(_tool_name, params):
        return {"target": params["target"], "payload": "y" * 12_000}

    targets = ["host-a", "host-b"]
    engine, _agent_loop, store, playbook_id = _build_running_engine(
        tmp_path,
        [{
            "name": "collect_each",
            "tool": "collect_data",
            "for_each": "targets",
            "params": {"target": "{{item}}"},
        }],
        tool_result,
    )

    session_id = await engine.execute(playbook_id, {"targets": targets})

    iteration_steps = [
        step for step in store.get_steps(session_id)
        if step["step_type"] == "for_each_iteration"
    ]
    assert len(iteration_steps) == len(targets)
    assert [json.loads(step["tool_result"]) for step in iteration_steps] == [
        {"target": target, "payload": "y" * 12_000} for target in targets
    ]


@pytest.mark.asyncio
async def test_approved_tool_result_over_10000_chars_is_stored_complete(tmp_path):
    result = {"payload": "z" * 12_000}
    store = AgentStore(str(tmp_path / "approval.db"))
    agent_loop = MagicMock()
    agent_loop.config = {}
    agent_loop.run_tool = AsyncMock(return_value=result)
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    playbook_id = "approved-tool-result-storage"
    step = PlaybookStep.from_dict({"name": "approved_collect", "tool": "collect_data"})
    engine._cache[playbook_id] = {
        "id": playbook_id,
        "name": "Approved tool result storage",
        "_parsed_steps": [step],
    }
    session_id = store.create_session(
        goal="Approved tool result storage", playbook_id=playbook_id,
    )
    store.update_session_metadata(session_id, {
        "context": {},
        "pending_step_name": step.name,
        "step_number": 1,
        "case_id": None,
    })
    store.update_session_status(session_id, "waiting_approval")
    engine._run_step_loop = AsyncMock()

    await engine.execute_from_step(session_id, approved=True, approved_by="tester")

    stored_step = next(
        step for step in store.get_steps(session_id)
        if step["tool_name"] == "collect_data"
    )
    assert len(stored_step["tool_result"]) > 10_000
    assert json.loads(stored_step["tool_result"]) == result


def test_oversized_tool_result_is_valid_json_preview(monkeypatch):
    result = {"payload": "p" * 500}
    serialized = json.dumps(result, default=str)
    monkeypatch.setattr(
        playbook_engine_module, "_MAX_STORED_TOOL_RESULT_CHARS", 100,
    )

    stored = json.loads(playbook_engine_module._serialize_tool_result(result))

    assert stored["truncated"] is True
    assert stored["original_size"] == len(serialized)
    assert len(stored["preview"]) <= 10_000
    assert "error" not in stored


def test_oversized_top_level_error_records_ended_in_error(monkeypatch):
    result = {"error": "collection failed", "payload": "e" * 500}
    monkeypatch.setattr(
        playbook_engine_module, "_MAX_STORED_TOOL_RESULT_CHARS", 100,
    )

    stored = json.loads(playbook_engine_module._serialize_tool_result(result))

    assert stored["truncated"] is True
    assert stored["ended_in_error"] is True
    assert "error" not in stored


def test_oversized_mcp_envelope_without_error_records_success(monkeypatch):
    result = {
        "result": {"payload": "m" * 500},
        "server": "remote_tools",
        "tool": "process_list_collect",
    }
    monkeypatch.setattr(
        playbook_engine_module, "_MAX_STORED_TOOL_RESULT_CHARS", 100,
    )

    serialized = playbook_engine_module._serialize_tool_result(result)
    stored = json.loads(serialized)

    assert stored["truncated"] is True
    assert stored["ended_in_error"] is False
    assert "error" not in stored


@pytest.mark.asyncio
async def test_top_level_tool_error_still_takes_on_failure_path(tmp_path):
    async def tool_result(tool_name, _params):
        if tool_name == "collect_data":
            return {"error": "collection failed"}
        return {"notice": "failure path reached"}

    engine, agent_loop, store, playbook_id = _build_running_engine(
        tmp_path,
        [
            {
                "name": "collect",
                "tool": "collect_data",
                "on_success": "dependent",
                "on_failure": "failure_notice",
            },
            {"name": "dependent", "tool": "must_not_run"},
            {"name": "failure_notice", "tool": "failure_notice"},
        ],
        tool_result,
    )

    session_id = await engine.execute(playbook_id, {})

    assert [call.args[0] for call in agent_loop.run_tool.await_args_list] == [
        "collect_data", "failure_notice",
    ]
    steps = store.get_steps(session_id)
    failed_step = next(step for step in steps if step["tool_name"] == "collect_data")
    assert json.loads(failed_step["tool_result"]) == {"error": "collection failed"}
    assert not any(step["tool_name"] == "must_not_run" for step in steps)
