"""Scenario tests for approval and partial tool execution behavior."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentPhase, AgentState
from src.agent.agent_store import AgentStore
from src.agent.playbook_engine import PlaybookEngine, PlaybookStep
from src.web.auth import get_current_user
from src.web.routes import agent as agent_routes


def _build_paused_engine(
    tmp_path, step_dict, context, tool_result, additional_steps=None,
):
    store = AgentStore(str(tmp_path / "agent.db"))
    agent_loop = MagicMock()
    agent_loop.config = {}
    agent_loop.run_tool = AsyncMock(side_effect=tool_result)

    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    step = PlaybookStep.from_dict(step_dict)
    playbook_id = "approval-scenario-test"
    engine._cache[playbook_id] = {
        "id": playbook_id,
        "name": "Approval scenario test",
        "_parsed_steps": [step, *(additional_steps or [])],
    }

    session_id = store.create_session(
        goal="Approval scenario test",
        playbook_id=playbook_id,
        user_id=41,
        kind="playbook",
    )
    store.update_session_metadata(session_id, {
        "context": context,
        "pending_step_name": step.name,
        "step_number": 3,
        "case_id": None,
    })
    store.update_session_status(session_id, "waiting_approval")

    captured = {}

    async def capture_continuation(
        session_id, playbook_id, pb, steps, step_map, context,
        current_step, step_number, case_id,
    ):
        captured["context"] = context
        captured["current_step"] = current_step
        return session_id

    engine._run_step_loop = AsyncMock(side_effect=capture_continuation)
    return engine, agent_loop, session_id, captured


def _build_running_engine(tmp_path, steps, result):
    store = AgentStore(str(tmp_path / "agent.db"))
    agent_loop = MagicMock()
    agent_loop.config = {}
    agent_loop.run_tool = AsyncMock(side_effect=result)
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    playbook_id = engine.register_playbook(
        "Scenario playbook", "Approval scenario coverage", steps,
    )
    return engine, agent_loop, store, playbook_id


@pytest.mark.asyncio
async def test_reject_skips_tool_audits_rejection_and_takes_on_failure(tmp_path):
    failure_step = PlaybookStep.from_dict({
        "name": "rejection_path",
        "action": "final_answer",
    })
    engine, agent_loop, session_id, captured = _build_paused_engine(
        tmp_path,
        {
            "name": "protected_action",
            "tool": "contain_host",
            "requires_approval": True,
            "on_failure": "rejection_path",
        },
        {},
        {"contained": True},
        additional_steps=[failure_step],
    )

    await engine.execute_from_step(
        session_id, approved=False, approved_by="analyst-1",
    )

    assert agent_loop.run_tool.call_count == 0
    rejection_entries = [
        entry for entry in engine.store.get_audit_log(session_id)
        if entry["action_type"] == "approval_rejected"
    ]
    assert len(rejection_entries) == 1
    assert captured["current_step"].name == "rejection_path"


@pytest.mark.asyncio
async def test_repeated_approval_executes_tool_once_and_rejects_second_resume(tmp_path):
    engine, agent_loop, session_id, _captured = _build_paused_engine(
        tmp_path,
        {
            "name": "protected_action",
            "tool": "contain_host",
            "requires_approval": True,
        },
        {},
        {"contained": True},
    )

    await engine.execute_from_step(session_id, approved=True, approved_by="analyst")
    with pytest.raises(ValueError, match="no pending approval"):
        await engine.execute_from_step(
            session_id, approved=True, approved_by="analyst",
        )

    assert agent_loop.run_tool.call_count == 1


@pytest.mark.parametrize("status", ["completed", "failed"])
@pytest.mark.asyncio
async def test_nonwaiting_session_does_not_execute_approved_tool(tmp_path, status):
    engine, agent_loop, session_id, _captured = _build_paused_engine(
        tmp_path,
        {
            "name": "protected_action",
            "tool": "contain_host",
            "requires_approval": True,
        },
        {},
        {"contained": True},
    )
    engine.store.update_session_status(session_id, status)

    with pytest.raises(ValueError, match="no pending approval"):
        await engine.execute_from_step(
            session_id, approved=True, approved_by="analyst",
        )

    agent_loop.run_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_top_level_tool_error_takes_failure_path_and_skips_dependent_tool(tmp_path):
    async def result(tool_name, params):
        return {"error": "collection failed"}

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
            {"name": "failure_notice", "action": "final_answer"},
        ],
        result,
    )

    session_id = await engine.execute(playbook_id, {})

    agent_loop.run_tool.assert_awaited_once_with("collect_data", {})
    steps = store.get_steps(session_id)
    tool_step = next(step for step in steps if step["tool_name"] == "collect_data")
    assert json.loads(tool_step["tool_result"]) == {"error": "collection failed"}
    assert not any(step["tool_name"] == "must_not_run" for step in steps)


@pytest.mark.parametrize(
    "raised", [RuntimeError("dispatcher unavailable"), asyncio.TimeoutError()],
    ids=["exception", "timeout"],
)
@pytest.mark.asyncio
async def test_tool_exception_or_timeout_is_saved_as_error_without_crashing(
    tmp_path, raised,
):
    engine, agent_loop, store, playbook_id = _build_running_engine(
        tmp_path,
        [{"name": "lookup", "tool": "lookup"}],
        raised,
    )

    session_id = await engine.execute(playbook_id, {})

    agent_loop.run_tool.assert_awaited_once()
    tool_step = next(
        step for step in store.get_steps(session_id)
        if step["tool_name"] == "lookup"
    )
    assert "error" in json.loads(tool_step["tool_result"])
    assert store.get_session(session_id)["status"] == "completed"


@pytest.mark.asyncio
async def test_nested_error_is_recorded_but_treated_as_top_level_success(tmp_path):
    nested_result = {
        "sources": {"shodan": {"error": "provider unavailable"}},
        "llm_analysis": {"error": "model unavailable"},
        "verdict": "UNKNOWN",
    }

    async def result(tool_name, params):
        if tool_name == "lookup":
            return nested_result
        return {"marker": tool_name}

    engine, agent_loop, store, playbook_id = _build_running_engine(
        tmp_path,
        [
            {
                "name": "lookup",
                "tool": "lookup",
                "on_success": "success_marker",
                "on_failure": "failure_marker",
            },
            {
                "name": "success_marker",
                "tool": "success_marker",
                "on_success": "done",
            },
            {
                "name": "failure_marker",
                "tool": "failure_marker",
                "on_success": "done",
            },
            {"name": "done", "action": "final_answer"},
        ],
        result,
    )

    session_id = await engine.execute(playbook_id, {})

    called_tools = [call.args[0] for call in agent_loop.run_tool.await_args_list]
    assert called_tools == ["lookup", "success_marker"]
    lookup_step = next(
        step for step in store.get_steps(session_id)
        if step["tool_name"] == "lookup"
    )
    assert json.loads(lookup_step["tool_result"]) == nested_result


@pytest.mark.xfail(
    strict=True,
    reason="approval timeout writes no audit entry; fix requires agent_loop.py (near-forbidden)",
)
@pytest.mark.asyncio
async def test_agent_loop_approval_timeout_fails_without_tool_and_writes_timeout_audit(
    monkeypatch, tmp_path,
):
    store = AgentStore(str(tmp_path / "agent.db"))
    loop = AgentLoop(
        config={"agent": {"max_steps": 5}},
        tool_registry=MagicMock(),
        agent_store=store,
    )
    session_id = "approval-timeout"
    state = AgentState(session_id=session_id, goal="test approval timeout", max_steps=5)
    loop._active_sessions[session_id] = state
    loop._approval_events[session_id] = asyncio.Event()
    loop.tools.get_tool.return_value = SimpleNamespace(requires_approval=True)
    loop.tools.execute_tool = AsyncMock(return_value={"executed": True})
    loop._think = AsyncMock(return_value={
        "action": "use_tool",
        "tool": "contain_host",
        "params": {"host": "host-1"},
    })
    loop._generate_summary = AsyncMock(return_value="approval timed out")

    async def timeout(awaitable, timeout):
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(asyncio, "wait_for", timeout)

    await loop._run_loop(session_id)

    assert state.phase == AgentPhase.FAILED
    loop.tools.execute_tool.assert_not_awaited()
    timeout_entries = [
        entry for entry in store.get_audit_log(session_id)
        if entry["action_type"] == "approval_timeout"
    ]
    assert timeout_entries


def _agent_approval_app(
    tmp_path, *, role, user_id, owner_id, pending_step=True,
):
    username = "real-analyst"
    current_user = {
        "id": user_id,
        "username": username,
        "email": "real-analyst@example.test",
        "role": role,
        "is_active": 1,
    }
    app = FastAPI()
    app.dependency_overrides[get_current_user] = lambda: current_user
    store = AgentStore(str(tmp_path / f"route-{role}-{owner_id}.db"))
    session_id = store.create_session(
        goal="Playbook approval route scenario",
        playbook_id="route-scenario",
        user_id=owner_id,
        kind="playbook",
    )
    if pending_step:
        store.update_session_metadata(session_id, {"pending_step_name": "protected"})
    store.update_session_status(session_id, "waiting_approval")
    app.state.agent_store = store
    agent_loop = MagicMock()
    agent_loop.approve_action = AsyncMock(return_value=True)
    agent_loop.reject_action = AsyncMock(return_value=True)
    app.state.agent_loop = agent_loop

    async def record_approval(session, approved, approved_by="unknown", **kwargs):
        store.add_audit_entry(
            session_id=session,
            action="contain_host",
            action_type="approval_granted" if approved else "approval_rejected",
            actor="human",
            approved_by=approved_by,
        )
        return session

    engine = SimpleNamespace(execute_from_step=AsyncMock(side_effect=record_approval))
    app.state.playbook_engine = engine
    app.include_router(agent_routes.router, prefix="/api/agent")
    return app, store, engine, session_id, username


def test_agent_approval_route_uses_authenticated_username_not_forged_body(tmp_path):
    app, store, engine, session_id, username = _agent_approval_app(
        tmp_path, role="Threat Hunter", user_id=41, owner_id=41,
    )

    with TestClient(app) as client:
        response = client.post(
            f"/api/agent/sessions/{session_id}/approve",
            json={"approved": True, "approved_by": "forged"},
        )

    assert response.status_code == 200
    audit = store.get_audit_log(session_id=session_id)
    assert audit[0]["approved_by"] == username
    assert engine.execute_from_step.await_args.kwargs["approved_by"] == username


def test_agent_loop_approval_route_uses_authenticated_username_not_forged_body(tmp_path):
    app, _store, _engine, session_id, username = _agent_approval_app(
        tmp_path,
        role="Threat Hunter",
        user_id=41,
        owner_id=41,
        pending_step=False,
    )

    with TestClient(app) as client:
        response = client.post(
            f"/api/agent/sessions/{session_id}/approve",
            json={"approved": True, "approved_by": "forged"},
        )

    assert response.status_code == 200
    app.state.agent_loop.approve_action.assert_awaited_once_with(
        session_id, approved_by=username,
    )


@pytest.mark.parametrize(
    "role,user_id,owner_id,expected_status",
    [
        ("SOC Analyst Tier 1-2", 41, 41, 403),
        ("Threat Hunter", 41, 99, 404),
    ],
    ids=["role-forbidden", "not-owner"],
)
def test_unauthorized_approval_does_not_run_tool_or_write_audit(
    tmp_path, role, user_id, owner_id, expected_status,
):
    app, store, engine, session_id, _username = _agent_approval_app(
        tmp_path, role=role, user_id=user_id, owner_id=owner_id,
    )

    with TestClient(app) as client:
        response = client.post(
            f"/api/agent/sessions/{session_id}/approve",
            json={"approved": True},
        )

    assert response.status_code == expected_status
    engine.execute_from_step.assert_not_awaited()
    assert store.get_audit_log(session_id=session_id) == []
