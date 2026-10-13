"""
Author: Ugur Ates
Agent API routes - Investigation management.
"""

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..auth import get_current_user
from ..chat_intents import route_chat_message
from ..source_classification import count_source_classes
from ..visibility import (
    serialize_agent_session,
    serialize_agent_stats,
    serialize_audit_entries,
    serialize_correlation,
    serialize_memory_stats,
    serialize_result_payload,
    serialize_sandbox_status,
    serialize_tool_definition,
)

logger = logging.getLogger(__name__)


async def _require_agent_access(
    request: Request,
    current_user: dict = Depends(get_current_user),
) -> None:
    """Allow non-investigative instant replies; retain the agent RBAC gate."""
    path = request.url.path.rstrip("/")
    if request.method == "POST" and path.endswith("/investigate"):
        # These roles may reach the handler's intent gate. Only Threat Hunters
        # and admins may start an investigation after that gate.
        if current_user.get("role") in {"Incident Responder", "Threat Hunter", "admin"}:
            return
    elif current_user.get("role") in {"Threat Hunter", "admin"}:
        return
    role = current_user.get("role", "Your role")
    if role == "Incident Responder":
        detail = "Incident Responders can use greeting and help replies and run approved playbooks. Starting an agent investigation requires the Threat Hunter role or administrator access."
    elif role == "SOC Analyst Tier 1-2":
        detail = "SOC Analyst Tier 1-2 can use greeting and help replies, but agent investigations require the Threat Hunter role or administrator access."
    else:
        detail = f"{role} cannot access agent investigations. Ask an administrator for access."
    raise HTTPException(status_code=403, detail=detail)


router = APIRouter(dependencies=[Depends(_require_agent_access)])


def _owner_scope(current_user: dict) -> Optional[int]:
    return None if current_user.get("role") == "admin" else current_user["id"]


class InvestigateRequest(BaseModel):
    goal: str = Field(..., min_length=1, description="Investigation goal in natural language")
    case_id: Optional[str] = None
    playbook_id: Optional[str] = None
    max_steps: Optional[int] = Field(None, ge=1, le=500, description="Maximum investigation steps")
    history: List[Dict[str, str]] = Field(default_factory=list)


class ApprovalRequest(BaseModel):
    approved: bool
    comment: str = ""
    approved_by: str = "unknown" 


def _require_agent_loop(request: Request):
    loop = request.app.state.agent_loop
    if loop is None:
        raise HTTPException(503, "Agent loop not initialized")
    return loop


def _require_agent_store(request: Request):
    store = request.app.state.agent_store
    if store is None:
        raise HTTPException(503, "Agent store not initialized")
    return store


@router.post('/investigate')
async def start_investigation(
    request: Request,
    body: InvestigateRequest,
    current_user: dict = Depends(get_current_user),
):
    """Start a new agent investigation."""
    role = current_user.get("role")
    if role not in {"Incident Responder", "Threat Hunter", "admin"}:
        raise HTTPException(
            status_code=403,
            detail=f"{role or 'Your role'} cannot access agent investigations.",
        )

    # Case/playbook sessions are explicit workflows and retain their direct
    # dispatch behavior without asking the conversational intent gate.
    if not body.case_id and not body.playbook_id:
        agent_loop = _require_agent_loop(request)
        instant = await route_chat_message(
            agent_loop, body.goal, body.history, role=role,
        )
        if instant is not None:
            return instant

    if role not in {"Threat Hunter", "admin"}:
        raise HTTPException(
            status_code=403,
            detail="Starting an agent investigation requires the Threat Hunter role or administrator access.",
        )

    agent_loop = _require_agent_loop(request)

    session_id = await agent_loop.investigate(
        body.goal,
        body.case_id,
        body.playbook_id,
        max_steps=body.max_steps,
        user_id=current_user["id"],
        role=current_user["role"],
    )
    return {"session_id": session_id, "status": "active", "goal": body.goal}


@router.get('/stats')
async def agent_stats(request: Request, current_user: dict = Depends(get_current_user)):
    """Get agent statistics."""
    store = _require_agent_store(request)
    stats = store.get_agent_stats(
        user_id=(
            None if current_user.get("role") == "admin"
            else current_user.get("id")
        )
    )
    # Add tool count
    tool_registry = request.app.state.tool_registry
    if tool_registry:
        stats['registered_tools'] = len(tool_registry.list_tools())
    # Add MCP connection count
    mcp_client = request.app.state.mcp_client
    if mcp_client:
        status = mcp_client.get_connection_status()
        stats['mcp_servers'] = len(status)
        stats['mcp_connected'] = sum(1 for s in status.values() if s.get('connected'))
    return serialize_agent_stats(stats, current_user['role'])


@router.get('/tools')
async def list_tools(request: Request, category: Optional[str] = None,
                     current_user: dict = Depends(get_current_user)):
    """List all registered tools."""
    tool_registry = request.app.state.tool_registry
    if tool_registry is None:
        raise HTTPException(503, "Tool registry not initialized")
    tools = tool_registry.list_tools(category=category)
    visible = [
        serialized for tool in tools
        if (serialized := serialize_tool_definition(tool, current_user['role'])) is not None
    ]
    return {"tools": visible}


@router.get('/memory/ioc/{ioc}')
async def recall_ioc(request: Request, ioc: str, current_user: dict = Depends(get_current_user)):
    """Check investigation memory for a previously analyzed IOC."""
    memory = request.app.state.investigation_memory
    if memory is None:
        raise HTTPException(503, "Investigation memory not initialized")

    cached = memory.recall_ioc(ioc)
    if cached:
        return {"cached": True, "ioc": ioc, "result": serialize_result_payload(cached, current_user['role'])}
    return {"cached": False, "ioc": ioc, "message": f"No prior investigation found for {ioc}"}


@router.get('/memory/stats')
async def memory_stats(request: Request, current_user: dict = Depends(get_current_user)):
    """Get investigation memory statistics."""
    memory = request.app.state.investigation_memory
    if memory is None:
        raise HTTPException(503, "Investigation memory not initialized")

    summary = memory.get_pattern_summary()
    return serialize_memory_stats(summary, current_user['role'])


@router.get('/sandbox/status')
async def sandbox_status(request: Request, current_user: dict = Depends(get_current_user)):
    """Get sandbox environment status."""
    sandbox = request.app.state.sandbox_orchestrator
    if sandbox is None:
        raise HTTPException(503, "Sandbox orchestrator not initialized")

    status = sandbox.get_sandbox_status()
    return {"sandboxes": serialize_sandbox_status(status, current_user['role'])}


@router.get('/correlation/{session_id}')
async def get_session_correlation(
    request: Request,
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get correlation analysis for a session's findings."""
    store = _require_agent_store(request)
    session = store.get_session(
        session_id,
        user_id=_owner_scope(current_user),
    )
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )

    correlation_engine = request.app.state.correlation_engine
    if correlation_engine is None:
        raise HTTPException(503, "Correlation engine not initialized")

    # Get session findings and correlate
    findings = session.get('findings', [])
    if isinstance(findings, str):
        import json
        try:
            findings = json.loads(findings)
        except (json.JSONDecodeError, TypeError):
            findings = []

    result = correlation_engine.correlate(findings)
    return {"session_id": session_id, "correlation": serialize_correlation(result, current_user['role'])}


@router.get('/sessions')
async def list_sessions(
    request: Request,
    limit: int = 50,
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """List agent investigation sessions."""
    store = _require_agent_store(request)
    sessions = store.list_sessions(
        limit=limit,
        status=status,
        user_id=_owner_scope(current_user),
    )
    return {
        "sessions": [serialize_agent_session(session, role=current_user['role']) for session in sessions]
    }


@router.get('/sessions/{session_id}')
async def get_session(
    request: Request,
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get session details with all steps."""
    store = _require_agent_store(request)
    session = store.get_session(
        session_id,
        user_id=_owner_scope(current_user),
    )
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )
    steps = store.get_steps(session_id)
    session['steps'] = steps
    # Include live state if available
    agent_loop = request.app.state.agent_loop
    if agent_loop:
        live_state = agent_loop.get_state(session_id)
        if live_state:
            session['live_state'] = live_state
    serialized = serialize_agent_session(
        session, steps=steps, live_state=session.get('live_state'), role=current_user['role']
    )
    visible_steps = serialized.get("steps")
    if isinstance(visible_steps, list):
        raw_steps_by_id = {
            raw_step.get("id"): raw_step
            for raw_step in steps
            if isinstance(raw_step, dict) and raw_step.get("id") is not None
        }
        for visible_step in visible_steps:
            if (
                not isinstance(visible_step, dict)
                or visible_step.get("id") is None
            ):
                continue
            raw_step = raw_steps_by_id.get(visible_step.get("id"))
            if (
                not isinstance(raw_step, dict)
                or raw_step.get("step_type") != "tool_call"
                or raw_step.get("tool_name") != "investigate_ioc"
            ):
                continue
            safe_result = serialize_result_payload(
                raw_step.get("tool_result"), current_user["role"]
            )
            safe_sources = safe_result.get("sources")
            if isinstance(safe_sources, dict):
                visible_step["source_counts"] = count_source_classes(
                    safe_sources, safe_result.get("score_breakdown")
                )
    return serialized


@router.post('/sessions/{session_id}/approve')
async def approve_action(
    request: Request,
    session_id: str,
    body: ApprovalRequest,
    current_user: dict = Depends(get_current_user),
):
    """Approve or reject a pending action."""
    store = _require_agent_store(request)
    session = store.get_session(
        session_id,
        user_id=_owner_scope(current_user),
    )
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )

    approved_by = current_user.get("username") or current_user.get("email") or "unknown"
    metadata = session.get('metadata', {})
    if isinstance(metadata, dict) and 'pending_step_name' in metadata:
        # Flow C: Playbook session
        playbook_engine = getattr(request.app.state, 'playbook_engine', None)
        if playbook_engine is None:
            return {"success": False, "error": "playbook_engine not available"}
        try:
            await playbook_engine.execute_from_step(
                session_id, approved=body.approved, approved_by=approved_by,
            )
            return {"success": True}
        except Exception as exc:
            return {"success": False, "error": "Action execution failed"}
    else:
        # Flow B: Agent Loop session
        agent_loop = _require_agent_loop(request)
        if body.approved:
            success = await agent_loop.approve_action(session_id, approved_by=approved_by)
        else:
            success = await agent_loop.reject_action(session_id, approved_by=approved_by)
        return {"success": success}


@router.post('/sessions/{session_id}/cancel')
async def cancel_session(
    request: Request,
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Cancel an active investigation."""
    store = _require_agent_store(request)
    session = store.get_session(
        session_id,
        user_id=_owner_scope(current_user),
    )
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )

    agent_loop = _require_agent_loop(request)
    await agent_loop.cancel_session(session_id)
    return {"status": "cancelled"}

@router.delete('/sessions/{session_id}')
async def delete_session(
    request: Request,
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete an investigation session and its steps."""
    store = _require_agent_store(request)
    session = store.get_session(
        session_id,
        user_id=_owner_scope(current_user),
    )
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )

    # กันลบ session ที่ agent loop ยังทำงานอยู่ (แค่มีอยู่ใน _active_sessions ก็ถือว่า active)
    agent_loop = request.app.state.agent_loop
    if agent_loop and agent_loop.get_state(session_id) is not None:
        raise HTTPException(409, "Cannot delete an active investigation session; cancel it first")

    deleted = store.delete_session(session_id)
    if not deleted:
        raise HTTPException(500, "Failed to delete session")
    return {"status": "deleted", "session_id": session_id}
@router.get('/sessions/{session_id}/audit')
async def get_session_audit_trail(
    session_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Return the full audit trail for one session, newest first.

    Each entry includes actor ('human' / 'agent' / 'system'), action,
    action_type ('approval_granted' / 'approval_rejected' / 'tool_call'),
    approved_by, status, and timestamp -- this is the evidence that a
    named human approved a specific action, not just a bare true/false.
    """
    agent_store = getattr(request.app.state, 'agent_store', None)
    if agent_store is None:
        return JSONResponse(
            {"error": "AgentStore not available"}, status_code=503,
        )

    session = agent_store.get_session(
        session_id,
        user_id=_owner_scope(current_user),
    )
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )

    entries = agent_store.get_audit_log(session_id=session_id, limit=200)

    # Convenience: pull out just the human-approval-related entries,
    # since that's the part relevant to the HITL demo/slide.
    approval_entries = [
        e for e in entries
        if e.get('action_type') in ('approval_granted', 'approval_rejected')
    ]

    return {
        "session_id": session_id,
        "goal": session.get('goal'),
        "status": session.get('status'),
        "total_entries": len(entries),
        "approval_entries": serialize_audit_entries(approval_entries, current_user['role']),
        "all_entries": serialize_audit_entries(entries, current_user['role']),
    }
