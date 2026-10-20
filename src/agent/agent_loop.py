"""
Agent Loop - ReAct reasoning engine for autonomous security investigations.

The loop cycles through THINK -> ACT -> OBSERVE until the LLM decides to emit
a final answer or the step budget is exhausted.  Dangerous actions pause for
analyst approval (WAITING_HUMAN).
"""

import asyncio
from copy import copy
from datetime import datetime, timezone
import json
import logging
import time
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from .agent_state import AgentPhase, AgentState
from .agent_store import AgentStore
from .tool_registry import ToolRegistry
from .agent_response_parsing import (
    contains_tool_call_template,
    extract_deterministic_verdict,
    extract_deterministic_verdict_source,
    sanitize_final_answer,
    sanitize_unscored_answer,
    normalise_decision,
    parse_tool_call_response,
    extract_json,
    truncate,
)
from .agent_tool_selection import ToolSelector
from .agent_llm_backends import LLMBackend
from .mcp_tool_classification import classify_mcp_tool
from src.web.visibility import is_tool_allowed

logger = logging.getLogger(__name__)

_RAG_PROVENANCE_FIELDS = {
    "schema_version",
    "citation_id",
    "knowledge_type",
    "source_name",
    "source_url",
    "source_version",
    "confidence",
    "tlp",
    "created",
    "modified",
    "revoked",
}
_RAG_STRING_FIELDS = _RAG_PROVENANCE_FIELDS - {"confidence", "revoked"}
_RAG_KNOWLEDGE_TYPES = {"analytic_guidance", "attack_pattern", "course_of_action"}
_VALID_TLP = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"}


def _parse_provenance_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 provenance timestamp and require a timezone."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def _walk_rag_references(value):
    """Yield RAG references recursively from Flow B tool-result structures."""
    if isinstance(value, dict):
        references = value.get("rag_references")
        if isinstance(references, list):
            yield from references
        for key, nested in value.items():
            if key != "rag_references":
                yield from _walk_rag_references(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_rag_references(nested)


def _strip_rag_references(value):
    """Remove unvalidated RAG payloads before findings enter an agent prompt."""
    if isinstance(value, dict):
        return {
            key: _strip_rag_references(nested)
            for key, nested in value.items()
            if key != "rag_references"
        }
    if isinstance(value, list):
        return [_strip_rag_references(nested) for nested in value]
    return value


def _validate_rag_reference(reference: Dict, now: Optional[datetime] = None):
    """Validate STIX-aligned provenance at the Flow B consumption boundary."""
    if not isinstance(reference, dict):
        return False, "reference is not an object"
    if not isinstance(reference.get("text"), str) or not reference["text"].strip():
        return False, "text is missing"

    metadata = reference.get("metadata")
    if not isinstance(metadata, dict):
        return False, "metadata is missing"

    missing = sorted(_RAG_PROVENANCE_FIELDS - metadata.keys())
    if missing:
        return False, f"missing metadata: {', '.join(missing)}"

    for field in _RAG_STRING_FIELDS:
        if not isinstance(metadata[field], str) or not metadata[field].strip():
            return False, f"{field} must be a non-empty string"

    if metadata["schema_version"] not in {
        "socpow-rag-provenance/1",
        "cabta-rag-provenance/1",
    }:
        return False, "unsupported schema_version"
    if metadata["knowledge_type"] not in _RAG_KNOWLEDGE_TYPES:
        return False, "invalid knowledge_type"

    confidence = metadata["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, int):
        return False, "confidence must be an integer"
    if not 0 <= confidence <= 100:
        return False, "confidence must be between 0 and 100"
    if metadata["tlp"] not in _VALID_TLP:
        return False, "invalid TLP 2.0 marking"

    parsed_url = urlparse(metadata["source_url"])
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        return False, "source_url must be an absolute HTTPS URL"

    try:
        created = _parse_provenance_timestamp(metadata["created"])
        modified = _parse_provenance_timestamp(metadata["modified"])
        if modified < created:
            return False, "modified precedes created"
        if metadata.get("valid_until"):
            valid_until = _parse_provenance_timestamp(metadata["valid_until"])
            if valid_until <= (now or datetime.now(timezone.utc)):
                return False, "knowledge entry has expired"
    except ValueError as exc:
        return False, str(exc)

    if not isinstance(metadata["revoked"], bool):
        return False, "revoked must be boolean"
    if metadata["revoked"]:
        return False, "knowledge entry is revoked"

    return True, ""


def _build_flow_b_rag_blocks(findings):
    """Build validated RAG context and a compact source list for Flow B."""
    context_lines = []
    source_lines = []
    seen = set()

    for reference in _walk_rag_references(findings):
        valid, reason = _validate_rag_reference(reference)
        metadata = reference.get("metadata", {}) if isinstance(reference, dict) else {}
        citation_id = metadata.get("citation_id", "unknown")
        if not valid:
            logger.warning(
                "[AGENT] Ignoring RAG entry %s: invalid provenance: %s",
                citation_id,
                reason,
            )
            continue
        if citation_id in seen:
            continue
        seen.add(citation_id)

        label = (
            f"[KB:{citation_id}] {metadata['source_name']} "
            f"({metadata['source_version']}) | {metadata['source_url']} | "
            f"confidence={metadata['confidence']} | {metadata['tlp']}"
        )
        context_lines.extend((label, reference["text"][:1200]))
        source_lines.append(label)

    return "\n".join(context_lines), "\n".join(source_lines)


def _append_rag_sources(answer: str, sources: str) -> str:
    """Append validated source citations deterministically to a Flow B answer."""
    if not sources:
        return answer
    return f"{answer}\n\nKnowledge sources:\n{sources}"

# -------------------------------------------------------------------- #
#  System prompt template
# -------------------------------------------------------------------- #

_SYSTEM_PROMPT = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Investigation goal: {goal}

Previous findings:
{findings_block}

{playbooks_block}

INSTRUCTIONS:
1. You MUST use tools to gather evidence before drawing conclusions. Never answer from memory alone.
2. For IOC investigations: call investigate_ioc first, then use MCP tools like threat_intel_tools.blocklist_check, threat_intel_tools.threatfox_ioc_lookup, threat_intel_tools.feodo_tracker_check for deeper analysis.
3. For file analysis: call analyze_malware first, then use MCP tools like remnux_tools.pe_analyze, remnux_tools.yara_scan, remnux_tools.file_entropy, remnux_tools.hash_file for deeper analysis.
4. For email analysis: call analyze_email first, then use MCP tools like remnux_tools.olevba_analyze, remnux_tools.rtfobj_analyze for attachment analysis (if applicable).
5. After gathering evidence, call correlate_findings to produce the final verdict.
6. Only write a final text answer (no tool call) AFTER you have gathered real evidence from at least 2 tools.
7. When calling a tool, ONLY pass the tool's own parameters (e.g. {{"ioc": "8.8.8.8"}}). Do NOT include extra keys like "action", "reasoning", or "tool" in the arguments.
8. Use DIFFERENT tools each step. Never call the same tool with the same parameters twice.

If previous findings are "(none yet)", you MUST call a tool now. Do NOT skip to a conclusion.

RULES:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use the tools provided. Do NOT invent tool names.
- Use knowledge-base claims only from the validated RAG context.
- Cite every knowledge-base entry you use with its exact [KB:citation_id].
"""

# Fallback prompt for when no native tool calling is available
_SYSTEM_PROMPT_NO_TOOLS = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Available tools:
{tools_block}

{playbooks_block}

Investigation goal: {goal}

Previous findings:
{findings_block}

Decide your next action. Respond in JSON (no markdown, no extra text):
{{"action": "use_tool", "tool": "tool_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "run_playbook", "playbook_id": "playbook_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "final_answer", "answer": "investigation summary", "verdict": "MALICIOUS/SUSPICIOUS/CLEAN", "reasoning": "why"}}

IMPORTANT:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Actions marked as requiring approval will pause for analyst review.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use tools that are listed above. Do NOT invent tool names.
- If a playbook matches the investigation goal, prefer running the playbook for structured analysis.
- Always include the "action" key in your JSON response.
- Use knowledge-base claims only from the validated RAG context.
- Cite every knowledge-base entry you use with its exact [KB:citation_id].
"""

_SUMMARY_PROMPT = """\
You are a Blue Team Security Agent. Summarise the following investigation
in 3-5 sentences suitable for a SOC ticket.  Include the verdict
(MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN), key evidence, and recommended
next steps.

CRITICAL RULE: A tool error (e.g. "HTTP 401", "Timeout", "Connection failed")
is NOT evidence of malicious activity — it only means the lookup could not
be completed. If ALL findings below are tool errors and none contain actual
threat intelligence data (detections, reputation scores, botnet/malware
names, etc.), you MUST set the verdict to "UNKNOWN" and the recommended
next step MUST be to retry with a different tool or fix the failing
integration. Do NOT infer risk level from the mere fact that a lookup failed.

Goal: {goal}

Steps taken: {step_count}

Findings:
{findings_json}

Validated knowledge context:
{rag_context}

If knowledge-base guidance is used, cite it as [KB:citation_id].

Respond in plain text (no JSON).
"""


class AgentLoop:
    """Orchestrates the ReAct loop, delegates to LLM + tools."""

    def __init__(
        self,
        config: Dict[str, Any],
        tool_registry: ToolRegistry,
        agent_store: AgentStore,
        llm_analyzer=None,
        mcp_client=None,
        playbook_engine=None,
        notification_manager=None,
    ):
        self.config = config
        self.tools = tool_registry
        self.store = agent_store
        self.llm = llm_analyzer
        self.mcp_client = mcp_client
        self._playbook_engine = playbook_engine
        self.notification_manager = notification_manager

        agent_cfg = config.get('agent', {})
        self.max_steps = agent_cfg.get('max_steps', 50)

        # LLM connection settings (mirrors LLMAnalyzer)
        llm_cfg = config.get('llm', {})
        self.provider = llm_cfg.get('provider', 'ollama')
        self.ollama_endpoint = llm_cfg.get('ollama_endpoint', 'http://localhost:11434')
        self.ollama_model = llm_cfg.get('model', llm_cfg.get('ollama_model', 'llama3.2:3b'))
        self.anthropic_key = config.get('api_keys', {}).get('anthropic', '')
        self.anthropic_model = llm_cfg.get('anthropic_model', 'claude-sonnet-4-20250514')
        self.timeout = aiohttp.ClientTimeout(total=120)

        self.tool_selector = ToolSelector(
            tools=self.tools, playbook_engine=getattr(self, '_playbook_engine', None),
        )
        self.llm_backend = LLMBackend(
            provider=self.provider,
            tools=self.tools,
            ollama_model=self.ollama_model,
            ollama_endpoint=self.ollama_endpoint,
            anthropic_key=self.anthropic_key,
            anthropic_model=self.anthropic_model,
            timeout=self.timeout,
            vllm_base_url=llm_cfg.get('vllm_base_url'),
            vllm_api_key=llm_cfg.get('vllm_api_key'),
            vllm_model=llm_cfg.get('vllm_model'),
        )

        # Active sessions & pub-sub
        self._active_sessions: Dict[str, AgentState] = {}
        self._approval_events: Dict[str, asyncio.Event] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None  # set on first investigate()

    # ================================================================== #
    #  Public API
    # ================================================================== #

    async def investigate(
        self,
        goal: str,
        case_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
        max_steps: Optional[int] = None,
        user_id: Optional[int] = None,
        role: Optional[str] = None,
    ) -> str:
        """Start an autonomous investigation. Returns *session_id* immediately."""

        session_id = self.store.create_session(
            goal=goal,
            case_id=case_id,
            playbook_id=playbook_id,
            user_id=user_id,
        )

        effective_max_steps = max_steps if max_steps is not None else self.max_steps
        state = AgentState(
            session_id=session_id,
            goal=goal,
            case_id=case_id,
            user_id=user_id,
            role=role,
            max_steps=effective_max_steps,
        )
        self._active_sessions[session_id] = state
        self._approval_events[session_id] = asyncio.Event()

        # Capture the main event loop so _notify() can safely push
        # messages to subscriber queues from background threads.
        try:
            self._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._main_loop = None

        # Fire-and-forget the loop in a background thread so the caller
        # gets the session_id without blocking.
        def _run():
            asyncio.run(self._run_loop(session_id))

        t = threading.Thread(target=_run, daemon=True, name=f"agent-{session_id}")
        t.start()

        logger.info(f"[AGENT] Investigation started: {session_id} - {goal[:80]}")
        return session_id

    async def approve_action(self, session_id: str, approved_by: str = "unknown") -> bool:
        """Approve the pending action so the loop can resume."""
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        # Signal the event so _wait_for_approval unblocks
        evt = self._approval_events.get(session_id)
        if evt:
            state.pending_approval["approved"] = True
            state.pending_approval["approved_by"] = approved_by
            evt.set()
        return True

    async def reject_action(self, session_id: str, approved_by: str = "unknown") -> bool:
        """Reject the pending action; the loop will skip it and re-think."""
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        evt = self._approval_events.get(session_id)
        if evt:
            state.pending_approval["approved"] = False
            state.pending_approval["approved_by"] = approved_by
            evt.set()
        return True

    async def cancel_session(self, session_id: str) -> None:
        """Cancel a running investigation."""
        state = self._active_sessions.get(session_id)
        if state and not state.is_terminal():
            state.errors.append("Cancelled by analyst")
            state.phase = AgentPhase.FAILED  # direct set to avoid transition check
            self.store.update_session_status(session_id, 'failed', 'Cancelled by analyst')
            self._notify(session_id, {"type": "cancelled"})
            # Unblock any waiting approval
            evt = self._approval_events.get(session_id)
            if evt:
                evt.set()
        logger.info(f"[AGENT] Session cancelled: {session_id}")

    def get_state(self, session_id: str) -> Optional[Dict]:
        """Return live state dict (or None)."""
        state = self._active_sessions.get(session_id)
        return state.to_dict() if state else None

    async def _call_mcp_tool(self, server: str, tool: str, params: Dict) -> Dict:
        """
        Call an MCP tool, bridging to the main event loop if needed.

        MCP stdio connections are established during app startup on the
        main uvicorn event loop. investigate()/playbook runs execute in
        a background thread with its own asyncio.run() loop. Awaiting
        mcp_client.call_tool() directly from that loop leaves the MCP
        client's background reader task orphaned on the original loop,
        so the call silently stalls until MCPClientManager's internal
        60s wait_for() timeout fires -- even when the underlying tool
        call itself would have completed in under a second.

        This routes the call through run_coroutine_threadsafe onto the
        loop the connection actually lives on whenever we detect we're
        not already running on it.
        """
        main_loop = self._main_loop
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if main_loop is not None and main_loop.is_running() and current_loop is not main_loop:
            future = asyncio.run_coroutine_threadsafe(
                self.mcp_client.call_tool(server, tool, params), main_loop,
            )
            return await asyncio.wrap_future(future)

        return await self.mcp_client.call_tool(server, tool, params)

    async def run_tool(
        self,
        tool_name: str,
        params: Dict,
        role: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict:
        """Execute a single tool by name (used by PlaybookEngine).

        Supports multiple tool name formats:
        - ``mcp:server-name/tool_name`` (playbook YAML format)
        - ``server-name.tool_name`` (internal registry format)
        - ``tool_name`` (local tool)

        Returns the tool result dict.
        """
        effective_role = role
        if effective_role is None and isinstance(context, dict):
            effective_role = context.get("role")

        # ---- Normalise playbook-style "mcp:server/tool" references ----
        original_name = tool_name
        mcp_server = None
        mcp_tool = None

        if tool_name.startswith("mcp:"):
            # Format: mcp:server-name/tool_name
            rest = tool_name[4:]  # strip "mcp:"
            if "/" in rest:
                mcp_server, mcp_tool = rest.split("/", 1)
                # Convert to registry format: server-name.tool_name
                tool_name = f"{mcp_server}.{mcp_tool}"
            else:
                # mcp:tool_name (no server specified)
                tool_name = rest

        tool_def = self.tools.get_tool(tool_name)

        if tool_def is None and mcp_server and mcp_tool:
            # Tool not registered yet: it still needs a trusted static
            # classification before the dispatcher may reach the MCP client.
            classification = classify_mcp_tool(mcp_server, mcp_tool)
            fallback_tool = {
                "name": tool_name,
                "source": mcp_server,
                **classification,
            }
            if effective_role is None or not is_tool_allowed(effective_role, fallback_tool):
                return {"error": "Tool is not allowed for this role"}
            if self.mcp_client is not None:
                try:
                    result = await self._call_mcp_tool(
                        mcp_server, mcp_tool, params,
                    )
                    return result if isinstance(result, dict) else {"result": result}
                except Exception as exc:
                    return {"error": f"MCP tool '{original_name}' call failed: {exc}"}
            return {"error": f"MCP client not available for tool: {original_name}"}

        if tool_def is None:
            return {"error": f"Tool not found: {original_name}"}

        # Every role-aware dispatcher call is checked at the last possible
        # point before execution.  Legacy local callers without a role remain
        # compatible; MCP calls without a role are denied above.
        if effective_role is not None and not is_tool_allowed(effective_role, tool_def):
            return {"error": "Tool is not allowed for this role"}

        if tool_def.source == 'local':
            return await self.tools.execute_local_tool(tool_name, **params)
        elif self.mcp_client is not None:
            return await self._call_mcp_tool(
                tool_def.source, tool_name.split(".", 1)[-1], params,
            )
        else:
            return {"error": f"MCP client not available for tool: {original_name}"}

    # ------------------------------------------------------------------ #
    #  Pub / Sub
    # ------------------------------------------------------------------ #

    def subscribe(self, session_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(session_id, []).append(q)
        return q

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(session_id, [])
        if queue in subs:
            subs.remove(queue)

    def _notify(self, session_id: str, message: Dict) -> None:
        """Push a message to all WebSocket subscribers for *session_id*.

        Thread-safe: if called from a background thread (agent loop),
        schedules the put on the main event loop so asyncio.Queue
        operations happen in the correct loop context.
        """
        subs = self._subscribers.get(session_id, [])
        if not subs:
            return

        main_loop = self._main_loop

        def _put_all():
            for q in subs:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    pass

        # If we have a reference to the main loop AND we're in a different
        # thread, use call_soon_threadsafe to schedule the put.
        if main_loop is not None and main_loop.is_running():
            try:
                main_loop.call_soon_threadsafe(_put_all)
                return
            except RuntimeError:
                pass  # loop closed, fall through

        # Fallback: direct put (works when called from the main loop)
        _put_all()

    # ================================================================== #
    #  Main ReAct Loop
    # ================================================================== #

    async def _run_loop(self, session_id: str) -> None:
        state = self._active_sessions.get(session_id)
        if state is None:
            return

        # Track previously called tools to prevent infinite loops
        _prev_tool_calls: list = []
        final_answer_saved = False

        try:
            state.transition(AgentPhase.THINKING)

            while not state.is_terminal() and state.step_count < state.max_steps:
                # ---- THINK ----
                state.phase = AgentPhase.THINKING
                state.current_tool = None
                self._notify(session_id, {
                    "type": "phase", "phase": "thinking",
                    "step": state.step_count,
                    "max_steps": state.max_steps,
                })

                decision = await self._think(state)

                if decision is None:
                    # Retry once: LLM may have returned an unparseable
                    # response or had a transient connection issue.
                    logger.warning("[AGENT] First LLM call returned None, retrying...")
                    await asyncio.sleep(1)
                    decision = await self._think(state)

                if decision is None:
                    state.errors.append(
                        "LLM returned no decision. Verify Ollama is running "
                        f"({self.ollama_endpoint}) and model '{self.ollama_model}' "
                        "is pulled. Run: ollama pull " + self.ollama_model
                    )
                    state.transition(AgentPhase.FAILED)
                    break

                # Record the thinking step
                self.store.add_step(
                    session_id, state.step_count, 'thinking',
                    json.dumps(decision, default=str),
                )

                # ---- Check for final answer ----
                if decision.get('action') == 'final_answer':
                    raw_summary = decision.get('answer', '')
                    leaked_tool_template = contains_tool_call_template(raw_summary)
                    summary = sanitize_final_answer(raw_summary, state.findings, state.goal)
                    if leaked_tool_template:
                        raw_preview = " ".join(str(raw_summary).split())[:200]
                        logger.warning(
                            "[AGENT] Removed tool-call template from final answer: %s",
                            raw_preview,
                        )
                    verdict_source = extract_deterministic_verdict_source(state.findings)
                    verdict = (
                        extract_deterministic_verdict(state.findings)
                        if verdict_source is not None else None
                    )
                    from .agent_response_parsing import build_evidence_card
                    evidence = (
                        build_evidence_card(state.findings, state.goal)
                        if verdict_source is not None else None
                    )
                    if verdict is None and not leaked_tool_template:
                        summary = sanitize_unscored_answer(summary, state.goal)
                    final_decision = {"answer": summary}
                    if verdict is not None and verdict_source is not None:
                        final_decision["verdict"] = verdict
                        final_decision["verdict_source"] = verdict_source
                        if evidence is not None:
                            final_decision["evidence"] = evidence
                    state.add_finding({
                        "type": "final_answer",
                        "answer": summary,
                        "verdict": verdict,
                        "reasoning": decision.get('reasoning', ''),
                    })
                    try:
                        self.store.add_step(
                            session_id, state.step_count, 'final_answer',
                            json.dumps(final_decision, default=str),
                        )
                        final_answer_saved = True
                    except Exception:
                        # A persistence error must not turn a successful run into
                        # a failed session; the common completion path retries.
                        logger.warning(
                            "[AGENT] Could not save final answer for %s",
                            session_id,
                            exc_info=True,
                        )

                    # Alert on high-severity verdicts (MALICIOUS/SUSPICIOUS by
                    # default -- configurable via notifications.create_on_verdict).
                    if self.notification_manager is not None and \
                            verdict in getattr(self.notification_manager, 'create_on_verdict', []):
                        try:
                            self.notification_manager.notify("verdict_alert", {
                                "ioc": state.goal,
                                "verdict": verdict,
                                "session_id": session_id,
                            })
                        except Exception as notify_exc:
                            logger.warning(
                                f"[AGENT] Notification dispatch failed: {notify_exc}"
                            )
                    break

                # ---- Check for run_playbook action ----
                if decision.get('action') == 'run_playbook':
                    if state.role not in (None, "Threat Hunter", "admin"):
                        state.errors.append("Playbook execution is not allowed for this role")
                        state.step_count += 1
                        continue
                    pb_id = decision.get('playbook_id', '')
                    pb_params = decision.get('params', {})
                    reasoning = decision.get('reasoning', '')

                    if hasattr(self, '_playbook_engine') and self._playbook_engine:
                        self.store.add_step(
                            session_id, state.step_count, 'run_playbook',
                            json.dumps({
                                "playbook_id": pb_id,
                                "params": pb_params,
                                "reasoning": reasoning,
                            }, default=str),
                        )
                        self._notify(session_id, {
                            "type": "phase", "phase": "running_playbook",
                            "step": state.step_count, "playbook_id": pb_id,
                        })
                        try:
                            pb_session = await self._playbook_engine.execute(
                                pb_id,
                                pb_params,
                                case_id=state.case_id,
                                user_id=state.user_id,
                                role=state.role,
                            )
                            state.add_finding({
                                "type": "playbook_completed",
                                "playbook_id": pb_id,
                                "session_id": pb_session,
                                "reasoning": reasoning,
                            })
                            self.store.add_step(
                                session_id, state.step_count, 'playbook_result',
                                json.dumps({
                                    "playbook_id": pb_id,
                                    "sub_session_id": pb_session,
                                    "status": "completed",
                                }, default=str),
                            )
                        except Exception as exc:
                            state.add_finding({
                                "type": "playbook_error",
                                "playbook_id": pb_id,
                                "error": str(exc),
                            })
                            self.store.add_step(
                                session_id, state.step_count, 'playbook_error',
                                json.dumps({
                                    "playbook_id": pb_id,
                                    "error": str(exc),
                                }, default=str),
                            )
                        state.step_count += 1
                        continue
                    else:
                        state.errors.append(f"Playbook engine not available for: {pb_id}")
                        state.step_count += 1
                        continue

                # ---- Validate action field ----
                action = decision.get('action', '')
                if action not in ('use_tool', 'final_answer', 'run_playbook'):
                    # LLM returned a JSON without a valid action - treat as
                    # a thinking step and continue so it can try again.
                    state.errors.append(
                        f"LLM returned invalid action '{action}'. "
                        "Expected: use_tool, final_answer, or run_playbook."
                    )
                    state.step_count += 1
                    continue

                # ---- Resolve tool ----
                tool_name = decision.get('tool', '')
                tool_def = self.tools.get_tool(tool_name)

                if tool_def is None:
                    # Unknown tool - record error and let agent re-think
                    state.errors.append(f"Unknown tool: {tool_name}")
                    state.add_finding({
                        "type": "error",
                        "message": f"Tool '{tool_name}' not found in registry.",
                    })
                    state.step_count += 1
                    continue

                # ---- Approval gate ----
                if tool_def.requires_approval:
                    state.request_approval(
                        decision,
                        f"Tool '{tool_name}' requires analyst approval before execution.",
                    )
                    state.phase = AgentPhase.WAITING_HUMAN
                    self._notify(session_id, {
                        "type": "approval_required",
                        "tool": tool_name,
                        "params": decision.get('params', {}),
                        "reason": state.pending_approval["reason"],
                    })

                    # Wait until approve/reject/cancel
                    approved, approved_by = await self._wait_for_approval(session_id, state)
                    if state.is_terminal():
                        break

                    # Persist audit trail entry for the approval decision
                    self.store.add_audit_entry(
                        session_id=session_id,
                        action=tool_name,
                        action_type='approval_granted' if approved else 'approval_rejected',
                        actor='human',
                        requires_approval=True,
                        before_state=decision.get('params', {}),
                        approved_by=approved_by,
                        status='approved' if approved else 'rejected',
                    )

                    if not approved:
                        # Rejected - skip tool and re-think
                        state.add_finding({
                            "type": "approval_rejected",
                            "tool": tool_name,
                        })
                        state.step_count += 1
                        state.transition(AgentPhase.THINKING)
                        continue
                    # Approved - fall through to ACT
                    state.transition(AgentPhase.ACTING)
                else:
                    state.transition(AgentPhase.ACTING)

                # ---- Duplicate call guard ----
                call_sig = (tool_name, json.dumps(decision.get('params', {}), sort_keys=True, default=str))
                if call_sig in _prev_tool_calls:
                    logger.warning(
                        "[AGENT] Duplicate tool call detected: %s. Checking for real evidence...",
                        tool_name,
                    )
                    if self.tool_selector.has_successful_evidence(state):
                        break  # มี evidence จริงแล้ว → ไปสรุปผล
                    elif state.step_count < state.max_steps - 1:
                        # ยังไม่มี evidence จริงเลย (มีแต่ error) → ลอง local tool
                        # ที่มี multi-source fallback แทนที่จะ break ไปสรุปผลจาก error
                        ioc_val = decision.get('params', {}).get('indicator') \
                            or decision.get('params', {}).get('ioc', '')
                        logger.warning(
                            "[AGENT] No successful evidence yet, retrying with "
                            "investigate_ioc (multi-source fallback) instead of giving up."
                        )
                        decision = {
                            "action": "use_tool",
                            "tool": "investigate_ioc",
                            "params": {"ioc": ioc_val},
                            "reasoning": "Retry via multi-source tool after duplicate + no successful evidence",
                        }
                        call_sig = ("investigate_ioc", ioc_val)
                    else:
                        state.errors.append(
                            "Step budget exhausted without successful evidence "
                            "(only tool errors collected)"
                        )
                        break
                _prev_tool_calls.append(call_sig)

                # ---- ACT ----
                state.current_tool = tool_name
                is_mcp = '.' in tool_name
                self._notify(session_id, {
                    "type": "phase", "phase": "acting",
                    "step": state.step_count, "max_steps": state.max_steps,
                    "tool": tool_name,
                    "tool_source": "mcp" if is_mcp else "local",
                    "tool_server": tool_name.split('.')[0] if is_mcp else None,
                    "params": decision.get('params', {}),
                })

                import time as _time
                _act_start = _time.time()
                result = await self._act(state, decision)
                _act_dur = int((_time.time() - _act_start) * 1000)

                # ---- OBSERVE ----
                state.transition(AgentPhase.OBSERVING)
                state.current_tool = None
                state.add_finding({
                    "type": "tool_result",
                    "tool": tool_name,
                    "params": decision.get('params', {}),
                    "result": result,
                })
                state.step_count += 1

                # Persist findings snapshot
                self.store.update_session_findings(session_id, state.findings)

                # Notify WS with tool result for live display
                self._notify(session_id, {
                    "type": "tool_result",
                    "step": state.step_count - 1,
                    "max_steps": state.max_steps,
                    "tool": tool_name,
                    "tool_source": "mcp" if is_mcp else "local",
                    "tool_server": tool_name.split('.')[0] if is_mcp else None,
                    "duration_ms": _act_dur,
                    "params": decision.get('params', {}),
                    "result": result,
                })

                # ---- AUTO-ENRICH with MCP tools ----
                # After first local tool, automatically run relevant MCP tools
                if (tool_name in ('investigate_ioc', 'analyze_malware', 'analyze_email')
                        and state.step_count <= 3
                        and state.step_count < state.max_steps - 1):
                    mcp_calls = self.tool_selector.get_enrichment_mcp_tools(
                        tool_name, decision.get('params', {}), state.goal,
                    )
                    logger.warning(
                        "[AGENT] Auto-enrich: %d MCP tools queued for %s",
                        len(mcp_calls), tool_name,
                    )
                    for mcp_tool, mcp_params in mcp_calls:
                        if state.step_count >= state.max_steps - 1:
                            break
                        try:
                            logger.warning(
                                "[AGENT] Auto-enrich: calling %s",
                                mcp_tool,
                            )
                            state.current_tool = mcp_tool
                            state.phase = AgentPhase.ACTING
                            mcp_server = mcp_tool.split('.')[0] if '.' in mcp_tool else None
                            self._notify(session_id, {
                                "type": "phase", "phase": "acting",
                                "step": state.step_count, "max_steps": state.max_steps,
                                "tool": mcp_tool,
                                "tool_source": "mcp",
                                "tool_server": mcp_server,
                                "params": mcp_params,
                            })
                            mcp_decision = {
                                "action": "use_tool",
                                "tool": mcp_tool,
                                "params": mcp_params,
                                "reasoning": "Auto-enrichment with MCP tool",
                            }
                            _mcp_start = _time.time()
                            mcp_result = await self._act(state, mcp_decision)
                            _mcp_dur = int((_time.time() - _mcp_start) * 1000)
                            state.phase = AgentPhase.OBSERVING
                            state.current_tool = None
                            state.add_finding({
                                "type": "tool_result",
                                "tool": mcp_tool,
                                "params": mcp_params,
                                "result": mcp_result,
                            })
                            state.step_count += 1
                            self.store.update_session_findings(
                                session_id, state.findings,
                            )
                            # Notify WS with MCP tool result
                            self._notify(session_id, {
                                "type": "tool_result",
                                "step": state.step_count - 1,
                                "max_steps": state.max_steps,
                                "tool": mcp_tool,
                                "tool_source": "mcp",
                                "tool_server": mcp_server,
                                "duration_ms": _mcp_dur,
                                "params": mcp_params,
                                "result": mcp_result,
                            })
                            logger.warning(
                                "[AGENT] Auto-enrich: %s done (%dms)", mcp_tool, _mcp_dur,
                            )
                        except Exception as enrich_exc:
                            logger.warning(
                                "[AGENT] Auto-enrich %s failed: %s",
                                mcp_tool, enrich_exc,
                            )
                            state.step_count += 1

                self._notify(session_id, {
                    "type": "observation",
                    "step": state.step_count,
                    "tool": tool_name,
                    "result_preview": truncate(json.dumps(result, default=str), 500),
                })

                # Transition back to THINKING for next iteration
                state.transition(AgentPhase.THINKING)

            # ---- Loop finished ----
            if not state.is_terminal():
                if state.step_count >= state.max_steps:
                    state.errors.append(f"Step limit ({state.max_steps}) reached")
                state.phase = AgentPhase.COMPLETED

            summary = await self._generate_summary(state)
            final_status = 'completed' if state.phase == AgentPhase.COMPLETED else 'failed'
            verdict_source = extract_deterministic_verdict_source(state.findings)
            verdict = (
                extract_deterministic_verdict(state.findings)
                if verdict_source is not None else None
            )
            from .agent_response_parsing import build_evidence_card
            evidence = (
                build_evidence_card(state.findings, state.goal)
                if verdict_source is not None else None
            )
            if final_status == 'completed' and not final_answer_saved:
                final_decision = {"answer": summary}
                if verdict_source is not None and verdict is not None:
                    final_decision["verdict"] = verdict
                    final_decision["verdict_source"] = verdict_source
                    if evidence is not None:
                        final_decision["evidence"] = evidence
                else:
                    final_decision["answer"] = sanitize_unscored_answer(
                        summary, state.goal,
                    )
                try:
                    self.store.add_step(
                        session_id, state.step_count, 'final_answer',
                        json.dumps(final_decision, default=str),
                    )
                    final_answer_saved = True
                except Exception:
                    logger.warning(
                        "[AGENT] Could not save completion answer for %s",
                        session_id,
                        exc_info=True,
                    )
            self.store.update_session_status(session_id, final_status, summary)
            self.store.update_session_findings(session_id, state.findings)

            completed_frame = {
                "type": "completed",
                "status": final_status,
                "summary": summary,
                "steps": state.step_count,
                "findings_count": len(state.findings),
            }
            if verdict_source is not None:
                completed_frame["verdict"] = verdict
                completed_frame["verdict_source"] = verdict_source
            if evidence is not None:
                completed_frame["evidence"] = evidence
            self._notify(session_id, completed_frame)

        except Exception as exc:
            logger.error(f"[AGENT] Loop error for {session_id}: {exc}", exc_info=True)
            state.errors.append(str(exc))
            state.phase = AgentPhase.FAILED
            self.store.update_session_status(session_id, 'failed', str(exc))
            self._notify(session_id, {"type": "failed", "error": str(exc)})

        finally:
            # Clean up
            self._approval_events.pop(session_id, None)

    # ================================================================== #
    #  THINK - ask LLM for next action
    # ================================================================== #

    async def _think(self, state: AgentState) -> Optional[Dict]:
        """Build context and call the LLM to decide the next action."""
        tools_block = self.tool_selector.build_tools_block()
        rag_context, _ = _build_flow_b_rag_blocks(state.findings)
        sanitized_state = copy(state)
        sanitized_state.findings = _strip_rag_references(state.findings)
        findings_block = self.tool_selector.build_findings_block(sanitized_state)
        if rag_context:
            findings_block += f"\n\nValidated RAG context (Flow B only):\n{rag_context}"
        playbooks_block = self.tool_selector.build_playbooks_block()
        all_tools = self.tools.get_tools_for_llm()
        if state.role is not None:
            all_tools = [
                tool for tool in all_tools
                if is_tool_allowed(
                    state.role,
                    self.tools.get_tool(tool.get("function", {}).get("name", "")),
                )
            ]
        # Filter tools to a manageable set for the LLM
        tools_json = self.tool_selector.filter_tools_for_goal(all_tools, state.goal, state)
        has_native_tools = len(tools_json) > 0

        if has_native_tools:
            # Use the clean prompt that doesn't instruct JSON response format
            # (avoids LLM stuffing decision JSON into tool_call arguments)
            system_prompt = _SYSTEM_PROMPT.format(
                goal=state.goal,
                findings_block=findings_block,
                playbooks_block=playbooks_block,
            )
        else:
            system_prompt = _SYSTEM_PROMPT_NO_TOOLS.format(
                tools_block=tools_block,
                goal=state.goal,
                findings_block=findings_block,
                playbooks_block=playbooks_block,
            )

        messages = [
            {"role": "user", "content": system_prompt},
        ]

        # Attempt tool-calling API first, fall back to plain chat
        raw = await self._chat_with_tools(messages, tools=tools_json)
        logger.info(f"[AGENT] LLM raw response type={type(raw).__name__}, "
                     f"preview={str(raw)[:500] if raw else 'None'}")
        if raw is None:
            return None

        # If the LLM used native tool_call, convert to our decision dict
        if isinstance(raw, dict) and 'tool_calls' in raw:
            return self._parse_tool_call_response(raw)

        # Otherwise parse the text as JSON
        if isinstance(raw, str):
            parsed = self._extract_json(raw)
            if parsed is not None:
                # Normalise non-standard JSON formats into our decision dict
                parsed = normalise_decision(
                    parsed, state,
                    self.tool_selector.guess_first_tool,
                    self.tool_selector.guess_tool_params,
                )
                return parsed
            # If we can't parse JSON and native tools were available,
            # the LLM gave a plain text answer.
            if has_native_tools and raw.strip():
                # If we already have findings → real conclusion
                if state.findings:
                    deterministic_verdict = extract_deterministic_verdict(state.findings)
                    return {
                        "action": "final_answer",
                        "answer": raw.strip(),
                        "verdict": deterministic_verdict,
                        "reasoning": "LLM provided text response after tool use",
                    }
                # No findings yet → auto-dispatch
                logger.warning(
                    "[AGENT] LLM gave text instead of tool call. "
                    "Auto-dispatching tool based on goal."
                )
                return {
                    "action": "use_tool",
                    "tool": self.tool_selector.guess_first_tool(state.goal),
                    "params": self.tool_selector.guess_tool_params(state.goal),
                    "reasoning": "Auto-dispatched: LLM did not call a tool",
                }
            return None

        # Already a dict (from JSON-mode response)
        if isinstance(raw, dict):
            return raw

        return None

    # ================================================================== #
    #  ACT - execute a tool
    # ================================================================== #

    async def _act(self, state: AgentState, decision: Dict) -> Dict:
        """Execute the tool specified in *decision*."""
        tool_name = decision.get('tool', '')
        params = decision.get('params', {})
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                params = {}

        logger.info(f"[AGENT] _act: tool={tool_name}, params={params}")

        start = time.time()
        tool_def = None
        if state.role is not None and not is_tool_allowed(
            state.role, self.tools.get_tool(tool_name)
        ):
            result = {"error": "Tool is not allowed for this role"}
        else:
            result = None
        try:
            tool_def = self.tools.get_tool(tool_name)
            if result is not None:
                pass
            elif tool_def is None:
                result = {"error": f"Tool not found: {tool_name}"}
            elif tool_def.source == 'local':
                call_params = dict(params)
                if tool_name == 'investigate_ioc':
                    call_params.setdefault('analysis_id', state.session_id)
                    call_params.setdefault('user_id', state.user_id)
                result = await self.tools.execute_local_tool(tool_name, **call_params)
            elif self.mcp_client is not None:
                # MCP remote tool call
                result = await self.mcp_client.call_tool(
                    tool_def.source, tool_name.split(".", 1)[-1], params,
                )
                if not isinstance(result, dict):
                    result = {"result": result}
            else:
                result = {"error": f"MCP client not available for tool: {tool_name}"}
        except Exception as exc:
            logger.error(f"[AGENT] Tool {tool_name} failed: {exc}", exc_info=True)
            result = {"error": str(exc)}

        duration_ms = int((time.time() - start) * 1000)

        # Persist step
        self.store.add_step(
            state.session_id,
            state.step_count,
            'tool_call',
            json.dumps(decision, default=str),
            tool_name,
            json.dumps(params, default=str),
            json.dumps(result, default=str),
            duration_ms,
        )

        # Persist audit trail entry for this tool call
        self.store.add_audit_entry(
            session_id=state.session_id,
            action=tool_name,
            action_type='tool_call',
            actor='agent',
            requires_approval=bool(tool_def.requires_approval) if tool_def else False,
            after_state=result,
            status='error' if isinstance(result, dict) and 'error' in result else 'success',
        )

        return result

    # ================================================================== #
    #  Approval wait
    # ================================================================== #

    async def _wait_for_approval(
        self, session_id: str, state: AgentState,
    ) -> tuple:
        """Block until the analyst approves/rejects or the session is cancelled.

        Returns (approved: bool, approved_by: str).
        """
        evt = self._approval_events.get(session_id)
        if evt is None:
            return False, "unknown"

        evt.clear()
        # Wait up to 30 minutes for human response
        try:
            await asyncio.wait_for(evt.wait(), timeout=1800)
        except asyncio.TimeoutError:
            state.errors.append("Approval timed out (30 min)")
            state.phase = AgentPhase.FAILED
            return False, "unknown"

        approval = state.clear_approval()
        if approval is None:
            return False, "unknown"
        return approval.get("approved", False), approval.get("approved_by", "unknown")

    # ================================================================== #
    #  Summary generation
    # ================================================================== #

    async def _generate_summary(self, state: AgentState) -> str:
        """Ask the LLM to produce a concise investigation summary."""
        rag_context, rag_sources = _build_flow_b_rag_blocks(state.findings)

        # If there is a final_answer finding, use it directly
        for f in reversed(state.findings):
            if f.get("type") == "final_answer":
                answer = f.get("answer", "")
                verdict = f.get("verdict", "")
                if answer:
                    if verdict:
                        answer = f"[{verdict}] {answer}"
                    return _append_rag_sources(answer, rag_sources)

        # Otherwise ask LLM to summarise
        sanitized_findings = _strip_rag_references(state.findings[-15:])
        findings_json = json.dumps(sanitized_findings, default=str, indent=1)
        prompt = _SUMMARY_PROMPT.format(
            goal=state.goal,
            step_count=state.step_count,
            findings_json=findings_json[:4000],
            rag_context=rag_context or "(none)",
        )

        try:
            raw = await self._call_llm_text(prompt)
            if raw:
                summary = raw[:2000]
                if extract_deterministic_verdict(state.findings) is None:
                    summary = sanitize_unscored_answer(summary, state.goal)
                return _append_rag_sources(summary, rag_sources)
        except Exception as exc:
            logger.warning(f"[AGENT] Summary generation failed: {exc}")

        # Fallback
        fallback = (
            f"Investigation completed in {state.step_count} steps. "
            f"{len(state.findings)} findings collected. "
            f"Errors: {len(state.errors)}."
        )
        if extract_deterministic_verdict(state.findings) is None:
            fallback = sanitize_unscored_answer(fallback, state.goal)
        return _append_rag_sources(fallback, rag_sources)

    # ================================================================== #
    #  LLM communication (thin wrappers delegating to self.llm_backend;
    #  kept on AgentLoop because tests patch/call these directly)
    # ================================================================== #

    async def _chat_with_tools(
        self, messages: List[Dict], tools: Optional[List[Dict]] = None,
    ) -> Optional[Any]:
        return await self.llm_backend.chat_with_tools(messages, tools=tools)

    async def _call_llm_text(self, prompt: str) -> Optional[str]:
        return await self.llm_backend.call_llm_text(prompt)

    async def _ollama_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        return await self.llm_backend.ollama_chat(messages, tools)

    async def _ollama_generate(self, prompt: str) -> Optional[str]:
        return await self.llm_backend.ollama_generate(prompt)

    # ================================================================== #
    #  Response parsing helpers (thin wrappers delegating to
    #  agent_response_parsing; kept on AgentLoop because tests call
    #  these directly, e.g. AgentLoop._extract_json / loop._parse_tool_call_response)
    # ================================================================== #

    def _parse_tool_call_response(self, raw: Dict) -> Optional[Dict]:
        return parse_tool_call_response(raw)

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict]:
        return extract_json(text)
