"""
Playbook Engine - Execute predefined investigation workflows.

Supports:
  - Sequential and conditional step execution
  - ``for_each`` iteration over dynamic result sets
  - Human-in-the-loop approval checkpoints
  - YAML-based playbook definitions (loaded from ``data/playbooks/``)
  - Runtime variable interpolation in tool parameters

A playbook is a list of steps.  Each step invokes a tool and can branch
based on the outcome (``on_success`` / ``on_failure`` / ``condition``).
"""

import asyncio
import json
import logging
import operator
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import threat intel for enrichment
from ..integrations.threat_intel import ThreatIntelligence
from ..integrations.ticketing import create_incident_ticket


logger = logging.getLogger(__name__)

# Try to import yaml; fall back gracefully if not installed
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class PlaybookValidationError(ValueError):
    """Raised when playbook input fails validation."""


@dataclass
class PlaybookStep:
    """One step in a playbook."""
    name: str
    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None  # e.g. "verdict == 'MALICIOUS'"
    on_success: Optional[str] = None  # Name of the next step on success
    on_failure: Optional[str] = None  # Name of the next step on failure
    requires_approval: bool = False  # Pause for human approval
    for_each: Optional[str] = None  # Iterate over a context variable
    timeout: int = 120  # Per-step timeout in seconds
    description: str = ""
    action: Optional[str] = None  # e.g. "final_answer", "trigger_playbook", "input"

    def to_dict(self) -> Dict:
        d = {
            "name": self.name,
            "tool": self.tool,
            "params": self.params,
            "condition": self.condition,
            "on_success": self.on_success,
            "on_failure": self.on_failure,
            "requires_approval": self.requires_approval,
            "for_each": self.for_each,
            "timeout": self.timeout,
            "description": self.description,
        }
        if self.action:
            d["action"] = self.action
        return d

    @classmethod
    def from_dict(cls, d: Dict) -> "PlaybookStep":
        # Handle condition: can be a string or a dict with if/then/else
        raw_cond = d.get("condition")
        condition_str = None
        on_success = d.get("on_success")
        on_failure = d.get("on_failure")

        if isinstance(raw_cond, dict):
            # Playbook YAML format: condition: {if: "...", then: "step", else: "step"}
            condition_str = raw_cond.get("if")
            if isinstance(condition_str, str):
                condition_str = condition_str.strip()
            cond_then = raw_cond.get("then")
            cond_else = raw_cond.get("else")
            if cond_then and not on_success:
                on_success = cond_then
            if cond_else and not on_failure:
                on_failure = cond_else
        elif isinstance(raw_cond, str):
            condition_str = raw_cond

        return cls(
            name=d["name"],
            tool=d.get("tool", ""),
            params=d.get("params") or {},
            condition=condition_str,
            on_success=on_success,
            on_failure=on_failure,
            requires_approval=d.get("requires_approval", False),
            for_each=d.get("for_each"),
            timeout=d.get("timeout", 120),
            description=d.get("description", ""),
            action=d.get("action"),
        )


# ---------------------------------------------------------------------------
# Safe condition evaluator (no eval)
# ---------------------------------------------------------------------------

# Supported operators for condition parsing
_OPERATORS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}

# Regex to parse simple conditions like: variable op value
_SIMPLE_COND = re.compile(
    r"^\s*(\w[\w.]*)\s*(==|!=|>=?|<=?)\s*(.+?)\s*$"
)
# Regex to parse 'value in variable' conditions
_IN_COND = re.compile(
    r"""^\s*['"](.+?)['"]\s+in\s+(\w[\w.]*)\s*$"""
)
# Regex to parse 'variable in (val1, val2)' or 'variable in [val1, val2]' conditions
_VAR_IN_TUPLE = re.compile(
    r"""^\s*(\w[\w.]*)\s+in\s+[\(\[](.+?)[\)\]]\s*$"""
)
# Matches a string that is ENTIRELY a single {{...}} placeholder (no
# surrounding text), so the resolved value's original type can be preserved.
# Match exactly one whole-value token. Strings containing multiple tokens such
# as ``"{{first}} {{second}}"`` must use _interpolate_string instead.
_WHOLE_VAR = re.compile(r"^\{\{([^{}]+)\}\}$")


def _parse_literal(text: str) -> Any:
    """Parse a string literal into a Python value."""
    text = text.strip()
    if (text.startswith("'") and text.endswith("'")) or \
       (text.startswith('"') and text.endswith('"')):
        return text[1:-1]
    if text.lower() == "true":
        return True
    if text.lower() == "false":
        return False
    if text.lower() == "none":
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _resolve_var(var_path: str, context: Dict) -> Any:
    """Resolve a dotted path, transparently traversing MCP result wrappers."""
    parts = var_path.split(".")

    def for_each_flag_fallback() -> Any:
        if len(parts) != 2 or parts[0] in context:
            return None
        suffix = {
            "malicious": "_any_malicious",
            "suspicious": "_any_suspicious",
        }.get(parts[1])
        if suffix is None:
            return None
        key = f"{parts[0]}{suffix}"
        return context[key] if key in context else None

    obj = context
    for part in parts:
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            break
    else:
        return obj

    # MCPClientManager stores successful calls as
    # {"result": {...}, "server": ..., "tool": ...}. Preserve normal path
    # resolution first, then retry legacy playbook references through that
    # wrapper so ``step.field`` remains compatible with ``step.result.field``.
    if len(parts) < 2:
        return for_each_flag_fallback()
    root = context.get(parts[0])
    if not (
        isinstance(root, dict)
        and isinstance(root.get("result"), dict)
        and "server" in root
        and "tool" in root
    ):
        return for_each_flag_fallback()

    obj = root["result"]
    for part in parts[1:]:
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return for_each_flag_fallback()
    return obj


def _tool_call_ended_in_error(result: Any) -> bool:
    """Return whether a single tool result represents a collection failure."""
    if not isinstance(result, dict):
        return False

    if result.get("status") == "error" or result.get("error") not in (None, ""):
        return True

    inner = result.get("result")
    if not isinstance(inner, dict):
        return False
    return (
        inner.get("status") == "error"
        or inner.get("error") not in (None, "")
    )


def _store_single_step_result(
    context: Dict[str, Any], step_name: str, result: Any,
) -> None:
    """Expose a single tool call's result and reusable collection-error flag."""
    context[step_name] = result
    context["last_result"] = result
    if isinstance(result, dict):
        for key, val in result.items():
            context[f"{step_name}_{key}"] = val
    context[f"{step_name}_collection_error"] = _tool_call_ended_in_error(result)


def safe_evaluate_condition(condition: str, context: Dict) -> bool:
    """
    Evaluate a step condition safely WITHOUT using eval().

    Supported syntax:
    - ``verdict == 'MALICIOUS'``
    - ``score > 70``
    - ``score >= 50``
    - ``'ransomware' in tags``
    - ``file_type in ('PE', 'ELF')``
    - ``cond1 and cond2``   (split on ' and ')
    - ``cond1 or cond2``    (split on ' or ')
    - bare ``{{var}}`` truthy check

    Returns False on any parse error (safe default).
    """
    if not condition or not condition.strip():
        return True

    condition = condition.strip()
    # Real playbook YAML conditions use Jinja-style "{{var}} == 'x'" syntax,
    # but the pattern matchers below expect bare variable names/paths
    # ("var == 'x'"). Strip the braces so those matchers can resolve them.
    condition = condition.replace("{{", "").replace("}}", "")

    try:
        # Handle 'and' by splitting
        if " and " in condition:
            parts = condition.split(" and ")
            return all(safe_evaluate_condition(p.strip(), context) for p in parts)

        # Handle 'or' by splitting
        if " or " in condition:
            parts = condition.split(" or ")
            return any(safe_evaluate_condition(p.strip(), context) for p in parts)

        # Flatten context: include last_result fields at top level
        flat_ctx = dict(context)
        lr = context.get("last_result", {})
        if isinstance(lr, dict):
            for k, v in lr.items():
                if k not in flat_ctx:
                    flat_ctx[k] = v
        # Also flatten one level of nested dicts
        for key, val in list(context.items()):
            if isinstance(val, dict):
                for k2, v2 in val.items():
                    fk = f"{key}_{k2}"
                    if fk not in flat_ctx:
                        flat_ctx[fk] = v2

        # Pattern: 'value' in variable
        m = _IN_COND.match(condition)
        if m:
            needle = m.group(1)
            haystack = _resolve_var(m.group(2), flat_ctx)
            if isinstance(haystack, (list, tuple, set)):
                return needle in haystack
            if isinstance(haystack, str):
                return needle in haystack
            return False

        # Pattern: variable in (val1, val2, ...)
        m = _VAR_IN_TUPLE.match(condition)
        if m:
            var_val = _resolve_var(m.group(1), flat_ctx)
            tuple_items = [_parse_literal(v.strip()) for v in m.group(2).split(",")]
            return var_val in tuple_items

        # Pattern: variable op value
        m = _SIMPLE_COND.match(condition)
        if m:
            left_val = _resolve_var(m.group(1), flat_ctx)
            op_str = m.group(2)
            right_val = _parse_literal(m.group(3))

            op_func = _OPERATORS.get(op_str)
            if op_func is None:
                return False

            # Type coercion for numeric comparisons
            if isinstance(right_val, (int, float)) and left_val is not None:
                try:
                    left_val = type(right_val)(left_val)
                except (ValueError, TypeError):
                    pass

            try:
                return op_func(left_val, right_val)
            except TypeError:
                return False

        # Pattern: bare variable or dotted path (truthy check)
        if re.fullmatch(r"\w[\w.]*", condition):
            return bool(_resolve_var(condition, flat_ctx))

        # Unrecognised pattern
        logger.debug("[PLAYBOOK] Could not parse condition: %s", condition)
        return False

    except Exception as exc:
        logger.debug("[PLAYBOOK] Condition '%s' failed: %s", condition, exc)
        return False


_VERDICT_SEVERITY = {"MALICIOUS": 4, "PHISHING": 3, "SUSPICIOUS": 2, "SPAM": 1, "CLEAN": 0}


def _is_malicious_result(item) -> bool:
    """Check whether a single for_each iteration result indicates malicious.
    Tolerates MCP-wrapped results ({"result": {...}}), plain dicts, and
    error dicts (treated as not malicious). Recognizes three shapes: a
    top-level "malicious" boolean (blocklist_check, feodo_tracker_check),
    and MalwareBazaar's raw abuse.ch passthrough shape (query_status ==
    "ok" with "data" means a known-malware match), plus KEV's "in_kev"
    boolean. Read-only, never raises."""
    if not isinstance(item, dict):
        return False
    if "error" in item:
        return False
    inner = item.get("result", item)
    if not isinstance(inner, dict):
        return False
    if "error" in inner:
        return False
    if inner.get("malicious") is True:
        return True
    if inner.get("in_kev") is True:
        return True
    # MalwareBazaar raw-passthrough shape: no "malicious" key,
    # instead query_status == "ok" means a known-malware match.
    if inner.get("query_status") == "ok" and inner.get("data"):
        return True
    return False


def _aggregate_malicious_flag(results_list) -> bool:
    """Scan a for_each step's iteration_results for any item whose
    unwrapped tool result indicates malicious (see ``_is_malicious_result``
    for the recognized shapes). Read-only, never raises."""
    if not isinstance(results_list, list):
        return False
    return any(_is_malicious_result(item) for item in results_list)


def _is_suspicious_result(item) -> bool:
    """Check whether a single for_each iteration result indicates a
    suspicious (but not necessarily confirmed-malicious) finding.
    Tolerates MCP-wrapped results ({"result": {...}}), plain dicts, and
    error dicts (treated as not suspicious). Recognizes one shape so far:
    a non-empty "suspicious_keywords" list, as returned by
    remnux_tools.olevba_analyze (src/mcp_servers/remnux_tools.py:196-295)
    for flagged VBA macro indicators. Deliberately separate from
    ``_is_malicious_result`` -- "suspicious" and "malicious" are distinct
    severities in this codebase and should not be folded together.
    Read-only, never raises."""
    if not isinstance(item, dict):
        return False
    if "error" in item:
        return False
    inner = item.get("result", item)
    if not isinstance(inner, dict):
        return False
    suspicious_keywords = inner.get("suspicious_keywords")
    if isinstance(suspicious_keywords, list) and len(suspicious_keywords) > 0:
        return True
    return False


def _aggregate_suspicious_flag(results_list) -> bool:
    """Scan a for_each step's iteration_results for any item whose
    unwrapped tool result indicates a suspicious (non-malicious-confirmed)
    finding (see ``_is_suspicious_result`` for the recognized shapes).
    Read-only, never raises."""
    if not isinstance(results_list, list):
        return False
    return any(_is_suspicious_result(item) for item in results_list)


def _collect_malicious_iocs(context: Dict) -> List[str]:
    """Scan context for for_each steps whose ``{step}_any_malicious`` flag
    is True, and return the flat list of IOC values (from the matching
    ``{step}_items`` list) whose corresponding entry in ``{step}_results``
    individually tests positive for malicious (see ``_is_malicious_result``).
    Matches each iteration result to its source item by index (zipping to
    the shorter of the two lists on length mismatch). Deduplicates the
    returned list, preserving order of first occurrence. Read-only, never
    raises, returns [] on any mismatch or missing data."""
    matched: List[str] = []
    seen = set()
    try:
        for key, val in context.items():
            if not key.endswith("_any_malicious") or val is not True:
                continue
            step_name = key[: -len("_any_malicious")]
            results = context.get(f"{step_name}_results")
            items = context.get(f"{step_name}_items")
            if not isinstance(results, list) or not isinstance(items, list):
                continue
            for result, item in zip(results, items):
                if not _is_malicious_result(result):
                    continue
                if item in seen:
                    continue
                seen.add(item)
                matched.append(item)
    except Exception as exc:
        logger.debug("[PLAYBOOK] _collect_malicious_iocs failed: %s", exc)
        return []
    return matched


def _collect_malicious_file_paths(context: Dict) -> List[str]:
    """Join extract_file_hashes's pairs with computed_hash_threat_check
    results/items by index to recover file paths for hashes confirmed
    malicious. extract_file_hashes is a single-execution (non-for_each)
    step, so its raw tool result is exposed both as context["extract_file_hashes"]
    (a dict with "pairs"/"hashes" keys) and flattened as
    context["extract_file_hashes_pairs"] / context["extract_file_hashes_hashes"]
    (see _run_step_loop's nested-field exposure at line 1430-1432).
    Read-only, never raises, returns [] on any mismatch or missing data.
    Does not deduplicate by hash — only by file_path, so two different
    files sharing a hash both appear."""
    matched: List[str] = []
    seen = set()
    try:
        pairs = context.get("extract_file_hashes_pairs")
        if not isinstance(pairs, list):
            extract_step = context.get("extract_file_hashes")
            pairs = extract_step.get("pairs") if isinstance(extract_step, dict) else None
        items = context.get("computed_hash_threat_check_items")
        results = context.get("computed_hash_threat_check_results")
        if not isinstance(pairs, list) or not isinstance(items, list) or not isinstance(results, list):
            return []
        for pair, item, result in zip(pairs, items, results):
            if not isinstance(pair, dict):
                continue
            if pair.get("sha256") != item:
                continue
            if not _is_malicious_result(result):
                continue
            fp = pair.get("file_path")
            if not isinstance(fp, str) or not fp:
                continue
            if fp in seen:
                continue
            seen.add(fp)
            matched.append(fp)
    except Exception as exc:
        logger.debug("[PLAYBOOK] _collect_malicious_file_paths failed: %s", exc)
        return []
    return matched


def _find_highest_verdict(context: Dict) -> Optional[str]:
    """สแกน context หา verdict ทุกตัวที่เกิดจาก tool results ระหว่าง playbook
    แล้วคืนตัวที่รุนแรงที่สุด (read-only, ไม่แก้ context)

    Precedence: explicit "verdict"/"*_verdict" keys always win over derived
    "*_any_malicious" signals when both are present in context. This
    prevents a stale/derived malicious flag from overriding an explicit
    verdict that was set directly (e.g. verdict="CLEAN" from an upstream
    step or caller-supplied input_data). Only falls back to derived
    "*_any_malicious" signals when no explicit verdict key exists at all.
    """
    explicit = []
    derived = []
    for key, val in context.items():
        if key == "verdict" or key.endswith("_verdict"):
            if isinstance(val, str) and val.upper() in _VERDICT_SEVERITY:
                explicit.append(val.upper())
        elif key.endswith("_any_malicious") and val is True:
            derived.append("MALICIOUS")
    if explicit:
        return max(explicit, key=lambda v: _VERDICT_SEVERITY[v])
    if derived:
        return max(derived, key=lambda v: _VERDICT_SEVERITY[v])
    return None


def _find_ioc_investigation_result(context: Dict) -> Optional[Dict]:
    """Scan context for a step result dict matching the IOC
    investigation shape (verdict/threat_score/sources/ioc_type all
    present). Returns the first match, or None. Read-only, never
    raises."""
    required_keys = {'verdict', 'threat_score', 'sources', 'ioc_type'}
    for key, val in context.items():
        if isinstance(val, dict) and required_keys.issubset(val.keys()):
            return val
    return None


def _scan_report_components(
    context: Dict, step_names: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Collect report-worthy components from original playbook step results.

    Playbook execution stores each result under its step name, under
    ``last_result``, and (for dict results) under flattened aliases.  Only the
    named step entries are considered here so one result cannot be classified
    repeatedly through its aliases.  MCP results are stored as
    ``{"result": {...}, "server": ..., "tool": ...}``; that wrapper is
    unwrapped for classification while the contained result is preserved.
    """
    required_ioc_keys = {'verdict', 'threat_score', 'sources', 'ioc_type'}
    components: Dict[str, Any] = {
        "report_type": None,
        "ioc_investigation": None,
        "mitre_findings": None,
        "generated_rules": None,
        "extracted_iocs": None,
        "final_answer": None,
        "triggered_playbooks": None,
    }

    # A flattened alias is identifiable because its step-name prefix is also
    # present as an original context key.  This also excludes the synthetic
    # ``*_collection_error`` and for_each aliases without maintaining a list of
    # every alias-producing branch in the executor.
    original_entries = []
    known_step_names = set(step_names) if step_names is not None else None
    context_keys = set(context.keys())
    for key, value in context.items():
        if key in {"last_result", "session_id", "playbook_id", "input"}:
            continue
        if known_step_names is not None:
            if key not in known_step_names or not isinstance(value, dict):
                continue
            original_entries.append((key, value))
            continue
        if not isinstance(value, dict):
            continue
        if any(
            key.startswith(f"{candidate}_")
            for candidate in context_keys
            if candidate != key and isinstance(context.get(candidate), dict)
        ):
            continue
        original_entries.append((key, value))

    rule_candidates = []
    ioc_candidates = []
    for step_name, stored_result in original_entries:
        result = stored_result
        if (
            isinstance(result, dict)
            and isinstance(result.get("result"), dict)
            and "server" in result
            and "tool" in result
        ):
            result = result["result"]

        if not isinstance(result, dict):
            continue

        if (
            components["ioc_investigation"] is None
            and required_ioc_keys.issubset(result.keys())
        ):
            components["ioc_investigation"] = result

        if (
            components["mitre_findings"] is None
            and isinstance(result.get("mitre_attacks"), list)
        ):
            components["mitre_findings"] = result["mitre_attacks"]

        if "rules" in result:
            rule_candidates.append((step_name, result["rules"]))

        if "iocs" in result:
            ioc_candidates.append((step_name, result["iocs"]))

        if result.get("action") == "final_answer":
            components["final_answer"] = result

        if result.get("action") == "trigger_playbook":
            if components["triggered_playbooks"] is None:
                components["triggered_playbooks"] = []
            components["triggered_playbooks"].append(result)

    if rule_candidates:
        preferred_rules = [
            candidate for candidate in rule_candidates
            if re.search(
                r"(?:^|_)(?:final|later|confirm|generate|detection)(?:_|$)",
                candidate[0].lower(),
            )
        ]
        _, rules = (preferred_rules or rule_candidates)[-1]
        components["generated_rules"] = {"rules": rules}

    if ioc_candidates:
        preferred_iocs = [
            candidate for candidate in ioc_candidates
            if candidate[0].lower() in {"final_ioc_extract", "final_ioc_extraction"}
        ]
        _, iocs = (preferred_iocs or ioc_candidates)[-1]
        components["extracted_iocs"] = {"iocs": iocs}

    populated_fields = [
        field_name for field_name in (
            "ioc_investigation",
            "mitre_findings",
            "generated_rules",
            "extracted_iocs",
            "final_answer",
            "triggered_playbooks",
        )
        if components[field_name] is not None
    ]
    if not populated_fields:
        return None

    report_type_by_field = {
        "ioc_investigation": "ioc_investigation",
        "mitre_findings": "mitre_mapping",
        "generated_rules": "rules",
        "extracted_iocs": "iocs",
        "final_answer": "final_answer",
        "triggered_playbooks": "trigger_playbook",
    }
    components["report_type"] = (
        report_type_by_field[populated_fields[0]]
        if len(populated_fields) == 1
        else "composite"
    )
    return components


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PlaybookEngine:
    """
    Loads and executes investigation playbooks.

    A playbook is identified by its ``playbook_id`` (which is either its
    file-stem for built-in YAML playbooks or the DB ``id`` for user-created
    ones).

    The engine delegates actual tool calls to the ``agent_loop``, which
    handles MCP tool routing, local tools, and result recording.
    """

    def __init__(self, agent_loop, agent_store, notification_manager=None):
        """
        Parameters
        ----------
        agent_loop
            An object with an async ``run_tool(tool_name, params) -> dict``
            method.
        agent_store
            An ``AgentStore`` instance for persistence.
        notification_manager
            Optional ``NotificationManager`` used to alert on approval
            checkpoints and executed approved actions. May be ``None``.
        """
        self.agent_loop = agent_loop
        self.store = agent_store
        self.notification_manager = notification_manager
        # Initialize ThreatIntelligence for context enrichment
        # TODO: This assumes the agent_loop's config is available. Refactor if needed.
        if hasattr(agent_loop, 'config'):
            self.threat_intel = ThreatIntelligence(agent_loop.config)
        else:
            self.threat_intel = None
            logger.warning("[PLAYBOOK] ThreatIntelligence not initialized for enrichment.")

        # Built-in playbooks directory
        self._playbooks_dir = Path(__file__).parent.parent.parent / "data" / "playbooks"

        # In-memory cache: playbook_id -> definition dict
        self._cache: Dict[str, Dict] = {}

        # Load built-in playbooks at start
        self.load_builtin_playbooks()

    # ------------------------------------------------------------------ #
    #  Loading
    # ------------------------------------------------------------------ #

    def load_builtin_playbooks(self) -> int:
        """
        Load YAML playbook definitions from ``data/playbooks/``.

        Returns the number of playbooks loaded.
        """
        if not self._playbooks_dir.is_dir():
            logger.debug("[PLAYBOOK] No playbooks directory at %s", self._playbooks_dir)
            return 0

        if not _HAS_YAML:
            logger.warning(
                "[PLAYBOOK] PyYAML is not installed -- cannot load YAML playbooks. "
                "Install with: pip install pyyaml"
            )
            return 0

        count = 0
        for path in sorted(self._playbooks_dir.glob("*.yaml")) + sorted(self._playbooks_dir.glob("*.yml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    definition = yaml.safe_load(f)

                if not isinstance(definition, dict):
                    logger.warning("[PLAYBOOK] Skipping %s (not a dict)", path.name)
                    continue

                pid = definition.get("id", path.stem)
                definition["id"] = pid
                definition["source"] = "builtin"
                definition["file"] = str(path)

                # Validate steps
                steps = definition.get("steps", [])
                if not steps:
                    logger.warning("[PLAYBOOK] Skipping %s (no steps)", path.name)
                    continue

                # Parse steps into PlaybookStep objects (validation)
                parsed = [PlaybookStep.from_dict(s) for s in steps]
                definition["_parsed_steps"] = parsed

                self._cache[pid] = definition
                count += 1
                logger.debug("[PLAYBOOK] Loaded: %s (%d steps)", pid, len(parsed))

            except Exception as exc:
                logger.warning("[PLAYBOOK] Failed to load %s: %s", path.name, exc)

        # Also load from DB
        try:
            for pb in self.store.list_playbooks():
                pid = pb.get("id", pb.get("name", ""))
                if pid and pid not in self._cache:
                    steps_data = pb.get("steps_json", [])
                    if isinstance(steps_data, str):
                        steps_data = json.loads(steps_data)
                    self._cache[pid] = {
                        "id": pid,
                        "name": pb.get("name", pid),
                        "description": pb.get("description", ""),
                        "steps": steps_data,
                        "_parsed_steps": [PlaybookStep.from_dict(s) for s in steps_data],
                        "source": "database",
                    }
                    count += 1
        except Exception as exc:
            logger.debug("[PLAYBOOK] DB load error: %s", exc)

        logger.info("[PLAYBOOK] %d playbooks available", len(self._cache))
        return count

    # ------------------------------------------------------------------ #
    #  Accessors
    # ------------------------------------------------------------------ #

    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Get a playbook definition by ID."""
        pb = self._cache.get(playbook_id)
        if pb:
            steps = [
                s.to_dict() if hasattr(s, "to_dict") else s
                for s in pb.get("_parsed_steps", pb.get("steps", []))
            ]
            return {
                "id": pb.get("id", playbook_id),
                "name": pb.get("name", playbook_id),
                "description": pb.get("description", ""),
                "steps": steps,
                "source": pb.get("source", "unknown"),
                "trigger_type": pb.get("trigger_type", "manual"),
                "input_params": pb.get("input_params", pb.get("input", [])),
                "overview": pb.get("overview", []),
                "output": pb.get("output", ""),
                "approval_steps": sum(
                    1 for step in steps
                    if isinstance(step, dict) and step.get("requires_approval") is True
                ),
            }
        return None

    def list_playbooks(self) -> List[Dict]:
        """List all available playbooks (built-in + database)."""
        results = []
        for pid, pb in self._cache.items():
            results.append({
                "id": pid,
                "name": pb.get("name", pid),
                "category": pb.get("category", "General"),
                "description": pb.get("description", ""),
                "step_count": len(pb.get("_parsed_steps", pb.get("steps", []))),
                "steps": [s.to_dict() for s in pb.get("_parsed_steps", [])],
                "source": pb.get("source", "unknown"),
                "trigger_type": pb.get("trigger_type", "manual"),
            })
        return results

    def list_available(self) -> List[Dict]:
        """Alias for ``list_playbooks`` -- lists all available playbooks."""
        return self.list_playbooks()

    def load_playbook(self, yaml_path: str) -> Dict:
        """Load a single YAML playbook from a file path and register it.

        Args:
            yaml_path: Absolute or relative path to the YAML playbook file.

        Returns:
            Dict with playbook metadata (id, name, step_count) on success,
            or a dict with an ``error`` key on failure.
        """
        if not _HAS_YAML:
            return {"error": "PyYAML is not installed. Install with: pip install pyyaml"}

        path = Path(yaml_path)
        if not path.is_file():
            return {"error": f"Playbook file not found: {yaml_path}"}

        try:
            with open(path, "r", encoding="utf-8") as f:
                definition = yaml.safe_load(f)

            if not isinstance(definition, dict):
                return {"error": f"Invalid playbook format in {path.name} (expected a dict)"}

            pid = definition.get("id", path.stem)
            definition["id"] = pid
            definition["source"] = "file"
            definition["file"] = str(path.resolve())

            steps = definition.get("steps", [])
            if not steps:
                return {"error": f"Playbook {path.name} has no steps"}

            parsed = [PlaybookStep.from_dict(s) for s in steps]
            definition["_parsed_steps"] = parsed

            self._cache[pid] = definition

            logger.info("[PLAYBOOK] Loaded from file: %s (%d steps)", pid, len(parsed))

            return {
                "id": pid,
                "name": definition.get("name", pid),
                "description": definition.get("description", ""),
                "step_count": len(parsed),
                "source": "file",
                "file": str(path.resolve()),
            }

        except Exception as exc:
            logger.error("[PLAYBOOK] Failed to load %s: %s", yaml_path, exc)
            return {"error": f"Failed to load playbook: {exc}"}

    # ------------------------------------------------------------------ #
    #  Execution
    # ------------------------------------------------------------------ #

    def _resolve_playbook(
        self, playbook_id: str, input_data: Any,
    ) -> Tuple[Dict, str, List["PlaybookStep"], Dict]:
        """
        Look up a playbook by ID (exact, case-insensitive, or by name) and
        normalise *input_data* to a dict.

        Returns
        -------
        (pb, resolved_playbook_id, steps, normalised_input_data)

        Raises
        ------
        ValueError
            If the playbook doesn't exist or has no steps.
        """
        # --- FIX: original code had a SyntaxError here (except/elif were
        # mis-indented as if nested inside the `try` body, and `elif` had no
        # matching top-level `if`). This made the entire module fail to
        # import. Corrected below. ---
        if isinstance(input_data, str):
            try:
                input_data = json.loads(input_data) if input_data.strip() else {}
            except json.JSONDecodeError:
                input_data = {}
        elif not isinstance(input_data, dict):
            input_data = {}

        # --- FIX: avoid pointless full-cache scan when playbook_id is
        # already an exact key match; only fall back to case-insensitive /
        # name-based lookup when a direct hit isn't found. ---
        pb = self._cache.get(playbook_id)
        if pb is None:
            for cached_id, cached_pb in self._cache.items():
                if (cached_id.lower() == playbook_id.lower() or
                        cached_pb.get("name", "").lower() == playbook_id.lower()):
                    pb = cached_pb
                    playbook_id = cached_id
                    break

        if pb is None:
            raise ValueError(f"Playbook '{playbook_id}' not found")

        steps: List[PlaybookStep] = pb.get("_parsed_steps", [])
        if not steps:
            raise ValueError(f"Playbook '{playbook_id}' has no steps")

        input_data = self._fill_required_input_params(pb, input_data)

        required_params = [
            p.get("name") for p in pb.get("input_params", [])
            if isinstance(p, dict) and p.get("required") and p.get("name")
        ]
        missing_params = [
            name for name in required_params
            if (
                name not in input_data
                or not input_data[name]
                or (
                    isinstance(input_data[name], str)
                    and not input_data[name].strip()
                )
            )
        ]
        if missing_params:
            raise PlaybookValidationError(
                f"Playbook '{playbook_id}' is missing required params: "
                f"{', '.join(missing_params)}"
            )

        return pb, playbook_id, steps, input_data

    @staticmethod
    def _fill_required_input_params(pb: Dict, input_data: Dict) -> Dict:
        """
        Ensure every ``required: true`` entry in the playbook's
        ``input_params`` has a value in *input_data*.

        Callers (e.g. the chat API) often don't know a playbook's exact
        parameter names in advance and instead pass generic keys like
        ``query`` / ``user_input`` / ``message``. Without this, a template
        like ``{{alert_text}}`` is left un-interpolated whenever the caller's
        key doesn't happen to match the playbook's declared param name.

        A single missing required param is backfilled from the first generic
        key that has a value, in this priority order: ``query``,
        ``user_input``, ``message``. Playbooks with multiple required params
        must receive those values explicitly; no generic value is broadcast.
        """
        required_params = [
            p.get("name") for p in pb.get("input_params", [])
            if isinstance(p, dict) and p.get("required") and p.get("name")
        ]
        if not required_params:
            return input_data
        if len(required_params) > 1:
            return input_data

        fallback_value = None
        for generic_key in ("query", "user_input", "message"):
            if input_data.get(generic_key):
                fallback_value = input_data[generic_key]
                break

        if fallback_value is None:
            return input_data

        for name in required_params:
            if not input_data.get(name):
                input_data[name] = fallback_value

        return input_data

    async def start(
        self,
        playbook_id: str,
        input_data: Any,
        case_id: Optional[str] = None,
        user_id: Optional[int] = None,
        role: Optional[str] = None,
    ) -> str:
        """
        Start a playbook run in the background and return immediately.

        Mirrors ``AgentLoop.investigate()``: the playbook is resolved and the
        session is created synchronously (so callers get an instant 404 for
        an unknown ``playbook_id``), then the actual step-by-step execution
        runs on a background thread so the HTTP request that triggered it
        doesn't block for the playbook's full duration.

        Returns
        -------
        str
            Session ID. Poll/subscribe to it (e.g. via ``/ws/agent/{id}``)
            for progress.
        """
        pb, playbook_id, steps, input_data = self._resolve_playbook(playbook_id, input_data)

        goal = f"Playbook: {pb.get('name', playbook_id)}"
        session_id = self.store.create_session(
            goal=goal,
            case_id=case_id,
            playbook_id=playbook_id,
            user_id=user_id,
            kind="playbook",
        )

        def _run():
            asyncio.run(
                self._execute_session(
                    session_id, playbook_id, pb, steps, input_data, case_id, role,
                )
            )

        threading.Thread(
            target=_run, daemon=True, name=f"playbook-{session_id}",
        ).start()

        logger.info(
            "[PLAYBOOK] Started %s in background (session %s)",
            playbook_id, session_id,
        )
        return session_id

    async def execute(
        self,
        playbook_id: str,
        input_data: Any,
        case_id: Optional[str] = None,
        user_id: Optional[int] = None,
        role: Optional[str] = None,
    ) -> str:
        """
        Execute a playbook and block until it finishes (or hits an approval
        checkpoint).

        Use this for callers that already run off the request thread (e.g.
        the ``trigger_playbook`` action, or the LLM's ``run_playbook``
        decision inside ``AgentLoop``'s background thread). For
        HTTP-request-triggered runs, prefer ``start()`` instead so the
        request doesn't block for the playbook's full duration.

        Parameters
        ----------
        playbook_id : str
            ID of the playbook to run.
        input_data : dict
            Initial context variables (e.g. ``{"file_path": "/tmp/mal.exe"}``).
        case_id : str, optional
            Associated case ID for tracking.

        Returns
        -------
        str
            Session ID of the execution.
        """
        pb, playbook_id, steps, input_data = self._resolve_playbook(playbook_id, input_data)

        # Create a session
        goal = f"Playbook: {pb.get('name', playbook_id)}"
        session_id = self.store.create_session(
            goal=goal,
            case_id=case_id,
            playbook_id=playbook_id,
            user_id=user_id,
            kind="playbook" if user_id is not None else None,
        )

        return await self._execute_session(
            session_id, playbook_id, pb, steps, input_data, case_id, role,
        )

    async def _execute_session(
        self,
        session_id: str,
        playbook_id: str,
        pb: Dict,
        steps: List["PlaybookStep"],
        input_data: Dict,
        case_id: Optional[str],
        role: Optional[str] = None,
    ) -> str:
        """Run all steps of an already-resolved playbook for an existing
        session (fresh start, always begins at steps[0])."""

        # Execution context (variables available to steps)
        context: Dict[str, Any] = {
            "session_id": session_id,
            "playbook_id": playbook_id,
            "input": input_data,
            **input_data,
        }

        # Auto-enrich context from IPs if enabled in the playbook
        context = await self._enrich_context_if_needed(pb, context)

        # Build step lookup by name
        step_map: Dict[str, PlaybookStep] = {s.name: s for s in steps}

        logger.info(
            "[PLAYBOOK] Starting %s (session %s, %d steps)",
            playbook_id, session_id, len(steps),
        )

        step_args = (
            session_id, playbook_id, pb, steps, step_map, context,
            steps[0], 0, case_id,
        )
        if role is None:
            return await self._run_step_loop(*step_args)
        return await self._run_step_loop(*step_args, role)

    async def execute_from_step(
        self, session_id: str, approved: bool, approved_by: str = "unknown",
        role: Optional[str] = None,
    ) -> str:
        """Resume a playbook session paused at an approval checkpoint.

        Loads the context + pending step persisted (via
        ``AgentStore.update_session_metadata``) right before the pause in
        ``_run_step_loop``, executes (if approved) or skips (if rejected)
        the pending step, then continues the normal loop from there.
        """
        session = self.store.get_session(session_id)
        if session is None:
            raise ValueError(f"Session '{session_id}' not found")

        if session.get("status") != "waiting_approval":
            raise ValueError(
                f"Session '{session_id}' has no pending approval checkpoint to resume"
            )

        playbook_id = session.get("playbook_id")
        pb = self._cache.get(playbook_id)
        if pb is None:
            raise ValueError(f"Playbook '{playbook_id}' not found in cache")

        steps: List[PlaybookStep] = pb.get("_parsed_steps", [])
        step_map: Dict[str, PlaybookStep] = {s.name: s for s in steps}
        step_index_map: Dict[int, int] = {id(s): i for i, s in enumerate(steps)}

        metadata = session.get("metadata") or {}
        if not isinstance(metadata, dict) or "pending_step_name" not in metadata:
            raise ValueError(
                f"Session '{session_id}' has no pending approval checkpoint to resume"
            )

        context: Dict[str, Any] = metadata.get("context", {})
        step_number: int = metadata.get("step_number", 0)
        pending_step_name: str = metadata["pending_step_name"]
        pending_step = step_map.get(pending_step_name)
        if pending_step is None:
            raise ValueError(
                f"Pending step '{pending_step_name}' no longer exists in "
                f"playbook '{playbook_id}'"
            )

        # Claim the approval before any approved action can be dispatched.
        # The status guard above rejects subsequent resume attempts.
        self.store.update_session_status(session_id, "active")
        claimed_metadata = dict(metadata)
        claimed_metadata.pop("pending_step_name", None)
        self.store.update_session_metadata(session_id, claimed_metadata)

        case_id = metadata.get("case_id")

        if approved and pending_step.for_each:
            context, next_step_name = await self._execute_for_each(
                session_id, pending_step, context, step_number, role,
            )
            iteration_results = context[f"{pending_step.name}_results"]
            batch_items = context[f"{pending_step.name}_items"]
            action_status = (
                "error"
                if any(
                    isinstance(result, dict) and "error" in result
                    for result in iteration_results
                )
                else "success"
            )
            self.store.add_audit_entry(
                session_id=session_id,
                action=pending_step.tool,
                action_type="approval_granted",
                actor="human",
                requires_approval=True,
                before_state={
                    "for_each": pending_step.for_each,
                    "items": batch_items,
                },
                after_state=iteration_results,
                approved_by=approved_by,
                status=action_status,
            )
        elif approved:
            try:
                params = self._interpolate_params(
                    pending_step.params, context, step_name=pending_step.name,
                )
            except PlaybookValidationError as exc:
                self._record_interpolation_failure(
                    session_id, step_number, pending_step, exc,
                )
                return session_id
            self.agent_loop._notify(session_id, {
                "type": "tool_call", "step": step_number,
                "tool": pending_step.tool, "args": params,
            })
            start = time.time()
            result = await self._run_tool(
                pending_step.tool, params, pending_step.timeout,
                session_id=session_id, role=role,
            )
            duration_ms = int((time.time() - start) * 1000)
            self.agent_loop._notify(session_id, {
                "type": "tool_result", "step": step_number,
                "tool": pending_step.tool,
                "result_preview": str(result)[:500],
                "duration": duration_ms,
            })

            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="tool_call",
                content=pending_step.description or pending_step.name,
                tool_name=pending_step.tool,
                tool_params=json.dumps(params, default=str),
                tool_result=json.dumps(result, default=str)[:10000],
                duration_ms=duration_ms,
            )
            action_status = "error" if isinstance(result, dict) and "error" in result else "success"
            self.store.add_audit_entry(
                session_id=session_id,
                action=pending_step.tool,
                action_type="approval_granted",
                actor="human",
                requires_approval=True,
                before_state=params,
                after_state=result,
                approved_by=approved_by,
                status=action_status,
            )
            if self.notification_manager:
                try:
                    self.notification_manager.notify("action_executed", {
                        "tool": pending_step.tool,
                        "session_id": session_id,
                        "status": action_status,
                        "approved_by": approved_by,
                        "actor": approved_by,
                        "owner": approved_by,
                    })
                except Exception as notify_exc:
                    logger.warning(
                        "[PLAYBOOK] Notification dispatch failed: %s", notify_exc,
                    )

            _store_single_step_result(context, pending_step.name, result)

            success = not (isinstance(result, dict) and "error" in result)
            next_step_name = pending_step.on_success if success else pending_step.on_failure
        else:
            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="approval_rejected",
                content=f"Approval rejected: {pending_step.description or pending_step.name}",
                tool_name=pending_step.tool,
            )
            try:
                before_state = self._interpolate_params(
                    pending_step.params, context, step_name=pending_step.name,
                )
            except PlaybookValidationError as exc:
                self._record_interpolation_failure(
                    session_id, step_number, pending_step, exc,
                )
                return session_id
            self.store.add_audit_entry(
                session_id=session_id,
                action=pending_step.tool,
                action_type="approval_rejected",
                actor="human",
                requires_approval=True,
                before_state=before_state,
                approved_by=approved_by,
                status="rejected",
            )
            # Preserve the rejection in the execution context.  Downstream
            # steps may reference fields from this step; those fields do not
            # exist because the protected action was intentionally skipped.
            # Marking the step lets the loop skip dependent work instead of
            # treating a missing result as a malformed playbook.
            skipped_steps = context.setdefault("_skipped_steps", {})
            skipped_steps[pending_step.name] = {
                "status": "rejected",
                "reason": "approval rejected",
            }
            context[pending_step.name] = {
                "status": "rejected",
                "skipped": True,
                "reason": "approval rejected",
            }
            context["last_result"] = context[pending_step.name]
            next_step_name = pending_step.on_failure

        next_step = self._resolve_next(next_step_name, step_map, steps, pending_step, step_index_map)

        step_args = (
            session_id, playbook_id, pb, steps, step_map, context,
            next_step, step_number, case_id,
        )
        if role is None:
            return await self._run_step_loop(*step_args)
        return await self._run_step_loop(*step_args, role)

    async def _execute_for_each(
        self,
        session_id: str,
        current_step: "PlaybookStep",
        context: Dict[str, Any],
        step_number: int,
        role: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """Run a for_each step's iteration and return (context, next step)."""
        items = _resolve_var(current_step.for_each, context)
        if not isinstance(items, list):
            items = [items] if items else []

        logger.debug(
            "[PLAYBOOK] for_each '%s': %d items",
            current_step.for_each, len(items),
        )

        iteration_results = []
        for i, item in enumerate(items[:50]):  # Cap iterations
            iter_context = {**context, "item": item, "item_index": i}
            params = self._interpolate_params(
                current_step.params, iter_context, step_name=current_step.name,
            )

            self.agent_loop._notify(session_id, {
                "type": "tool_call", "step": step_number,
                "tool": current_step.tool, "args": params,
            })
            start = time.time()
            result = await self._run_tool(
                current_step.tool, params, current_step.timeout,
                session_id=session_id, role=role,
            )
            duration_ms = int((time.time() - start) * 1000)
            self.agent_loop._notify(session_id, {
                "type": "tool_result", "step": step_number,
                "tool": current_step.tool,
                "result_preview": str(result)[:500],
                "duration": duration_ms,
            })

            iteration_results.append(result)

            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="for_each_iteration",
                content=f"{current_step.name} (item {i})",
                tool_name=current_step.tool,
                tool_params=json.dumps(params, default=str),
                tool_result=json.dumps(result, default=str)[:10000],
                duration_ms=duration_ms,
            )

        context[f"{current_step.name}_results"] = iteration_results
        context["last_result"] = iteration_results
        context[f"{current_step.name}_any_malicious"] = _aggregate_malicious_flag(iteration_results)
        context[f"{current_step.name}_any_suspicious"] = _aggregate_suspicious_flag(iteration_results)
        context[f"{current_step.name}_items"] = items

        # Determine success
        has_error = any("error" in r for r in iteration_results if isinstance(r, dict))
        next_step_name = current_step.on_failure if has_error else current_step.on_success
        return context, next_step_name

    async def _run_step_loop(
        self,
        session_id: str,
        playbook_id: str,
        pb: Dict,
        steps: List["PlaybookStep"],
        step_map: Dict[str, "PlaybookStep"],
        context: Dict[str, Any],
        current_step: Optional["PlaybookStep"],
        step_number: int,
        case_id: Optional[str],
        role: Optional[str] = None,
    ) -> str:
        """Run the step loop starting at *current_step* / *step_number* with
        the given *context*. Shared by a fresh ``_execute_session`` start
        (step 0) and ``execute_from_step`` resuming after an approval gate."""
        step_index_map: Dict[int, int] = {id(s): i for i, s in enumerate(steps)}
        errors_by_step: Dict[str, None] = {}
        try:
            while current_step is not None:
                step_number += 1

                # Safety: prevent infinite loops
                if step_number > 200:
                    logger.error("[PLAYBOOK] Step limit (200) reached -- aborting")
                    self.store.update_session_status(
                        session_id, "failed",
                        summary="Aborted: exceeded maximum step count (200)",
                    )
                    return session_id

                # Pure decision/branch step: มี condition แต่ไม่มี tool/action/for_each เลย
                # แปลว่าเป็น branch node ล้วน ๆ (if/then/else) ไม่ใช่ tool ที่มี precondition
                # ต้อง resolve ทันทีจากผลของ condition โดยไม่ตกไป execute เป็น tool call
                if (current_step.condition and not current_step.tool
                        and not current_step.action and not current_step.for_each):
                    decision_result = self.evaluate_condition(current_step.condition, context)
                    next_step_name = (
                        current_step.on_success if decision_result else current_step.on_failure
                    )
                    logger.info(
                        "[PLAYBOOK] Decision step '%s': condition=%s -> next='%s'",
                        current_step.name, decision_result, next_step_name,
                    )
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="decision",
                        content=(
                            f"{current_step.description or current_step.name}: "
                            f"condition evaluated to {decision_result}"
                        ),
                        tool_name="",
                        tool_params="",
                        tool_result=json.dumps({"decision": decision_result}, default=str),
                        duration_ms=0,
                    )
                    self.agent_loop._notify(session_id, {
                        "type": "step", "step": step_number,
                    })
                    context[current_step.name] = {"decision": decision_result}
                    context["last_result"] = context[current_step.name]
                    current_step = self._resolve_next(
                        next_step_name, step_map, steps, current_step, step_index_map,
                    )
                    continue

                # Evaluate condition (gate สำหรับ step ที่มี tool ควบคู่กับ condition -- ของเดิม)
                if current_step.condition:
                    if not self.evaluate_condition(current_step.condition, context):
                        logger.debug(
                            "[PLAYBOOK] Skipping step '%s' (condition false)",
                            current_step.name,
                        )
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="skipped",
                            content=(
                                f"Skipped: condition '{current_step.condition}' "
                                "evaluated false"
                            ),
                            tool_name=current_step.tool,
                        )
                        context[current_step.name] = {
                            "status": "skipped",
                            "skipped": True,
                            "reason": "condition evaluated false",
                        }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, current_step, step_index_map,
                        )
                        continue

                    # Human approval checkpoint
                if current_step.requires_approval:
                    logger.info(
                        "[PLAYBOOK] Step '%s' requires human approval -- pausing",
                        current_step.name,
                    )
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="approval_required",
                        content=f"Waiting for approval: {current_step.description or current_step.name}",
                        tool_name=current_step.tool,
                        tool_params=json.dumps(
                            self._interpolate_params(
                                current_step.params, context, step_name=current_step.name,
                            ),
                            default=str,
                        ),
                    )
                    self.store.add_audit_entry(
                        session_id=session_id,
                        action=current_step.tool,
                        action_type="approval_required",
                        actor="system",
                        requires_approval=True,
                        before_state=self._interpolate_params(
                            current_step.params, context, step_name=current_step.name,
                        ),
                        status="pending",
                    )
                    if self.notification_manager:
                        try:
                            self.notification_manager.notify("approval_required", {
                                "tool": current_step.tool,
                                "session_id": session_id,
                                "description": current_step.description or current_step.name,
                            })
                        except Exception as notify_exc:
                            logger.warning(
                                "[PLAYBOOK] Notification dispatch failed: %s", notify_exc,
                            )
                    # Persist context + pending step so execute_from_step can
                    # resume exactly where this run paused.
                    self.store.update_session_metadata(session_id, {
                        "context": context,
                        "pending_step_name": current_step.name,
                        "step_number": step_number,
                        "case_id": case_id,
                    })
                    self.store.update_session_status(session_id, "waiting_approval")
                    self.agent_loop._notify(session_id, {
                        "type": "approval_required",
                        "tool": current_step.tool,
                        "description": current_step.description or current_step.name,
                    })

                    # Execution pauses here. Call execute_from_step(session_id,
                    # approved) to resume -- it reloads the persisted
                    # context/pending step and continues the loop.
                    return session_id

                # Handle action-only steps (no tool call needed)
                if current_step.action and not current_step.tool:
                    action = current_step.action
                    params = self._interpolate_params(
                        current_step.params, context, step_name=current_step.name,
                    )

                    if action == "final_answer":
                        # Terminal step: record description as final report
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="final_answer",
                            content=current_step.description or current_step.name,
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(
                                {"action": "final_answer", "report": current_step.description},
                                default=str,
                            ),
                            duration_ms=0,
                        )
                        self.agent_loop._notify(session_id, {
                            "type": "step", "step": step_number,
                        })
                        context[current_step.name] = {
                            "action": "final_answer",
                            "report": current_step.description,
                        }
                        context["last_result"] = context[current_step.name]
                        # final_answer is terminal — go to next sequential or end
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, current_step, step_index_map,
                        )
                        continue

                    elif action == "trigger_playbook":
                        # Trigger another playbook
                        target_pb = params.get("playbook", "")
                        trigger_input = {k: v for k, v in params.items() if k != "playbook"}
                        trigger_input.update({k: v for k, v in context.items()
                                              if k not in ("session_id", "playbook_id", "input")})

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="trigger_playbook",
                            content=f"Triggering playbook: {target_pb}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )
                        self.agent_loop._notify(session_id, {
                            "type": "step", "step": step_number,
                        })

                        try:
                            parent_session = self.store.get_session(session_id)
                            parent_user_id = (
                                parent_session.get("user_id")
                                if isinstance(parent_session, dict)
                                else None
                            )
                            sub_session = await self.execute(
                                target_pb,
                                trigger_input,
                                case_id=case_id,
                                user_id=parent_user_id,
                                role=role if parent_user_id is not None else None,
                            )
                            context[current_step.name] = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "sub_session_id": sub_session,
                            }
                        except Exception as exc:
                            logger.warning(
                                "[PLAYBOOK] trigger_playbook '%s' failed: %s",
                                target_pb, exc,
                            )
                            context[current_step.name] = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "error": str(exc),
                            }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, current_step, step_index_map,
                        )
                        continue

                    elif action == "input":
                        # Input step: use existing context data or record prompt
                        prompt = params.get("prompt", current_step.description)
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="input",
                            content=f"Input: {prompt}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(
                                {"action": "input", "prompt": prompt, "value": prompt},
                                default=str,
                            ),
                            duration_ms=0,
                        )
                        context[current_step.name] = {
                            "action": "input",
                            "value": prompt,
                        }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, current_step, step_index_map,
                        )
                        continue

                    else:
                        # Unknown action — log and skip
                        logger.warning(
                            "[PLAYBOOK] Unknown action '%s' in step '%s'",
                            action, current_step.name,
                        )
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="action",
                            content=f"Action: {action} - {current_step.description}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )
                        context[current_step.name] = {"action": action}
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, current_step, step_index_map,
                        )
                        continue

                # Handle for_each iteration
                if current_step.for_each:
                    context, next_step_name = await self._execute_for_each(
                        session_id, current_step, context, step_number, role,
                    )
                    iteration_results = context.get(f"{current_step.name}_results", [])
                    if any(
                        isinstance(result, dict) and "error" in result
                        for result in iteration_results
                    ):
                        errors_by_step.setdefault(current_step.name, None)

                else:
                    # Single execution
                    try:
                        params = self._interpolate_params(
                            current_step.params, context, step_name=current_step.name,
                        )
                    except PlaybookValidationError as exc:
                        if not self._is_skipped_dependency_error(exc, context):
                            raise
                        logger.info(
                            "[PLAYBOOK] Skipping '%s' because an upstream step "
                            "was rejected: %s",
                            current_step.name,
                            exc,
                        )
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="skipped_dependency",
                            content=f"Skipped: {exc}",
                            tool_name=current_step.tool,
                        )
                        context[current_step.name] = {
                            "status": "skipped",
                            "skipped": True,
                            "reason": str(exc),
                        }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_failure,
                            step_map,
                            steps,
                            current_step,
                            step_index_map,
                        )
                        continue

                    self.agent_loop._notify(session_id, {
                        "type": "tool_call", "step": step_number,
                        "tool": current_step.tool, "args": params,
                    })
                    start = time.time()
                    result = await self._run_tool(
                        current_step.tool, params, current_step.timeout,
                        session_id=session_id, role=role,
                    )
                    duration_ms = int((time.time() - start) * 1000)
                    self.agent_loop._notify(session_id, {
                        "type": "tool_result", "step": step_number,
                        "tool": current_step.tool,
                        "result_preview": str(result)[:500],
                        "duration": duration_ms,
                    })

                    # Record step
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="tool_call",
                        content=current_step.description or current_step.name,
                        tool_name=current_step.tool,
                        tool_params=json.dumps(params, default=str),
                        tool_result=json.dumps(result, default=str)[:10000],
                        duration_ms=duration_ms,
                    )

                    # Store result in context
                    _store_single_step_result(context, current_step.name, result)
                    if isinstance(result, dict) and "error" in result:
                        errors_by_step.setdefault(current_step.name, None)

                    # Determine next step
                    success = not (isinstance(result, dict) and "error" in result)
                    next_step_name = (
                        current_step.on_success if success else current_step.on_failure
                    )

                context["collected_malicious_iocs"] = _collect_malicious_iocs(context)
                context["collected_malicious_file_paths"] = _collect_malicious_file_paths(context)

                # Resolve the next step
                current_step = self._resolve_next(
                    next_step_name, step_map, steps, current_step, step_index_map,
                )

            # All steps completed
            highest_verdict = _find_highest_verdict(context)
            summary = (
                f"Playbook '{pb.get('name', playbook_id)}' completed "
                f"({step_number} steps executed)"
            )
            if errors_by_step:
                failed_step_names = list(errors_by_step)
                shown_names = ", ".join(failed_step_names[:5])
                if len(failed_step_names) > 5:
                    shown_names += ", …"
                failed_count = len(failed_step_names)
                summary += (
                    f" — WARNING: {failed_count} step(s) failed or were denied: "
                    f"{shown_names}"
                )
            if highest_verdict:
                summary += f" — highest verdict: {highest_verdict}"

            ticket_verdicts = self.agent_loop.config.get("ticketing", {}).get(
                "create_on_verdict", ["MALICIOUS", "SUSPICIOUS"],
            )
            malicious_iocs = context.get("collected_malicious_iocs") or _collect_malicious_iocs(context)
            should_ticket = highest_verdict in ticket_verdicts
            if should_ticket and session_id:
                session = self.store.get_session(session_id)
                owner_id = session.get("user_id") if isinstance(session, dict) else None
                ticket_verdict = highest_verdict or "MALICIOUS"
                tickets_to_create = list(malicious_iocs)
                if not tickets_to_create:
                    # Playbooks with no for_each step (e.g. malware_analysis.yaml,
                    # ioc_triage.yaml) never populate {step}_any_malicious, so
                    # malicious_iocs is always empty here even when highest_verdict
                    # matches config. Fall back to a single ticket so these runs
                    # still get an audit record, trying progressively
                    # less-specific identifiers: direct IOC input -> IOC
                    # investigation result's ioc -> file hash (malware playbooks)
                    # -> file path -> last resort.
                    fallback_result = _find_ioc_investigation_result(context)
                    fallback_ioc = (
                        context.get("ioc")
                        or (fallback_result or {}).get("ioc")
                        or _resolve_var("local_full_analysis.hashes.sha256", context)
                        or context.get("file_path")
                        or "unknown_ioc"
                    )
                    tickets_to_create = [fallback_ioc]
                for ioc in tickets_to_create:
                    try:
                        ticket_job_result = {
                            "ioc": ioc,
                            "verdict": ticket_verdict,
                            "summary": summary,
                            "recommendations": "",
                        }
                        create_incident_ticket(
                            ticket_job_result, session_id, owner_id=owner_id,
                        )
                    except Exception as e:
                        logger.error(
                            "[PLAYBOOK] Failed to create incident ticket for %s: %s",
                            ioc, e,
                        )

            legacy_ioc = _find_ioc_investigation_result(context)
            components = _scan_report_components(
                context, [step.name for step in steps]
            )
            if legacy_ioc is not None or components is not None:
                try:
                    existing = self.store.get_session(session_id) or {}
                    existing_metadata = existing.get('metadata') or {}
                    if not isinstance(existing_metadata, dict):
                        existing_metadata = {}
                    if legacy_ioc is not None:
                        ioc = context.get('ioc') or legacy_ioc.get('ioc') or 'unknown_ioc'
                        existing_metadata['ioc_investigation_result'] = legacy_ioc
                        existing_metadata['ioc'] = ioc
                    if components is not None:
                        existing_metadata['report_envelope'] = components
                    self.store.update_session_metadata(session_id, existing_metadata)
                    if "report data available" not in summary:
                        summary += " — report data available"
                except Exception as meta_exc:
                    logger.warning(
                        "[PLAYBOOK] Failed to persist report data to session "
                        "metadata for %s: %s", session_id, meta_exc,
                    )

            self.store.update_session_status(session_id, "completed", summary=summary)
            self.agent_loop._notify(session_id, {"type": "completed", "summary": summary})
            logger.info(
                "[PLAYBOOK] Completed %s (session %s, %d steps)",
                playbook_id, session_id, step_number,
            )

        except Exception as exc:
            logger.error(
                "[PLAYBOOK] Execution error in %s step %d: %s",
                playbook_id, step_number, exc,
            )
            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="error",
                content=f"Playbook error: {exc}",
            )
            self.store.update_session_status(
                session_id, "failed", summary=f"Error: {str(exc)[:200]}",
            )
            self.agent_loop._notify(session_id, {"type": "failed", "error": str(exc)[:200]})

        return session_id

    # ------------------------------------------------------------------ #
    #  Condition evaluation
    # ------------------------------------------------------------------ #

    def evaluate_condition(self, condition: str, context: Dict) -> bool:
        """
        Evaluate a step condition against the current context.

        Delegates to ``safe_evaluate_condition`` which uses pattern matching
        instead of eval() for safety.

        Supported syntax:
        - ``verdict == 'MALICIOUS'``
        - ``score > 70``
        - ``score >= 50 and verdict != 'CLEAN'``
        - ``'ransomware' in tags``
        - ``file_type in ('PE', 'ELF')``
        """
        return safe_evaluate_condition(condition, context)

    async def _enrich_context_if_needed(self, pb: Dict, context: Dict) -> Dict:
        """
        If the playbook has `auto_enrich_context: true`, find related IOCs.

        Specifically, if the context only contains an IP address, this function
        will attempt to find related domains and file hashes from VirusTotal
        to allow other playbook steps (like file analysis) to run.
        """
        if not pb.get("auto_enrich_context"):
            return context

        if not self.threat_intel:
            logger.warning("[PLAYBOOK] Skipping enrichment: ThreatIntel not available.")
            return context

        has_ips = bool(context.get("ip_addresses") or context.get("ip_address"))
        has_domains = bool(context.get("domains") or context.get("domain"))
        has_hashes = bool(context.get("file_hashes") or context.get("hash"))

        if not (has_ips and not has_domains and not has_hashes):
            return context

        ips = context.get("ip_addresses") or [context.get("ip_address")]
        ips = [ip for ip in ips if ip]

        if not ips:
            return context

        logger.info(f"[PLAYBOOK] Auto-enriching context for {len(ips)} IP(s)...")

        if "domains" not in context:
            context["domains"] = []
        if "file_hashes" not in context:
            context["file_hashes"] = []

        for ip in ips:
            try:
                logger.debug(f"[PLAYBOOK] Getting raw VT report for IP: {ip}")
                report = await asyncio.wait_for(
                    self.threat_intel.get_raw_virustotal_report(ip, "ipv4"),
                    timeout=15.0,
                )

                if "error" in report or "data" not in report:
                    logger.warning(f"[PLAYBOOK] Enrichment for {ip} failed: {report.get('error', 'No data')}")
                    continue

                relationships = report["data"].get("relationships", {})

                # Extract domains from resolutions
                resolutions = relationships.get("resolutions", {}).get("data", [])
                found_domains = [res["id"] for res in resolutions if res.get("type") == "domain"]
                new_domains = [d for d in found_domains if d not in context["domains"]]
                if new_domains:
                    context["domains"].extend(new_domains)
                    logger.info(f"[PLAYBOOK] Enriched {len(new_domains)} domains for {ip}")

                # Extract hashes from files
                comm_files = relationships.get("communicating_files", {}).get("data", [])
                down_files = relationships.get("downloaded_files", {}).get("data", [])
                found_hashes = [f["id"] for f in comm_files + down_files]
                new_hashes = [h for h in found_hashes if h not in context["file_hashes"]]
                if new_hashes:
                    context["file_hashes"].extend(new_hashes)
                    logger.info(f"[PLAYBOOK] Enriched {len(new_hashes)} file hashes for {ip}")

            except asyncio.TimeoutError:
                logger.warning(
                    f"[PLAYBOOK] Context enrichment timed out for IP: {ip}. Proceeding."
                )
            except Exception as e:
                logger.warning(
                    f"[PLAYBOOK] Context enrichment failed for IP: {ip} (error: {e}). Proceeding."
                )

        return context


    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    async def _run_tool(
        self,
        tool_name: str,
        params: Dict,
        timeout: int,
        session_id: str = None,
        role: Optional[str] = None,
    ) -> Dict:
        """
        Run a tool via the agent loop with a timeout.

        Returns the tool result dict, or an ``error`` dict on failure/timeout.
        """
        try:
            if hasattr(self.agent_loop, "run_tool"):
                import asyncio
                call_params = dict(params)
                if tool_name == "investigate_ioc" and "analysis_id" not in call_params:
                    call_params["analysis_id"] = session_id
                if tool_name == "investigate_ioc" and "user_id" not in call_params:
                    session = self.store.get_session(session_id)
                    if isinstance(session, dict) and session.get("user_id") is not None:
                        call_params["user_id"] = session["user_id"]
                if role is None:
                    # Preserve compatibility with lightweight test/dry-run
                    # loop adapters that implement the original two-argument
                    # interface. Production role-aware calls always take the
                    # guarded branch below.
                    dispatch = self.agent_loop.run_tool(tool_name, call_params)
                else:
                    dispatch = self.agent_loop.run_tool(
                        tool_name,
                        call_params,
                        role=role,
                        context={"role": role, "session_id": session_id},
                    )
                result = await asyncio.wait_for(dispatch, timeout=timeout)
                return result if isinstance(result, dict) else {"result": result}
            else:
                return {"error": "agent_loop has no run_tool method"}
        except TimeoutError:
            return {"error": f"Tool '{tool_name}' timed out after {timeout}s"}
        except Exception as exc:
            return {"error": f"Tool '{tool_name}' failed: {exc}"}

    def _record_interpolation_failure(
        self,
        session_id: str,
        step_number: int,
        step: "PlaybookStep",
        exc: PlaybookValidationError,
    ) -> None:
        """Record an interpolation validation failure on a playbook session."""
        logger.error(
            "[PLAYBOOK] Interpolation error in step '%s': %s",
            step.name, exc,
        )
        self.store.add_step(
            session_id=session_id,
            step_number=step_number,
            step_type="error",
            content=f"Playbook error: {exc}",
            tool_name=step.tool,
        )
        self.store.add_audit_entry(
            session_id=session_id,
            action=step.tool,
            action_type="error",
            actor="system",
            requires_approval=step.requires_approval,
            before_state=step.params,
            after_state={"error": str(exc)},
            status="failed",
        )
        self.store.update_session_status(
            session_id, "failed", summary=f"Error: {str(exc)[:200]}",
        )
        self.agent_loop._notify(
            session_id, {"type": "failed", "error": str(exc)[:200]},
        )

    @staticmethod
    def _is_skipped_dependency_error(
        exc: PlaybookValidationError,
        context: Dict[str, Any],
    ) -> bool:
        """Return whether an interpolation error depends on a rejected step."""
        match = re.search(r"Unresolved template '\{\{(.+?)\}\}'", str(exc))
        if not match:
            return False
        variable_root = match.group(1).strip().split(".", 1)[0]
        skipped_steps = context.get("_skipped_steps", {})
        return isinstance(skipped_steps, dict) and variable_root in skipped_steps

    def _interpolate_params(
        self,
        params: Dict,
        context: Dict,
        step_name: Optional[str] = None,
        param_path: str = "",
    ) -> Dict:
        """
        Replace ``{{variable}}`` placeholders in parameter values with
        values from the context.

        Supports:
        - ``{{file_path}}`` -- simple variable
        - ``{{step_name.field}}`` -- nested access
        - ``{{item}}`` -- current for_each item
        """
        result = {}
        for key, value in params.items():
            current_path = f"{param_path}.{key}" if param_path else str(key)
            if isinstance(value, str):
                whole_match = _WHOLE_VAR.match(value.strip())
                if whole_match:
                    template = whole_match.group(1).strip()
                    resolved = _resolve_var(template, context)
                    if resolved is None:
                        raise PlaybookValidationError(
                            f"Unresolved template '{{{{{template}}}}}' in "
                            f"step '{step_name or '<unknown>'}', "
                            f"param '{current_path}'"
                        )
                    result[key] = resolved
                else:
                    result[key] = self._interpolate_string(
                        value,
                        context,
                        step_name=step_name,
                        param_key=current_path,
                    )
            elif isinstance(value, dict):
                result[key] = self._interpolate_params(
                    value,
                    context,
                    step_name=step_name,
                    param_path=current_path,
                )
            elif isinstance(value, list):
                result[key] = [
                    self._interpolate_string(
                        v,
                        context,
                        step_name=step_name,
                        param_key=f"{current_path}[{index}]",
                    ) if isinstance(v, str) else v
                    for index, v in enumerate(value)
                ]
            else:
                result[key] = value
        return result

    @staticmethod
    def _interpolate_string(
        template: str,
        context: Dict,
        step_name: Optional[str] = None,
        param_key: str = "<unknown>",
    ) -> str:
        """Replace ``{{var}}`` tokens in a string."""

        def _replacer(match):
            var_path = match.group(1).strip()
            resolved = _resolve_var(var_path, context)
            if resolved is not None:
                return str(resolved)
            raise PlaybookValidationError(
                f"Unresolved template '{match.group(0)}' in "
                f"step '{step_name or '<unknown>'}', param '{param_key}'"
            )

        return re.sub(r"\{\{(.+?)\}\}", _replacer, template)

    @staticmethod
    def _resolve_next(
        next_name: Optional[str],
        step_map: Dict[str, PlaybookStep],
        steps: List[PlaybookStep],
        current_step: Optional[PlaybookStep],
        step_index_map: Dict[int, int],
    ) -> Optional[PlaybookStep]:
        """
        Resolve the next step to execute.

        If ``next_name`` is given, look it up in ``step_map``.
        Otherwise fall through to the next step in ``steps`` (by actual list
        position via ``step_index_map``, keyed on object identity — NOT the
        step-execution counter, which does not track list position when steps
        are skipped or jumped to out of order).
        ``None`` means the playbook is done.
        """
        if next_name == "__end__" or next_name == "end":
            return None

        if next_name:
            return step_map.get(next_name)

        # Default: next step by actual list position (identity-based lookup)
        if current_step is None:
            return None
        current_idx = step_index_map.get(id(current_step))
        if current_idx is None:
            return None
        next_idx = current_idx + 1
        if next_idx < len(steps):
            return steps[next_idx]

        return None

    # ------------------------------------------------------------------ #
    #  Playbook creation
    # ------------------------------------------------------------------ #

    def register_playbook(
        self,
        name: str,
        description: str,
        steps: List[Dict],
        trigger_type: str = "manual",
    ) -> str:
        """
        Register a new playbook (saved to DB and cache).

        Returns the playbook ID.
        """
        # Validate steps
        parsed = [PlaybookStep.from_dict(s) for s in steps]

        pid = self.store.save_playbook(
            name=name,
            description=description,
            steps=steps,
            trigger_type=trigger_type,
        )

        self._cache[pid] = {
            "id": pid,
            "name": name,
            "description": description,
            "steps": steps,
            "_parsed_steps": parsed,
            "source": "database",
            "trigger_type": trigger_type,
        }

        logger.info("[PLAYBOOK] Registered: %s (%d steps)", name, len(parsed))
        return pid
