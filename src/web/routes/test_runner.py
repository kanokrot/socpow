"""Admin-only pytest collection and execution for the dashboard."""

from __future__ import annotations

import asyncio
import ast
import os
from pathlib import Path
import tokenize
import re
import signal
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..auth import require_role

TEST_TIMEOUT_SECONDS = 600
PROJECT_ROOT = Path(__file__).resolve().parents[3]
TOPIC_METADATA = {
    "agent": {"name": "Agent workflows", "description": "Checks how agents plan, call tools, and finish work."},
    "scoring": {"name": "Scoring", "description": "Checks how indicators and evidence affect risk scores."},
    "auth": {"name": "Access and identity", "description": "Checks sign-in, roles, and protected pages."},
    "web": {"name": "Web dashboard", "description": "Checks dashboard pages, routes, and API behavior."},
    "threat_intel": {"name": "Threat intelligence", "description": "Checks threat feeds, lookups, and indicator handling."},
    "mcp": {"name": "MCP tools", "description": "Checks tool registration and MCP integrations."},
    "other": {"name": "Other system checks", "description": "Checks shared utilities and remaining system behavior."},
}
TOPIC_FILENAME_MAP = {
    "mcp": ("mcp",),
    "agent": ("agent", "orchestrat", "workflow", "tool_call", "playbook", "approval", "chat", "llm", "rag", "tool", "sandbox", "step", "for_each", "follow_up", "resume", "ticket", "intent", "greeting", "remote_tool", "notification", "resolve_var"),
    "scoring": ("scor", "risk", "severity", "confidence", "verdict", "recommendation", "sensitivity", "reliability", "source_weight", "condition", "allowlist", "validator", "rule", "detection_rule", "source_counts"),
    "auth": ("auth", "authentication", "permission", "role", "session", "login", "access", "rbac", "audit", "team_lead"),
    "web": ("web", "dashboard", "route", "page", "api", "template", "static", "ui", "layout", "branding", "theme", "history", "nav", "visibility", "export", "report", "case_", "cases", "settings", "config", "upload", "font", "rate_limiter", "runner"),
    "threat_intel": ("threat", "threatfox", "virustotal", "ioc", "feed", "osint", "indicator", "intelligence", "alienvault", "censys", "dga", "domain", "email", "file", "hash", "macro", "deobfus", "extract", "forensic", "certificate", "firewall", "ip_", "url_", "spamhaus", "sslbl", "typosquat", "yara", "sigma", "mitre", "kill_chain", "packer", "office", "pdf", "shellcode", "malware", "capabilities", "persistence", "containment", "analysis", "c2", "g3_fire", "alert"),
}
router = APIRouter()

_state_lock = threading.RLock()
_ast_cache_lock = threading.Lock()
_ast_info_cache: dict[str, tuple[int, dict[str, dict[str, Any]]]] = {}
_run_lock = threading.Lock()
_collection: dict[str, Any] = {
    "status": "empty", "files": [], "info": {}, "updated_at": None, "output": [],
}
_run: dict[str, Any] | None = None
_run_process: asyncio.subprocess.Process | None = None


class StartRequest(BaseModel):
    mode: str
    targets: list[str] = Field(default_factory=list)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def topic_for_filename(file_path: str) -> str:
    filename = Path(file_path).name.casefold()
    for topic, tokens in TOPIC_FILENAME_MAP.items():
        if any(token in filename for token in tokens):
            return topic
    return "other"


def _load_test_descriptions(project_root: Path | None = None) -> dict[str, dict[str, str]]:
    """Read optional plain-language test notes; missing or invalid files are ignored."""
    description_path = (project_root or PROJECT_ROOT) / "data" / "test_descriptions.json"
    try:
        import json
        raw = json.loads(description_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    if isinstance(raw.get("tests"), dict):
        raw = raw["tests"]
    fields = ("setup", "action", "expected")
    return {
        nodeid: {field: value[field] for field in fields if isinstance(value.get(field), str)}
        for nodeid, value in raw.items()
        if isinstance(nodeid, str) and isinstance(value, dict)
    }


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _humanized_test_name(name: str) -> str:
    humanized = name.removeprefix("test_").replace("_", " ").strip()
    return humanized or name


def _short_source_line(source: str) -> str:
    line = " ".join(source.split())
    return line if len(line) <= 120 else line[:117].rstrip() + "..."


def _parametrize_count(function: ast.FunctionDef | ast.AsyncFunctionDef) -> int | None:
    count = 1
    found = False
    for decorator in function.decorator_list:
        if _decorator_name(decorator) != "parametrize" or not isinstance(decorator, ast.Call):
            continue
        found = True
        values = decorator.args[1] if len(decorator.args) > 1 else next(
            (keyword.value for keyword in decorator.keywords if keyword.arg == "argvalues"), None
        )
        try:
            literal_values = ast.literal_eval(values) if values is not None else None
            value_count = len(literal_values) if isinstance(literal_values, (list, tuple, set, dict)) else 1
        except (ValueError, TypeError, SyntaxError):
            return None
        count *= value_count
    return count if found else 0


def _parametrize_arguments(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for decorator in function.decorator_list:
        if _decorator_name(decorator) != "parametrize" or not isinstance(decorator, ast.Call):
            continue
        argnames = decorator.args[0] if decorator.args else next(
            (keyword.value for keyword in decorator.keywords if keyword.arg == "argnames"), None
        )
        try:
            values = ast.literal_eval(argnames) if argnames is not None else None
        except (ValueError, TypeError, SyntaxError):
            continue
        if isinstance(values, str):
            names.update(name.strip() for name in values.split(",") if name.strip())
        elif isinstance(values, (list, tuple)):
            names.update(name for name in values if isinstance(name, str))
    return names


def extract_test_info_from_source(source: str, file_path: str) -> dict[str, dict[str, Any]]:
    """Extract test descriptions without importing or executing the source file."""
    try:
        module = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError, TypeError):
        return {}

    module_path = Path(file_path).as_posix()
    functions: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for item in module.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(("", item))
        elif isinstance(item, ast.ClassDef):
            functions.extend(
                (item.name, child)
                for child in item.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            )

    extracted: dict[str, dict[str, Any]] = {}
    for group, function in functions:
        nodeid = f"{module_path}::{group}::{function.name}" if group else f"{module_path}::{function.name}"
        parameter_names = _parametrize_arguments(function)
        signature_names = [
            arg.arg for arg in (
                list(function.args.posonlyargs) + list(function.args.args) + list(function.args.kwonlyargs)
            ) if arg.arg not in {"self", "cls"} and arg.arg not in parameter_names
        ]
        if function.args.vararg and function.args.vararg.arg not in {"self", "cls"} | parameter_names:
            signature_names.append(function.args.vararg.arg)
        if function.args.kwarg and function.args.kwarg.arg not in {"self", "cls"} | parameter_names:
            signature_names.append(function.args.kwarg.arg)
        uses = set(signature_names)
        for decorator in function.decorator_list:
            decorator_name = _decorator_name(decorator)
            if decorator_name and decorator_name not in {"pytest", "mark"}:
                uses.add(decorator_name)
            if decorator_name == "usefixtures" and isinstance(decorator, ast.Call):
                uses.update(
                    value.value for value in decorator.args
                    if isinstance(value, ast.Constant) and isinstance(value.value, str)
                )

        docstring = ast.get_docstring(function)
        first_doc_line = next((line.strip() for line in (docstring or "").splitlines() if line.strip()), "")
        assertions = sorted(
            (node for node in ast.walk(function) if isinstance(node, ast.Assert)),
            key=lambda node: node.lineno,
        )
        extracted[nodeid] = {
            "title": _humanized_test_name(function.name),
            "group": group,
            "doc": first_doc_line,
            "checks": [_short_source_line(ast.unparse(assertion)) for assertion in assertions[:6]],
            "uses": sorted(uses),
            "param_count": _parametrize_count(function),
        }
    return extracted


def _cached_file_test_info(file_path: str) -> dict[str, dict[str, Any]]:
    try:
        project_root = PROJECT_ROOT.resolve()
        source_path = (project_root / file_path).resolve()
        if not source_path.is_relative_to(project_root):
            return {}
        mtime = source_path.stat().st_mtime_ns
    except (OSError, ValueError):
        return {}

    with _ast_cache_lock:
        cached = _ast_info_cache.get(file_path)
        if cached and cached[0] == mtime:
            return cached[1]
    try:
        with tokenize.open(source_path) as handle:
            source = handle.read()
        info = extract_test_info_from_source(source, file_path)
    except Exception:
        return {}
    with _ast_cache_lock:
        _ast_info_cache[file_path] = (mtime, info)
    return info


def enrich_collection(files: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    info: dict[str, dict[str, Any]] = {}
    descriptions = _load_test_descriptions()
    for file in files:
        file["topic"] = topic_for_filename(file["path"])
        metadata = TOPIC_METADATA[file["topic"]]
        file["topic_name"] = metadata["name"]
        file["topic_description"] = metadata["description"]
        if file.get("error"):
            continue
        parsed = _cached_file_test_info(file["path"])
        for nodeid in file["nodeids"]:
            base_nodeid = nodeid.split("[", 1)[0]
            if base_nodeid in parsed:
                info[nodeid] = {**parsed[base_nodeid], **descriptions.get(base_nodeid, {}), **descriptions.get(nodeid, {})}
    return info


def parse_collection_output(output: str) -> list[dict[str, Any]]:
    """Turn pytest's quiet collection output into selectable file entries."""
    files: dict[str, dict[str, Any]] = {}
    current_error: str | None = None
    current_file: str | None = None
    error_lines: list[str] = []

    def finish_error() -> None:
        if current_file is not None:
            entry = files.setdefault(current_file, {"path": current_file, "nodeids": []})
            entry["error"] = "\n".join(error_lines).strip() or "Collection failed"

    for line in output.splitlines():
        heading = re.match(r"^ERROR collecting (.+\.py)\s*$", line.strip())
        if heading:
            finish_error()
            current_file = heading.group(1).replace("\\", "/")
            error_lines = []
            current_error = current_file
            files.setdefault(current_file, {"path": current_file, "nodeids": []})
            continue
        if current_error:
            if line.startswith("=====") or line.startswith("collected "):
                finish_error()
                current_file = None
                current_error = None
            else:
                error_lines.append(line)
                continue
        node = re.match(r"^(tests[/\\].+?\.py)::", line.strip())
        if node:
            path = node.group(1).replace("\\", "/")
            files.setdefault(path, {"path": path, "nodeids": []})["nodeids"].append(line.strip())

    finish_error()
    return [
        {**entry, "count": len(entry["nodeids"]), "selectable": not bool(entry.get("error"))}
        for entry in sorted(files.values(), key=lambda item: item["path"].casefold())
    ]


def validate_targets(mode: str, targets: list[str], files: list[dict[str, Any]],
                     previous_run: dict[str, Any] | None) -> list[str]:
    if any(not isinstance(target, str) or target.startswith("-") for target in targets):
        raise HTTPException(422, "Targets must be collected test IDs or file paths")
    if mode == "all":
        if targets:
            raise HTTPException(422, "all mode does not accept targets")
        valid = [item["path"] for item in files if not item.get("error")]
        if not valid:
            raise HTTPException(422, "No successfully collected test files are available")
        return valid
    if mode == "failed":
        if targets:
            raise HTTPException(422, "failed mode does not accept targets")
        failed = [
            item["nodeid"] for item in (previous_run or {}).get("results", [])
            if item.get("outcome") == "failed"
        ]
        if not failed:
            raise HTTPException(422, "There are no failed tests from the last run")
        return failed
    if mode != "selected":
        raise HTTPException(422, "mode must be all, selected, or failed")
    if not targets:
        raise HTTPException(422, "Select at least one test file or test")

    selectable = {item["path"] for item in files if not item.get("error")}
    selectable.update(node for item in files if not item.get("error") for node in item["nodeids"])
    checked: list[str] = []
    for target in targets:
        if not isinstance(target, str) or target.startswith("-") or target not in selectable:
            raise HTTPException(422, f"Invalid test target: {target!r}")
        if target not in checked:
            checked.append(target)
    return checked


def build_argv(targets: list[str], junit_path: str, ignored_files: list[str] = ()) -> list[str]:
    argv = [sys.executable, "-m", "pytest", "-v", f"--junitxml={junit_path}"]
    argv.extend(targets)
    argv.extend(f"--ignore={path}" for path in ignored_files)
    return argv


def parse_junit(path: str | Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []
    results = []
    for case in root.iter("testcase"):
        classname = case.attrib.get("classname", "")
        parts = classname.split(".") if classname else []
        module_parts: list[str] = []
        class_parts: list[str] = []
        for part in parts:
            if part.startswith("Test"):
                class_parts.append(part)
            else:
                module_parts.append(part)
        if module_parts and module_parts[0] == "tests":
            module_path = "/".join(module_parts) + ".py"
        else:
            module_path = "/".join(module_parts)
        nodeid = module_path
        if nodeid and case.attrib.get("name"):
            nodeid += "::" + "::".join(class_parts + [case.attrib["name"]])

        failure = case.find("failure")
        if failure is None:
            failure = case.find("error")
        skipped = case.find("skipped")
        outcome = "failed" if failure is not None else "skipped" if skipped is not None else "passed"
        detail_element = failure if failure is not None else skipped
        message = ""
        if detail_element is not None:
            candidates = (detail_element.attrib.get("message", ""), detail_element.text or "")
            for candidate in candidates:
                message = next((line.strip() for line in candidate.splitlines() if line.strip()), "")
                if message:
                    break
        message = message[:200]
        results.append({
            "nodeid": nodeid,
            "outcome": outcome,
            "duration": float(case.attrib.get("time", 0) or 0),
            "message": message,
        })
    return results


def _snapshot_collection() -> dict[str, Any]:
    with _state_lock:
        snapshot = {key: value for key, value in _collection.items() if key != "process"}
        snapshot["files"] = [dict(item) for item in _collection["files"]]
        snapshot["info"] = {nodeid: dict(item) for nodeid, item in _collection.get("info", {}).items()}
        snapshot["output"] = list(_collection["output"])
        snapshot["topics"] = {key: dict(value) for key, value in TOPIC_METADATA.items()}
        return snapshot


def _snapshot_run(offset: int = 0) -> dict[str, Any] | None:
    with _state_lock:
        if _run is None:
            return None
        result = dict(_run)
        lines = list(result.pop("output", []))
        result["output"] = lines[max(0, offset):]
        result["next_offset"] = len(lines)
        targets = result.get("targets", [])
        result["info"] = {
            nodeid: dict(details)
            for nodeid, details in _collection.get("info", {}).items()
            if nodeid in targets or any(
                target.endswith(".py") and nodeid.startswith(target + "::") for target in targets
            )
        }
        result["topics"] = {key: dict(value) for key, value in TOPIC_METADATA.items()}
        return result


async def _spawn(argv: list[str]) -> asyncio.subprocess.Process:
    options: dict[str, Any] = {
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.STDOUT,
        "cwd": str(PROJECT_ROOT),
    }
    if os.name == "nt":
        options["creationflags"] = getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        options["start_new_session"] = True
    return await asyncio.create_subprocess_exec(*argv, **options)


async def terminate_process_tree(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    if os.name == "nt":
        killer = await asyncio.create_subprocess_exec(
            "taskkill", "/PID", str(process.pid), "/T", "/F",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await killer.wait()
        if process.returncode is None:
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    if process.returncode is None:
        await process.wait()


async def _capture(process: asyncio.subprocess.Process, sink: list[str]) -> int:
    assert process.stdout is not None
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        sink.append(text)
        if _run is not None and sink is _run["output"]:
            percent = re.search(r"\[\s*(\d+)%\]", text)
            if percent:
                _run["progress"] = max(_run.get("progress", 0), int(percent.group(1)))
            elif re.search(r"\b(PASSED|FAILED|SKIPPED|ERROR)\b", text):
                _run["progress"] = min(
                    99, _run.get("progress", 0) + 1 / max(_run.get("expected_count", 1), 1) * 100
                )
    return await process.wait()


async def _collect_worker() -> None:
    argv = [
        sys.executable, "-m", "pytest", "--collect-only", "-q",
        "-o", "addopts=", "-p", "no:cacheprovider",
    ]
    output: list[str] = []
    process = None
    try:
        process = await _spawn(argv)
        with _state_lock:
            _collection["process"] = process
        returncode = await asyncio.wait_for(_capture(process, output), TEST_TIMEOUT_SECONDS)
        files = parse_collection_output("\n".join(output))
        info = enrich_collection(files)
        with _state_lock:
            _collection.update(status="ready", files=files, info=info, updated_at=_timestamp(),
                               output=output, exit_code=returncode, error=None)
    except asyncio.TimeoutError:
        if process is not None:
            await terminate_process_tree(process)
        with _state_lock:
            _collection.update(status="error", info={}, output=output, error="Collection timed out",
                               updated_at=_timestamp())
    except Exception as exc:
        with _state_lock:
            _collection.update(status="error", info={}, output=output, error=str(exc),
                               updated_at=_timestamp())
    finally:
        with _state_lock:
            _collection.pop("process", None)


async def _run_worker(argv: list[str], junit_path: str) -> None:
    global _run_process
    process = None
    try:
        process = await _spawn(argv)
        with _state_lock:
            _run_process = process
            cancelled = bool(_run and _run.get("cancel_requested"))
        if cancelled:
            await terminate_process_tree(process)
        output: list[str]
        with _state_lock:
            output = _run["output"] if _run else []
        try:
            returncode = await asyncio.wait_for(_capture(process, output), TEST_TIMEOUT_SECONDS)
            status = "completed" if returncode == 0 else "failed"
        except asyncio.TimeoutError:
            await terminate_process_tree(process)
            status, returncode = "timed_out", None
        results = parse_junit(junit_path)
        with _state_lock:
            if _run and _run.get("cancel_requested"):
                status = "cancelled"
            _run.update(status=status, return_code=returncode, results=results,
                        finished_at=_timestamp(), cancel_requested=False)
    except Exception as exc:
        with _state_lock:
            if _run:
                _run.update(status="failed", error=str(exc), finished_at=_timestamp())
    finally:
        with _state_lock:
            _run_process = None
            _run_lock.release()
        try:
            Path(junit_path).unlink(missing_ok=True)
        except OSError:
            pass


@router.get("/collect")
async def collect_tests(
    refresh: bool = Query(False),
    _admin: dict = Depends(require_role("admin")),
):
    with _state_lock:
        if _collection["status"] == "collecting":
            return _snapshot_collection()
        if _run and _run["status"] in {"running", "starting"}:
            raise HTTPException(409, "A test run is in progress")
        if _collection["status"] == "ready" and not refresh:
            return _snapshot_collection()
        if _collection["status"] == "error" and not refresh:
            return _snapshot_collection()
        _collection.update(status="collecting", error=None, info={}, output=[])
    asyncio.create_task(_collect_worker())
    return _snapshot_collection()


@router.post("/start")
async def start_tests(
    payload: StartRequest,
    _admin: dict = Depends(require_role("admin")),
):
    global _run
    with _state_lock:
        if _collection["status"] == "collecting":
            raise HTTPException(409, "Test collection is in progress")
        if _collection["status"] != "ready":
            raise HTTPException(409, "Collect tests before starting a run")
        if _run_lock.locked():
            raise HTTPException(409, "A test run is already in progress")
        targets = validate_targets(payload.mode, payload.targets, _collection["files"], _run)
        ignored = [item["path"] for item in _collection["files"] if item.get("error")]
        if not _run_lock.acquire(blocking=False):
            raise HTTPException(409, "A test run is already in progress")
        try:
            temp = tempfile.NamedTemporaryFile(prefix="socpow-tests-", suffix=".xml", delete=False)
            junit_path = temp.name
            temp.close()
            actual_targets = targets
            if payload.mode == "all":
                actual_targets = [item["path"] for item in _collection["files"] if not item.get("error")]
            else:
                selected_files = {target for target in targets if "::" not in target}
                actual_targets = [
                    target for target in targets
                    if "::" not in target or target.split("::", 1)[0] not in selected_files
                ]
            file_counts = {item["path"]: item["count"] for item in _collection["files"]}
            expected_count = sum(
                1 if "::" in target else file_counts.get(target, 0) for target in actual_targets
            )
            argv = build_argv(actual_targets, junit_path, ignored if payload.mode == "all" else ())
            _run = {
                "status": "running", "mode": payload.mode, "targets": actual_targets,
                "started_at": _timestamp(), "finished_at": None, "output": [],
                "results": [], "return_code": None, "cancel_requested": False,
                "expected_count": expected_count, "progress": 0,
            }
        except Exception:
            _run_lock.release()
            raise
    asyncio.create_task(_run_worker(argv, junit_path))
    return _snapshot_run()


@router.get("/status")
async def test_status(
    offset: int = Query(0, ge=0),
    _admin: dict = Depends(require_role("admin")),
):
    return _snapshot_run(offset) or {"status": "empty", "output": [], "next_offset": 0,
                                     "info": {}, "topics": {key: dict(value) for key, value in TOPIC_METADATA.items()}}


@router.post("/cancel")
async def cancel_tests(_admin: dict = Depends(require_role("admin"))):
    global _run_process
    with _state_lock:
        if not _run or _run["status"] not in {"running", "starting"}:
            raise HTTPException(409, "No test run is active")
        _run["cancel_requested"] = True
        process = _run_process
    if process is not None:
        await terminate_process_tree(process)
    return _snapshot_run()
