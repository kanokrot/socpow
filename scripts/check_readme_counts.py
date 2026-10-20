#!/usr/bin/env python3
"""Count MCP and playbook entries and check the matching README tables."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a YAML mapping in {path.relative_to(ROOT)}")
    return value


def count_playbooks() -> list[dict[str, Any]]:
    rows = []
    for path in sorted((ROOT / "data" / "playbooks").glob("*.yaml")):
        data = _load_yaml(path)
        steps = data.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError(f"Expected a steps list in {path.relative_to(ROOT)}")
        rows.append(
            {
                "name": str(data.get("name", path.stem)),
                "steps": len(steps),
                "mcp": sum(
                    isinstance(step, dict)
                    and isinstance(step.get("tool"), str)
                    and step["tool"].startswith("mcp:")
                    for step in steps
                ),
                "approvals": sum(
                    isinstance(step, dict)
                    and step.get("requires_approval") is True
                    for step in steps
                ),
            }
        )
    return rows


def _is_mcp_tool_decorator(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "tool"
    )


def count_mcp_tools() -> list[dict[str, Any]]:
    rows = []
    server_dir = ROOT / "src" / "mcp_servers"
    for path in sorted(server_dir.glob("*.py")):
        # Underscore files are shared helpers, not FastMCP server modules.
        if path.name == "__init__.py" or path.name.startswith("_"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        count = sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(_is_mcp_tool_decorator(item) for item in node.decorator_list)
            for node in ast.walk(tree)
        )
        rows.append({"module": path.stem, "tools": count})
    return rows


def configured_servers(
    modules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    config = _load_yaml(ROOT / "config.yaml.example")
    counts = {row["module"]: row["tools"] for row in modules}
    rows = []
    for server in config.get("mcp_servers", []):
        if not isinstance(server, dict):
            continue
        args = server.get("args", [])
        module_ref = next(
            (
                arg
                for arg in args
                if isinstance(arg, str) and arg.startswith("src.mcp_servers.")
            ),
            "",
        )
        module = module_ref.removeprefix("src.mcp_servers.")
        if module not in counts:
            raise ValueError(
                f"Configured server {server.get('name')!r} references unknown module {module_ref!r}"
            )
        auto_connect_explicit = server.get("auto_connect")
        rows.append(
            {
                "server": str(server.get("name", "")),
                "module": module,
                "module_path": module_ref,
                "transport": str(server.get("transport", "stdio")),
                "tools": counts[module],
                "enabled": server.get("enabled"),
                "auto_connect": (
                    "true" if auto_connect_explicit is None else str(bool(auto_connect_explicit)).lower()
                ),
                "auto_connect_default": auto_connect_explicit is None,
            }
        )
    return rows


def _markdown_table(text: str, header: str) -> list[list[str]]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != header:
            continue
        rows = []
        for candidate in lines[index + 2 :]:
            candidate = candidate.strip()
            if not candidate.startswith("|"):
                break
            rows.append([cell.strip().strip("`") for cell in candidate.strip("|").split("|")])
        return rows
    raise ValueError(f"README table header not found: {header}")


def check_readme(
    readme: str,
    playbooks: list[dict[str, Any]],
    modules: list[dict[str, Any]],
    servers: list[dict[str, Any]],
) -> list[str]:
    errors = []
    tool_total = sum(row["tools"] for row in modules)
    summary = re.search(
        r"The repository contains (\d+) FastMCP (?:server )?modules with (\d+) decorated tools\.",
        readme,
    )
    if not summary:
        errors.append("README MCP summary count is missing or has changed format")
    elif tuple(map(int, summary.groups())) != (len(modules), tool_total):
        errors.append(
            f"README MCP summary says {summary.group(1)} modules/{summary.group(2)} tools; "
            f"code has {len(modules)}/{tool_total}"
        )

    module_rows = _markdown_table(
        readme, "| Module | Tools | Configured auto-connect |"
    )
    module_actual = {row[0]: row for row in module_rows}
    configured_modules = {
        row["module"] for row in servers if row["auto_connect"] == "true"
    }
    expected_modules = {
        row["module"]: [
            str(row["tools"]),
            "Yes" if row["module"] in configured_modules else "No",
        ]
        for row in modules
    }
    if set(module_actual) != set(expected_modules):
        errors.append("README MCP module inventory names do not match source modules")
    for name, expected in expected_modules.items():
        actual = module_actual.get(name)
        if actual is None or actual[1:] != expected:
            errors.append(
                f"README MCP module row for {name} should have tools/auto-connect {expected}"
            )

    server_rows = _markdown_table(
        readme,
        "| Server | Module | Transport | Tools | enabled field | auto_connect |",
    )
    server_actual = {row[0]: row for row in server_rows}
    expected_server_names = {row["server"] for row in servers}
    if set(server_actual) != expected_server_names:
        errors.append("README configured MCP server names do not match config.yaml.example")
    for server in servers:
        actual = server_actual.get(server["server"])
        enabled = "not set" if server["enabled"] is None else str(server["enabled"]).lower()
        auto_connect = server["auto_connect"]
        if server["auto_connect_default"]:
            auto_connect += " (default)"
        expected = [
            server["module_path"], server["transport"], str(server["tools"]), enabled, auto_connect
        ]
        if actual is None or actual[1:] != expected:
            errors.append(
                f"README configured server row for {server['server']} should have {expected}"
            )

    playbook_rows = _markdown_table(
        readme, "| Playbook | Steps | MCP steps | Approval steps |"
    )
    playbook_actual = {row[0]: row for row in playbook_rows}
    expected_playbooks = {
        re.sub(r"\s*\([^)]*\)$", "", row["name"]): [
            str(row["steps"]), str(row["mcp"]), str(row["approvals"])
        ]
        for row in playbooks
    }
    if set(playbook_actual) != set(expected_playbooks):
        errors.append("README playbook names do not match data/playbooks/*.yaml")
    for name, expected in expected_playbooks.items():
        actual = playbook_actual.get(name)
        if actual is None or actual[1:] != expected:
            errors.append(f"README playbook row for {name} should have counts {expected}")
    return errors


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        print("| " + " | ".join(row) + " |")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="exit nonzero if README counts differ"
    )
    args = parser.parse_args()

    playbooks = count_playbooks()
    modules = count_mcp_tools()
    servers = configured_servers(modules)
    total_tools = sum(row["tools"] for row in modules)

    print(f"MCP modules: {len(modules)}; decorated tools: {total_tools}")
    print("\nMCP module inventory")
    enabled_by_config = {
        row["module"] for row in servers if row["auto_connect"] == "true"
    }
    _print_table(
        ["Module", "Tools", "Configured auto-connect"],
        [
            [row["module"], str(row["tools"]), "Yes" if row["module"] in enabled_by_config else "No"]
            for row in modules
        ],
    )
    print("\nMCP servers in config.yaml.example")
    _print_table(
        ["Server", "Module", "Transport", "Tools", "enabled field", "auto_connect"],
        [
            [
                row["server"], row["module_path"], row["transport"], str(row["tools"]),
                "not set" if row["enabled"] is None else str(row["enabled"]).lower(),
                row["auto_connect"] + (" (default)" if row["auto_connect_default"] else ""),
            ]
            for row in servers
        ],
    )
    print("\nPlaybooks")
    _print_table(
        ["Playbook", "Steps", "MCP steps", "Approval steps"],
        [
            [row["name"], str(row["steps"]), str(row["mcp"]), str(row["approvals"])]
            for row in playbooks
        ],
    )

    if args.check:
        errors = check_readme(README.read_text(encoding="utf-8"), playbooks, modules, servers)
        if errors:
            print("\nREADME count check failed:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        print("\nREADME count check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
