"""Compute operational metrics from agent.db without modifying the database."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = r"C:\Users\ACER\.blue-team-assistant\cache\agent.db"
DEFAULT_OUTPUT_PATH = Path(__file__).with_name("operational_metrics_output.csv")
STEP_LIMIT_PATTERN = re.compile(
    r"exceeded maximum step count|Step limit \(",
    re.IGNORECASE,
)
TABLE_HEADER = ("group", "metric", "numerator", "denominator", "rate", "details")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH)
    parser.add_argument("--since", help="Include sessions created at or after this ISO value")
    parser.add_argument("--session-ids-file", help='JSON file shaped as {"session_ids": [...]}')
    parser.add_argument("--extra-session-id", action="append", default=[])
    parser.add_argument("--label", help="Label this explicitly selected session set")
    parser.add_argument("--output-csv", default=str(DEFAULT_OUTPUT_PATH))
    return parser.parse_args()


def open_read_only(path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)


def rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.000000"
    return f"{numerator / denominator:.6f}"


def session_rows(
    connection: sqlite3.Connection,
    since: str | None,
    session_ids: list[str] | None,
) -> list[sqlite3.Row]:
    connection.row_factory = sqlite3.Row
    if session_ids is not None:
        if not session_ids:
            return []
        placeholders = ",".join("?" for _ in session_ids)
        cursor = connection.execute(
            f"""SELECT id, playbook_id, status, summary, findings, metadata
                FROM agent_sessions WHERE id IN ({placeholders})
                ORDER BY created_at, id""",
            session_ids,
        )
        found = cursor.fetchall()
        found_ids = {row["id"] for row in found}
        missing = [session_id for session_id in session_ids if session_id not in found_ids]
        if missing:
            raise ValueError(f"Unknown session ids: {', '.join(missing)}")
        return found
    if since:
        cursor = connection.execute(
            """SELECT id, playbook_id, status, summary, findings, metadata
               FROM agent_sessions WHERE created_at >= ? ORDER BY created_at, id""",
            (since,),
        )
    else:
        cursor = connection.execute(
            """SELECT id, playbook_id, status, summary, findings, metadata
               FROM agent_sessions ORDER BY created_at, id"""
        )
    return cursor.fetchall()


def read_session_ids(path: str | None, extra_ids: list[str]) -> list[str] | None:
    if path is None and not extra_ids:
        return None
    ids: list[str] = []
    if path:
        with Path(path).open(encoding="utf-8") as source:
            payload = json.load(source)
        if not isinstance(payload, dict) or not isinstance(payload.get("session_ids"), list):
            raise ValueError('session ids file must contain {"session_ids": [...]}')
        if not all(isinstance(value, str) and value for value in payload["session_ids"]):
            raise ValueError("session_ids must contain non-empty strings")
        ids.extend(payload["session_ids"])
    ids.extend(extra_ids)
    return list(dict.fromkeys(ids))


def flow_name(playbook_id: Any) -> str:
    return "Flow C" if playbook_id is not None else "Flow B"


def session_text(session: sqlite3.Row) -> str:
    values = (session["summary"], session["findings"], session["metadata"])
    return " ".join(str(value) for value in values if value is not None)


def parse_tool_success(tool_result: Any) -> str:
    """Return success, error, or unparseable using the top-level error contract."""
    try:
        parsed = json.loads(tool_result)
    except (TypeError, json.JSONDecodeError):
        return "unparseable"
    if not isinstance(parsed, dict):
        return "unparseable"
    if parsed.get("error") is not None:
        return "error"
    if parsed.get("truncated") is True:
        return "error" if parsed.get("ended_in_error") is True else "success"
    return "success"


def metric_row(
    group: str,
    metric: str,
    numerator: int,
    denominator: int,
    details: str = "",
) -> dict[str, str | int]:
    return {
        "group": group,
        "metric": metric,
        "numerator": numerator,
        "denominator": denominator,
        "rate": rate(numerator, denominator),
        "details": details,
    }


def _mcp_nested_error(parsed: Any) -> bool:
    if not isinstance(parsed, dict):
        return False
    result = parsed.get("result")
    return isinstance(result, dict) and (
        result.get("status") == "error" or result.get("error") not in (None, "")
    )


def _investigate_auxiliary_error(parsed: Any) -> bool:
    if not isinstance(parsed, dict):
        return False
    analysis = parsed.get("llm_analysis")
    if isinstance(analysis, dict) and analysis.get("error") not in (None, ""):
        return True
    sources = parsed.get("sources")
    return isinstance(sources, dict) and any(
        isinstance(source, dict) and source.get("error") not in (None, "")
        for source in sources.values()
    )


def _group_label(group: str, label: str | None) -> str:
    return f"{group} [{label}]" if label and group == "Flow C" else group


def compute_metrics(
    connection: sqlite3.Connection,
    sessions: list[sqlite3.Row],
    label: str | None = None,
) -> tuple[list[dict[str, str | int]], list[tuple[str, int, str]], list[tuple[str, int, str]]]:
    by_group = {
        group: [session for session in sessions if flow_name(session["playbook_id"]) == group]
        for group in ("Flow B", "Flow C")
    }
    rows: list[dict[str, str | int]] = []
    partial_failure_rows: list[tuple[str, int, str]] = []
    investigate_aux_rows: list[tuple[str, int, str]] = []

    for group in ("Flow B", "Flow C"):
        group_sessions = by_group[group]
        ids = [session["id"] for session in group_sessions]
        output_group = _group_label(group, label)
        placeholders = ",".join("?" for _ in ids)

        if group == "Flow B":
            if ids:
                audit_rows = connection.execute(
                    f"""SELECT status FROM audit_log
                        WHERE action_type = 'tool_call' AND session_id IN ({placeholders})""",
                    ids,
                ).fetchall()
            else:
                audit_rows = []
            successes = sum(row[0] == "success" for row in audit_rows)
            rows.append(metric_row(group, "step_success_rate", successes, len(audit_rows)))
        else:
            if ids:
                step_rows = connection.execute(
                    f"""SELECT session_id, step_number, tool_name, tool_result
                        FROM agent_steps
                        WHERE step_type = 'tool_call' AND session_id IN ({placeholders})
                        ORDER BY session_id, step_number""",
                    ids,
                ).fetchall()
            else:
                step_rows = []

            counts = {"success": 0, "error": 0, "unparseable": 0}
            for step in step_rows:
                status = parse_tool_success(step["tool_result"])
                counts[status] += 1
                try:
                    parsed = json.loads(step["tool_result"])
                except (TypeError, json.JSONDecodeError):
                    parsed = None
                item = (step["session_id"], step["step_number"], step["tool_name"] or "")
                if status == "success" and _mcp_nested_error(parsed):
                    partial_failure_rows.append(item)
                if (
                    step["tool_name"] == "investigate_ioc"
                    and _investigate_auxiliary_error(parsed)
                ):
                    investigate_aux_rows.append(item)

            classified_total = counts["success"] + counts["error"]
            rows.extend([
                metric_row(
                    output_group,
                    "step_success_rate",
                    counts["success"],
                    classified_total,
                ),
                metric_row(output_group, "error_count", counts["error"], len(step_rows)),
                metric_row(
                    output_group,
                    "unparseable_count",
                    counts["unparseable"],
                    len(step_rows),
                ),
                metric_row(output_group, "step_total", len(step_rows), len(step_rows)),
                metric_row(
                    output_group,
                    "partial_failure_count",
                    len(partial_failure_rows),
                    counts["success"],
                    ";".join(
                        f"{sid}:{step}:{tool}"
                        for sid, step, tool in partial_failure_rows
                    ),
                ),
                metric_row(
                    output_group,
                    "investigate_ioc_auxiliary_error_count",
                    len(investigate_aux_rows),
                    len(step_rows),
                    ";".join(
                        f"{sid}:{step}:{tool}"
                        for sid, step, tool in investigate_aux_rows
                    ),
                ),
            ])

        completed = sum(session["status"] == "completed" for session in group_sessions)
        non_completed = [
            session for session in group_sessions if session["status"] != "completed"
        ]
        step_limit_abort = sum(
            bool(STEP_LIMIT_PATTERN.search(session_text(session)))
            for session in non_completed
        )
        other_non_completed = len(non_completed) - step_limit_abort
        rows.extend([
            metric_row(group, "completion_rate", completed, len(group_sessions)),
            metric_row(
                group,
                "completion_rate_step_limit_abort_breakdown",
                step_limit_abort,
                len(non_completed),
            ),
            metric_row(
                group,
                "completion_rate_other_non_completed_breakdown",
                other_non_completed,
                len(non_completed),
            ),
        ])

        if ids:
            approval_rows = connection.execute(
                f"""SELECT action_type, status FROM audit_log
                    WHERE requires_approval = 1 AND session_id IN ({placeholders})
                      AND action_type IN ('approval_granted', 'approval_rejected')
                      AND status <> 'pending'""",
                ids,
            ).fetchall()
        else:
            approval_rows = []
        rejected = sum(
            row["status"] == "rejected" or row["action_type"] == "approval_rejected"
            for row in approval_rows
        )
        rows.append(metric_row(group, "human_override_rate", rejected, len(approval_rows)))

    return rows, partial_failure_rows, investigate_aux_rows


def write_csv(path: str, rows: list[dict[str, str | int]]) -> None:
    with Path(path).open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=TABLE_HEADER)
        writer.writeheader()
        writer.writerows(rows)


def print_table(
    rows: list[dict[str, str | int]],
    partial_rows: list[tuple[str, int, str]],
    investigate_rows: list[tuple[str, int, str]],
) -> None:
    print(" | ".join(TABLE_HEADER))
    for row in rows:
        print(" | ".join(str(row[column]) for column in TABLE_HEADER))
    for session_id, step_number, tool_name in partial_rows:
        print(f"partial_failure_tool | {session_id} | {step_number} | {tool_name}")
    for session_id, step_number, tool_name in investigate_rows:
        print(f"investigate_ioc_auxiliary_error | {session_id} | {step_number} | {tool_name}")


def main() -> None:
    args = parse_args()
    selected_ids = read_session_ids(args.session_ids_file, args.extra_session_id)
    connection = open_read_only(args.db_path)
    try:
        sessions = session_rows(connection, args.since, selected_ids)
        rows, partial_rows, investigate_rows = compute_metrics(
            connection, sessions, args.label,
        )
    finally:
        connection.close()

    print_table(rows, partial_rows, investigate_rows)
    write_csv(args.output_csv, rows)
    print(f"csv_path={args.output_csv}")


if __name__ == "__main__":
    main()
