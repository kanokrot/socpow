"""Read-only reconstruction of five formerly truncated playbook tool results."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from compute_operational_metrics import parse_tool_success


DEFAULT_DB_PATH = r"C:\Users\ACER\.blue-team-assistant\cache\agent.db"
SESSION_IDS = (
    "2320b6ac573d",
    "ab2cb362c774",
    "41fa383a6d03",
    "b0c0c527cdbb",
)
EXPECTED_FULL_RESULTS = {
    ("2320b6ac573d", 17): ("ioc_investigation_result", None),
    ("ab2cb362c774", 17): ("ioc_investigation_result", None),
    ("41fa383a6d03", 17): ("ioc_investigation_result", None),
    ("b0c0c527cdbb", 2): ("context", "collect_running_processes"),
    ("b0c0c527cdbb", 4): ("context", "collect_event_logs"),
}
EXPECTED_TOTALS = (15, 20)


def open_read_only(path: str) -> sqlite3.Connection:
    uri = Path(path).as_posix()
    return sqlite3.connect(f"file:{uri}?mode=ro", uri=True)


def load_full_result(metadata: dict, session_id: str, step_number: int):
    root, context_key = EXPECTED_FULL_RESULTS[(session_id, step_number)]
    if root == "context":
        context = metadata.get("context")
        if not isinstance(context, dict) or context_key not in context:
            raise ValueError(f"full result missing: {session_id}:{context_key}")
        return context[context_key]
    if root not in metadata:
        raise ValueError(f"full result missing: {session_id}:{root}")
    return metadata[root]


def legacy_success(tool_result: str) -> bool:
    try:
        parsed = json.loads(tool_result)
    except (TypeError, json.JSONDecodeError):
        return False
    return isinstance(parsed, dict) and "error" not in parsed


def main() -> int:
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH)
    args = parser.parse_args()

    connection = open_read_only(args.db_path)
    connection.row_factory = sqlite3.Row
    try:
        placeholders = ",".join("?" for _ in SESSION_IDS)
        session_rows = connection.execute(
            f"SELECT id, metadata FROM agent_sessions WHERE id IN ({placeholders})",
            SESSION_IDS,
        ).fetchall()
        metadata_by_id = {
            row["id"]: json.loads(row["metadata"] or "{}") for row in session_rows
        }
        if set(metadata_by_id) != set(SESSION_IDS):
            raise ValueError("one or more requested sessions were not found")
        steps = connection.execute(
            f"""SELECT session_id, step_number, tool_name, tool_result
                FROM agent_steps
                WHERE step_type='tool_call' AND session_id IN ({placeholders})
                ORDER BY session_id, step_number""",
            SESSION_IDS,
        ).fetchall()

        old_count = 0
        new_count = 0
        print("session_id,step_number,tool_name,old_success,new_success,full_len,serialized_prefix_matches_truncated")
        for step in steps:
            sid = step["session_id"]
            number = step["step_number"]
            stored = step["tool_result"] or ""
            old = legacy_success(stored)
            if (sid, number) in EXPECTED_FULL_RESULTS:
                full_result = load_full_result(metadata_by_id[sid], sid, number)
                serialized = json.dumps(full_result, default=str)
                full_len = len(serialized)
                prefix_matches = stored == serialized[:10_000]
                new_status = parse_tool_success(serialized)
                new = new_status == "success"
                print(
                    f"{sid},{number},{step['tool_name']},{int(old)},{int(new)},"
                    f"{full_len},{str(prefix_matches).lower()}"
                )
            else:
                new = parse_tool_success(stored) == "success"
                print(
                    f"{sid},{number},{step['tool_name']},{int(old)},{int(new)},,n/a"
                )
            old_count += int(old)
            new_count += int(new)

        print(f"SUMMARY old_success={old_count}/{len(steps)} new_success={new_count}/{len(steps)}")
        if (old_count, new_count) != EXPECTED_TOTALS:
            print(
                "EXPECTED_COUNTS_MISMATCH "
                f"expected={EXPECTED_TOTALS[0]}/{len(steps)}->{EXPECTED_TOTALS[1]}/{len(steps)}"
            )
            return 1
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
