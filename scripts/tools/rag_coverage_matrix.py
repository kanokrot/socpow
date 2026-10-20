"""Report RAG seed coverage against SOCPOW's production vocabulary.

This tool intentionally parses the seed YAML directly. It does not import
``RAGKnowledgeBase`` or initialize ChromaDB.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import sys
from pathlib import Path
from typing import Iterable

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RAG_DIR = PROJECT_ROOT / "data" / "rag_knowledge"
DEFAULT_BASELINE_PATH = Path(__file__).with_name("rag_coverage_baseline.json")

# Union from src/utils/helpers.py:73, src/scoring/tool_based_scoring.py:87,
# src/tools/email_analyzer.py:249-255, and src/agent/playbook_engine.py:357.
VERDICT_VOCABULARY = (
    "MALICIOUS",
    "SUSPICIOUS",
    "CLEAN",
    "UNKNOWN",
    "PHISHING",
    "SPAM",
)

# From src/utils/ioc_extractor.py:446 and categorize_ioc() return values.
IOC_TYPE_VOCABULARY = (
    "ipv4",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
    "email",
    "unknown",
)

SEMANTIC_ONLY_NOTE = (
    "No verdict or ioc_type metadata; discovery requires an unfiltered or "
    "category-compatible semantic query rather than the IOC metadata filter. "
    "email_analyzer.py uses category_filter='playbook'."
)


def _load_entries(rag_dir: Path) -> list[dict]:
    entries: list[dict] = []
    for yaml_path in sorted(rag_dir.glob("*.yaml")):
        with yaml_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if not data:
            continue
        if not isinstance(data, list):
            raise ValueError(f"Expected a list in {yaml_path}")
        for entry in data:
            if not isinstance(entry, dict):
                raise ValueError(f"Expected an object entry in {yaml_path}")
            missing = {"id", "text", "metadata"} - entry.keys()
            if missing:
                fields = ", ".join(sorted(missing))
                raise ValueError(f"Missing {fields} in {yaml_path}")
            entries.append(entry)
    return entries


def _rag_query_category_filters(src_dir: Path) -> list[str]:
    categories: set[str] = set()
    for source_path in sorted(src_dir.rglob("*.py")):
        try:
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if not isinstance(function, ast.Attribute) or function.attr != "query":
                continue
            owner = function.value
            if not isinstance(owner, ast.Attribute) or owner.attr != "rag_kb":
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "category_filter"
                    and isinstance(keyword.value, ast.Constant)
                    and isinstance(keyword.value.value, str)
                ):
                    categories.add(keyword.value.value)
    return sorted(categories)


def _coverage_record(exact: Iterable[str], wildcard: Iterable[str] = ()) -> dict:
    exact_ids = sorted(set(exact))
    wildcard_ids = sorted(set(wildcard) - set(exact_ids))
    entry_ids = sorted(set(exact_ids) | set(wildcard_ids))
    return {
        "count": len(entry_ids),
        "entry_ids": entry_ids,
        "matches": {
            "exact": exact_ids,
            "via-any-wildcard": wildcard_ids,
        },
    }


def build_coverage_matrix(rag_dir: Path = None) -> dict:
    """Build current RAG coverage for production verdict and IOC vocabularies."""
    resolved_rag_dir = Path(rag_dir) if rag_dir is not None else DEFAULT_RAG_DIR
    entries = _load_entries(resolved_rag_dir)

    verdict_coverage = {}
    for verdict in VERDICT_VOCABULARY:
        exact = [
            entry["id"]
            for entry in entries
            if entry["metadata"].get("verdict") == verdict
        ]
        verdict_coverage[verdict] = _coverage_record(exact)

    ioc_type_coverage = {}
    wildcard_ids = [
        entry["id"]
        for entry in entries
        if entry["metadata"].get("ioc_type") == "any"
    ]
    for ioc_type in IOC_TYPE_VOCABULARY:
        exact = [
            entry["id"]
            for entry in entries
            if entry["metadata"].get("ioc_type") == ioc_type
        ]
        ioc_type_coverage[ioc_type] = _coverage_record(exact, wildcard_ids)

    unfiltered_entries = []
    for entry in entries:
        metadata = entry["metadata"]
        if "verdict" not in metadata and "ioc_type" not in metadata:
            unfiltered_entries.append(
                {
                    "entry_id": entry["id"],
                    "category": metadata.get("category", "uncategorized"),
                    "note": SEMANTIC_ONLY_NOTE,
                }
            )

    yaml_categories = sorted(
        {
            entry["metadata"].get("category", "uncategorized")
            for entry in entries
        }
    )
    queried_categories = _rag_query_category_filters(PROJECT_ROOT / "src")
    category_details = {
        category: {
            "status": (
                "reachable"
                if category in queried_categories
                else "unreachable_category"
            ),
            "entry_ids": sorted(
                entry["id"]
                for entry in entries
                if entry["metadata"].get("category", "uncategorized")
                == category
            ),
        }
        for category in yaml_categories
    }

    return {
        "entry_count": len(entries),
        "verdict_vocabulary": list(VERDICT_VOCABULARY),
        "ioc_type_vocabulary": list(IOC_TYPE_VOCABULARY),
        "verdict_coverage": verdict_coverage,
        "ioc_type_coverage": ioc_type_coverage,
        "unfiltered_entries": sorted(
            unfiltered_entries, key=lambda item: item["entry_id"]
        ),
        "category_query_reachability": {
            "yaml_categories": yaml_categories,
            "queried_categories": queried_categories,
            "categories": category_details,
            "unreachable_category": sorted(
                set(yaml_categories) - set(queried_categories)
            ),
        },
    }


def _baseline_snapshot(matrix: dict) -> dict:
    return {
        "verdict_coverage": {
            value: details["count"]
            for value, details in matrix["verdict_coverage"].items()
        },
        "ioc_type_coverage": {
            value: details["count"]
            for value, details in matrix["ioc_type_coverage"].items()
        },
        "unreachable_category": matrix["category_query_reachability"][
            "unreachable_category"
        ],
    }


def _write_baseline(matrix: dict, path: Path = DEFAULT_BASELINE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_baseline_snapshot(matrix), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _format_ids(entry_ids: list[str]) -> str:
    return ", ".join(entry_ids) if entry_ids else "-"


def _print_human(matrix: dict) -> None:
    print(f"RAG entries: {matrix['entry_count']}")
    print("\nVerdict coverage")
    print("value       count  status  exact entry_ids")
    for value, details in matrix["verdict_coverage"].items():
        status = "OK" if details["count"] else "[GAP]"
        exact = details["matches"]["exact"]
        print(f"{value:<11} {details['count']:>5}  {status:<6}  {_format_ids(exact)}")

    print("\nIOC type coverage")
    print("value    count  status  exact entry_ids | via-any-wildcard entry_ids")
    for value, details in matrix["ioc_type_coverage"].items():
        status = "OK" if details["count"] else "[GAP]"
        exact = _format_ids(details["matches"]["exact"])
        wildcard = _format_ids(details["matches"]["via-any-wildcard"])
        print(
            f"{value:<8} {details['count']:>5}  {status:<6}  "
            f"{exact} | {wildcard}"
        )

    reachability = matrix["category_query_reachability"]
    print("\nCategory query reachability")
    print(f"YAML categories: {', '.join(reachability['yaml_categories'])}")
    print(f"Queried categories: {', '.join(reachability['queried_categories']) or '-'}")
    unreachable = reachability["unreachable_category"]
    print(f"unreachable_category: {', '.join(unreachable) or '-'}")

    print("\nUnfiltered entries (semantic query only)")
    if not matrix["unfiltered_entries"]:
        print("-")
    for entry in matrix["unfiltered_entries"]:
        print(f"{entry['entry_id']} [{entry['category']}] - {entry['note']}")


def _write_csv_rows(path: Path, coverage: dict) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("value", "count", "match_type", "entry_ids"),
        )
        writer.writeheader()
        for value, details in coverage.items():
            for match_type, entry_ids in details["matches"].items():
                writer.writerow(
                    {
                        "value": value,
                        "count": len(entry_ids),
                        "match_type": match_type,
                        "entry_ids": ";".join(entry_ids),
                    }
                )


def _write_csv(matrix: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_csv_rows(
        out_dir / "verdict_coverage.csv", matrix["verdict_coverage"]
    )
    _write_csv_rows(
        out_dir / "ioc_type_coverage.csv", matrix["ioc_type_coverage"]
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--format",
        choices=("human", "json", "csv"),
        default="human",
    )
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Regenerate scripts/tools/rag_coverage_baseline.json.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    matrix = build_coverage_matrix()

    if args.update_baseline:
        _write_baseline(matrix)
        print(f"Updated baseline: {DEFAULT_BASELINE_PATH}")
        return 0

    if args.format == "json":
        json.dump(matrix, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 0
    if args.format == "csv":
        if args.out_dir is None:
            raise SystemExit("--out-dir is required with --format csv")
        _write_csv(matrix, args.out_dir)
        return 0

    _print_human(matrix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
