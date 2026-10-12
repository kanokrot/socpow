#!/usr/bin/env python3
"""Compute holdout metrics and Wilson intervals from stored result files."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from scripts.eval.build_independent_url_holdout import (  # noqa: E402
    DEFAULT_SEED, git_metadata, read_rows, write_json,
)


NON_OVERLAP_NOTE = (
    "รายงานผลใน non-overlap stratum แยกต่างหาก พร้อมระบุชัดว่า URL ที่ไม่มีทั้ง C2 Trackers "
    "และ ThreatFox ตามนิยาม overlap ย่อม flag ไม่ได้จาก URL scoring path; ค่าต่ำใน stratum "
    "นี้จึงไม่ใช่ข้อค้นพบเกี่ยวกับคุณภาพ scoring"
)
SOURCES = ("feodotracker", "c2_trackers", "spamhaus", "tor_exit_nodes", "sslblacklist", "threatfox")


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float | None, float | None]:
    if trials <= 0:
        return None, None
    if successes < 0 or successes > trials:
        raise ValueError("successes must be between zero and trials")
    p = successes / trials
    z2 = z * z
    denom = 1 + z2 / trials
    center = (p + z2 / (2 * trials)) / denom
    margin = z * math.sqrt((p * (1 - p) / trials) + (z2 / (4 * trials * trials))) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected an object on JSONL line {line_no}")
        rows.append(value)
    return rows


def _flags_by_ioc(path: Path) -> dict[str, dict[str, Any]]:
    rows = read_rows(path)
    return {row["ioc"]: row for row in rows if isinstance(row.get("ioc"), str)}


def _truth_is_malicious(row: dict[str, Any]) -> bool:
    return str(row.get("expected_verdict", "")).upper() == "MALICIOUS"


def _predicted_positive(row: dict[str, Any]) -> bool:
    return str(row.get("predicted_verdict", "")).upper() == "MALICIOUS"


def confusion_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    predicted_counts: Counter[str] = Counter()
    expected_counts: Counter[str] = Counter()
    predicted_by_expected: dict[str, Counter[str]] = {}
    unavailable_rows = []
    for row in rows:
        expected = str(row.get("expected_verdict", "UNKNOWN")).upper()
        predicted = str(row.get("predicted_verdict") or "UNKNOWN").upper()
        expected_counts[expected] += 1
        predicted_counts[predicted] += 1
        predicted_by_expected.setdefault(expected, Counter())[predicted] += 1
        actual_pos = expected == "MALICIOUS"
        predicted_pos = predicted == "MALICIOUS"  # SUSPICIOUS and UNKNOWN are negative.
        if actual_pos and predicted_pos:
            tp += 1
        elif actual_pos:
            fn += 1
        elif predicted_pos:
            fp += 1
        else:
            tn += 1
        sources = row.get("sources")
        missing = []
        if isinstance(sources, dict):
            missing = [name for name in SOURCES
                       if isinstance(sources.get(name), dict) and sources[name].get("unavailable") is True]
        elif row.get("trusted_shortcut") is not True:
            missing = list(SOURCES)
        if missing:
            unavailable_rows.append({"ioc": row.get("ioc"), "sources_unavailable": missing})
    precision = tp / (tp + fp) if tp + fp else None
    specificity = tn / (tn + fp) if tn + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    precision_ci = wilson_interval(tp, tp + fp)
    specificity_ci = wilson_interval(tn, tn + fp) if tn + fp else None
    recall_ci = wilson_interval(tp, tp + fn)
    return {
        "n": len(rows),
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "precision": precision,
        "precision_wilson_95_ci": precision_ci,
        "specificity": specificity,
        "specificity_wilson_95": specificity_ci,
        "recall": recall,
        "recall_wilson_95_ci": recall_ci,
        "f1": f1,
        "expected_counts": dict(expected_counts),
        "predicted_3class_counts": dict(predicted_counts),
        "predicted_3class_counts_by_expected": {
            expected: {
                verdict: counts.get(verdict, 0)
                for verdict in ("MALICIOUS", "SUSPICIOUS", "UNKNOWN", "CLEAN")
            }
            for expected, counts in predicted_by_expected.items()
        },
        "rows_with_any_source_unavailable": len(unavailable_rows),
        "unavailable_rows": unavailable_rows,
    }


def _tri_or(*values: bool | None) -> bool | None:
    if any(value is True for value in values):
        return True
    if values and all(value is False for value in values):
        return False
    return None


def _overlap_flags(flags: dict[str, Any]) -> dict[str, bool | None]:
    c2 = flags.get("c2") if isinstance(flags.get("c2"), dict) else {}
    tf = flags.get("threatfox") if isinstance(flags.get("threatfox"), dict) else {}
    tf_exact = tf.get("exact_url") if isinstance(tf.get("exact_url"), dict) else {}
    tf_host = tf.get("host") if isinstance(tf.get("host"), dict) else {}
    c2_known = c2.get("status") == "ok"
    c2_exact = True if c2.get("exact_url_match") else (False if c2_known else None)
    c2_host = True if c2.get("host_level_match") else (False if c2_known else None)
    tf_exact_state = (True if tf_exact.get("hit") else False
                      if tf_exact.get("status") in {"miss", "hit"} else None)
    tf_host_state = (True if tf_host.get("hit") else False
                     if tf_host.get("status") in {"miss", "hit"} else None)
    exact = _tri_or(c2_exact, tf_exact_state)
    host = _tri_or(c2_host, tf_host_state)
    return {"exact": exact, "host": host, "any": _tri_or(exact, host)}


def compute(results_path: Path, overlap_path: Path, out_path: Path,
            seed: int = DEFAULT_SEED) -> tuple[Path, Path]:
    results = _load_jsonl(results_path)
    flags_map = _flags_by_ioc(overlap_path)
    joined: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for row in results:
        ioc = row.get("ioc")
        flags = flags_map.get(ioc) if isinstance(ioc, str) else None
        if flags is None:
            dropped.append({"ioc": ioc, "reason": "missing_overlap_flags"})
            continue
        joined.append({**row, "round": flags.get("round", row.get("round", row.get("sampling_source", row.get("source")))),
                       "overlap_flags": _overlap_flags(flags)})

    groups: dict[str, list[dict[str, Any]]] = {"overall": joined}
    rounds = sorted({str(row.get("round") or "unknown") for row in joined})
    for round_name in rounds:
        groups[f"round:{round_name}"] = [row for row in joined if str(row.get("round") or "unknown") == round_name]
    groups["overlap:any"] = [row for row in joined if row["overlap_flags"]["any"]]
    groups["non_overlap:any"] = [row for row in joined if row["overlap_flags"]["any"] is False]
    groups["unknown_overlap:any"] = [row for row in joined if row["overlap_flags"]["any"] is None]
    groups["overlap:exact_url"] = [row for row in joined if row["overlap_flags"]["exact"]]
    groups["non_overlap:exact_url"] = [row for row in joined if row["overlap_flags"]["exact"] is False]
    groups["unknown_overlap:exact_url"] = [row for row in joined if row["overlap_flags"]["exact"] is None]
    groups["overlap:host_level"] = [row for row in joined if row["overlap_flags"]["host"]]
    groups["non_overlap:host_level"] = [row for row in joined if row["overlap_flags"]["host"] is False]
    groups["unknown_overlap:host_level"] = [row for row in joined if row["overlap_flags"]["host"] is None]
    metrics = {name: confusion_metrics(group) for name, group in groups.items()}
    malicious = [row for row in joined if _truth_is_malicious(row)]
    coverage = {}
    for kind, flag_key in (("exact_url", "exact"), ("host_level", "host"), ("either", "any")):
        known_rows = [row for row in malicious if row["overlap_flags"][flag_key] is not None]
        successes = sum(row["overlap_flags"][flag_key] is True for row in known_rows)
        coverage[kind] = {"successes": successes, "trials": len(known_rows),
                          "unknown_source_rows": len(malicious) - len(known_rows),
                          "rate": successes / len(known_rows) if known_rows else None,
                          "wilson_95_ci": wilson_interval(successes, len(known_rows))}
    output = {"inputs": {"eval_results": str(results_path), "overlap_flags": str(overlap_path)},
              "metrics": metrics, "malicious_overlap_coverage": coverage,
              "joined_rows": len(joined), "eval_rows": len(results),
              "missing_overlap_flags": len(dropped), "non_overlap_note": NON_OVERLAP_NOTE}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(out_path, output)
    manifest_path = out_path.with_name(out_path.stem + "_manifest.json")
    write_json(manifest_path, {"script": Path(__file__).name, "seed": seed,
                              "counts_by_stage": {"eval_results": len(results),
                                                   "joined": len(joined),
                                                   "missing_overlap_flags": len(dropped)},
                              "dropped_items": dropped, "output_file": str(out_path),
                              **git_metadata()})
    print(NON_OVERLAP_NOTE)
    return out_path, manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-results", type=Path, required=True)
    parser.add_argument("--overlap-flags", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    try:
        output, manifest = compute(args.eval_results, args.overlap_flags, args.output, args.seed)
    except Exception as exc:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.output.with_name(args.output.stem + "_manifest.json"), {
            "script": Path(__file__).name, "seed": args.seed,
            "counts_by_stage": {}, "dropped_items": [{"reason": "run_failed", "error": type(exc).__name__}],
            **git_metadata(),
        })
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"Wrote {output} and {manifest}")


if __name__ == "__main__":
    main()
