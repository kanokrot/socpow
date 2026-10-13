#!/usr/bin/env python3
"""Offline verdict sensitivity analysis using stored evaluation source records.

No evaluator, feed, or API is invoked. A baseline reproduction gate runs before
any sensitivity scenario; a mismatch records diagnostics and stops the run.
"""
from __future__ import annotations

import argparse
import csv
import dis
import hashlib
import json
import math
import random
import subprocess
import sys
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import FunctionType
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.scoring import intelligent_scoring as scoring_module
from src.scoring.intelligent_scoring import IntelligentScoring
from src.utils import helpers as helpers_module
from src.utils.helpers import determine_verdict

SEED = 20261013
RANDOM_ROUNDS = 1000
SOURCES = tuple(scoring_module.SOURCE_SCORING_MULTIPLIERS)
CURRENT_WEIGHTS = dict(scoring_module.SOURCE_SCORING_MULTIPLIERS)
WEIGHT_GRID = {
    "current_ahp": CURRENT_WEIGHTS,
    "equal": {name: 1.0 for name in SOURCES},
}
WEIGHT_ORDER = sorted(SOURCES, key=lambda name: CURRENT_WEIGHTS[name], reverse=True)
ADJACENT_WEIGHT_SWAPS = [
    (WEIGHT_ORDER[index], WEIGHT_ORDER[index + 1])
    for index in range(len(WEIGHT_ORDER) - 1)
]
MULTIPLIER_2_GRID = [1.00, 1.10, 1.20, 1.30, 1.40]
MULTIPLIER_3_GRID = [1.20, 1.30, 1.40]
MALICIOUS_THRESHOLD_GRID = [60, 65, 70, 75, 80]
SUSPICIOUS_THRESHOLD_GRID = [30, 35, 40, 45, 50]
COVERAGE_THRESHOLD = 0.30

DATASETS = {
    "group_a_908": [
        "evidence/vt_independent_holdout_2026-09-25/group_a_eval_results.jsonl"
    ],
    "holdout_200": [
        "evidence/vt_independent_holdout_2026-09-25/vt_holdout_eval_results_179.jsonl",
        "evidence/vt_independent_holdout_2026-09-25/vt_holdout_eval_results_batch3_21.jsonl",
    ],
    "independent_256": [
        "evidence/independent_url_holdout_2026-10-11/eval_results.jsonl"
    ],
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(paths: Iterable[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            rows.extend(json.loads(line) for line in handle if line.strip())
    return rows


def _source_payload(row: dict[str, Any]) -> dict[str, Any]:
    sources = row.get("sources")
    return sources if isinstance(sources, dict) else {}


def _is_shortcut(row: dict[str, Any]) -> bool:
    return row.get("trusted_shortcut") is True or row.get("evaluation_path") == "trusted_shortcut"


def _calc(row: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
    if _is_shortcut(row):
        # Trusted-shortcut results bypass source scoring in the stored run.
        return int(row.get("threat_score") or 0), {}, str(row["predicted_verdict"])
    payload = {"sources": _source_payload(row)}
    score = IntelligentScoring.calculate_ioc_score(payload)
    coverage = IntelligentScoring.calculate_source_coverage(payload)
    verdict = determine_verdict(score, coverage)
    return score, coverage, verdict


def _replace_numeric_constants(function: FunctionType, replacements: dict[float | int, float | int]) -> FunctionType:
    """Clone a production function while replacing only its numeric constants.

    This preserves the actual production function logic and is used only within
    the current process to expose hard-coded calibration constants to a grid.
    """
    old_code = function.__code__
    new_constants = tuple(
        replacements.get(value, value)
        if isinstance(value, (int, float)) and not isinstance(value, bool)
        else value
        for value in old_code.co_consts
    )
    bytecode = bytearray(old_code.co_code)
    # CPython 3.14 emits LOAD_SMALL_INT for literal integers instead of
    # storing them in co_consts. Patch only those literal-load operands.
    for instruction in dis.get_instructions(function):
        if instruction.opname == "LOAD_SMALL_INT" and instruction.argval in replacements:
            replacement = replacements[instruction.argval]
            if not isinstance(replacement, int) or not 0 <= replacement <= 255:
                raise ValueError(f"LOAD_SMALL_INT replacement must be an integer in 0..255: {replacement!r}")
            bytecode[instruction.offset + 1] = replacement
    new_code = old_code.replace(co_consts=new_constants, co_code=bytes(bytecode))
    return FunctionType(new_code, function.__globals__, function.__name__, function.__defaults__, function.__closure__)


@contextmanager
def production_parameters(
    weights: dict[str, float] | None = None,
    multiplier_2: float = 1.20,
    multiplier_3: float = 1.30,
    malicious_threshold: int = 70,
    suspicious_threshold: int = 40,
):
    """Temporarily patch production constants/functions in this process only."""
    old_weights = scoring_module.SOURCE_SCORING_MULTIPLIERS
    original_score_method = IntelligentScoring.calculate_ioc_score
    original_verdict = helpers_module.determine_verdict
    score_function = original_score_method
    verdict_function = original_verdict
    patched_score = _replace_numeric_constants(score_function, {1.20: multiplier_2, 1.3: multiplier_3})
    patched_verdict = _replace_numeric_constants(
        verdict_function,
        {70: malicious_threshold, 40: suspicious_threshold},
    )
    try:
        if weights is not None:
            scoring_module.SOURCE_SCORING_MULTIPLIERS = dict(weights)
        IntelligentScoring.calculate_ioc_score = staticmethod(patched_score)
        helpers_module.determine_verdict = patched_verdict
        # _calc resolves the imported alias, so patch that alias too.
        globals()["determine_verdict"] = patched_verdict
        yield
    finally:
        scoring_module.SOURCE_SCORING_MULTIPLIERS = old_weights
        IntelligentScoring.calculate_ioc_score = staticmethod(original_score_method)
        helpers_module.determine_verdict = original_verdict
        globals()["determine_verdict"] = original_verdict


def baseline_check(datasets: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    report: dict[str, Any] = {}
    mismatches: list[dict[str, Any]] = []
    for dataset_name, rows in datasets.items():
        row_mismatches = []
        shortcut_count = sum(_is_shortcut(row) for row in rows)
        checked_count = 0
        for index, row in enumerate(rows):
            if _is_shortcut(row):
                continue
            checked_count += 1
            score, coverage, verdict = _calc(row)
            stored = row.get("predicted_verdict")
            if verdict != stored:
                row_mismatches.append(
                    {
                        "row_index": index,
                        "ioc": row.get("ioc"),
                        "stored_verdict": stored,
                        "recalculated_verdict": verdict,
                        "stored_threat_score": row.get("threat_score"),
                        "recalculated_threat_score": score,
                        "coverage": {
                            "total_sources_attempted": coverage.get("total_sources_attempted", 0),
                            "sources_flagged": coverage.get("sources_flagged", 0),
                            "sources_clean": coverage.get("sources_clean", 0),
                            "sources_unavailable": coverage.get("sources_unavailable", 0),
                        },
                    }
                )
        report[dataset_name] = {
            "rows": len(rows),
            "shortcut_count": shortcut_count,
            "baseline_checked_non_shortcut_rows": checked_count,
            "mismatch_count": len(row_mismatches),
            "examples": row_mismatches[:20],
        }
        mismatches.extend({"dataset": dataset_name, **item} for item in row_mismatches)
    report["total_mismatches"] = len(mismatches)
    report["mismatch_examples"] = mismatches[:50]
    return report


def _metrics(rows: list[dict[str, Any]], predictions: list[str]) -> dict[str, float | int | None]:
    expected = [row.get("expected_verdict") == "MALICIOUS" for row in rows]
    predicted = [verdict == "MALICIOUS" for verdict in predictions]
    tp = sum(actual and guess for actual, guess in zip(expected, predicted))
    fp = sum((not actual) and guess for actual, guess in zip(expected, predicted))
    tn = sum((not actual) and (not guess) for actual, guess in zip(expected, predicted))
    fn = sum(actual and (not guess) for actual, guess in zip(expected, predicted))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is None or recall is None:
        f1 = None
    elif tp == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    return {"n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}


def _baseline_diagnostics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe stored scores and production-recognized source flags."""
    score_distribution: dict[str, Counter] = {}
    flag_count_distribution: Counter = Counter()
    single_flagged: dict[str, Counter] = {name: Counter() for name in SOURCES}
    single_flagged_rows: Counter = Counter()
    consensus_counts = Counter()
    flagged_statuses = {"✓", "✓ FLAGGED", "FLAGGED", "flagged"}

    for row in rows:
        expected = str(row.get("expected_verdict", "NOT_RECORDED"))
        score_distribution.setdefault(expected, Counter())[str(row.get("threat_score"))] += 1
        sources = _source_payload(row)
        flagged_names = []
        for name in SOURCES:
            source_data = sources.get(name)
            if not isinstance(source_data, dict) or IntelligentScoring._is_source_error(source_data):
                continue
            if source_data.get("status") in flagged_statuses:
                flagged_names.append(name)
        flag_count_distribution[min(len(flagged_names), 3)] += 1
        if len(flagged_names) >= 2:
            consensus_counts["two_or_more"] += 1
            consensus_counts["two_sources"] += len(flagged_names) == 2
            consensus_counts["three_or_more_sources"] += len(flagged_names) >= 3
        if len(flagged_names) == 1:
            name = flagged_names[0]
            raw_score = IntelligentScoring._get_source_score(sources[name])
            single_flagged[name][str(raw_score)] += 1
            single_flagged_rows[name] += 1

    return {
        "threat_score_distribution_by_expected_verdict": {
            label: dict(sorted(counts.items())) for label, counts in sorted(score_distribution.items())
        },
        "flagged_source_count_distribution": {
            "0": flag_count_distribution[0], "1": flag_count_distribution[1],
            "2": flag_count_distribution[2], "3+": flag_count_distribution[3],
        },
        "single_flagged_rows_by_source": {
            name: {"count": single_flagged_rows[name], "raw_score_counts": dict(sorted(counts.items()))}
            for name, counts in sorted(single_flagged.items()) if single_flagged_rows[name]
        },
        "consensus_boost_rows": {
            "two_sources": int(consensus_counts["two_sources"]),
            "three_or_more_sources": int(consensus_counts["three_or_more_sources"]),
            "total": int(consensus_counts["two_or_more"]),
        },
    }


def _metric_delta(value: float | int | None, baseline: float | int | None) -> float | None:
    return value - baseline if value is not None and baseline is not None else None


def _scenario_result(rows: list[dict[str, Any]], baseline: list[str], predictions: list[str]) -> dict[str, Any]:
    transitions = Counter((old, new) for old, new in zip(baseline, predictions) if old != new)
    changed = sum(transitions.values())
    per_type_changes = {}
    for ioc_type in sorted({row.get("expected_ioc_type", row.get("ioc_type")) for row in rows} - {None}):
        indices = [index for index, row in enumerate(rows) if row.get("expected_ioc_type", row.get("ioc_type")) == ioc_type]
        type_transitions = Counter((baseline[index], predictions[index]) for index in indices if baseline[index] != predictions[index])
        per_type_changes[ioc_type] = {
            "changed_count": sum(type_transitions.values()),
            "changed_to_clean": sum(count for (_, new), count in type_transitions.items() if new == "CLEAN"),
            "changed_to_suspicious": sum(count for (_, new), count in type_transitions.items() if new == "SUSPICIOUS"),
            "changed_to_malicious": sum(count for (_, new), count in type_transitions.items() if new == "MALICIOUS"),
            "changed_to_unknown": sum(count for (_, new), count in type_transitions.items() if new == "UNKNOWN"),
        }
    return {
        "changed_count": changed,
        "changed_to_clean": sum(count for (_, new), count in transitions.items() if new == "CLEAN"),
        "changed_to_suspicious": sum(count for (_, new), count in transitions.items() if new == "SUSPICIOUS"),
        "changed_to_malicious": sum(count for (_, new), count in transitions.items() if new == "MALICIOUS"),
        "changed_to_unknown": sum(count for (_, new), count in transitions.items() if new == "UNKNOWN"),
        "shortcut_count": sum(_is_shortcut(row) for row in rows),
        "transitions": {f"{old}->{new}": count for (old, new), count in sorted(transitions.items())},
        "per_ioc_type_changes": per_type_changes,
        "metrics": _metrics(rows, predictions),
        "per_ioc_type": {
            ioc_type: _metrics(subset, [prediction for row, prediction in zip(rows, predictions) if row.get("expected_ioc_type", row.get("ioc_type")) == ioc_type])
            for ioc_type in sorted({row.get("expected_ioc_type", row.get("ioc_type")) for row in rows})
            if ioc_type is not None
            for subset in [[row for row in rows if row.get("expected_ioc_type", row.get("ioc_type")) == ioc_type]]
        },
    }


def _evaluate(rows: list[dict[str, Any]], baseline: list[str], label: str, params: dict[str, Any], weights: dict[str, float] | None = None) -> dict[str, Any]:
    with production_parameters(weights=weights, **params):
        predictions = [row["predicted_verdict"] if _is_shortcut(row) else _calc(row)[2] for row in rows]
    result = {"factor": label, "value": params | ({"weights": weights} if weights is not None else {}), **_scenario_result(rows, baseline, predictions)}
    baseline_by_type = {}
    for ioc_type in {row.get("expected_ioc_type", row.get("ioc_type")) for row in rows}:
        if ioc_type is None:
            continue
        subset = [row for row in rows if row.get("expected_ioc_type", row.get("ioc_type")) == ioc_type]
        subset_baseline = [verdict for row, verdict in zip(rows, baseline) if row.get("expected_ioc_type", row.get("ioc_type")) == ioc_type]
        baseline_by_type[ioc_type] = _metrics(subset, subset_baseline)
    result["per_ioc_type_delta"] = {
        ioc_type: {
            key: (value - baseline_by_type[ioc_type][key] if value is not None and baseline_by_type[ioc_type][key] is not None else None)
            for key, value in metrics.items() if key in ("accuracy", "precision", "recall", "f1")
        }
        for ioc_type, metrics in result["per_ioc_type"].items()
    }
    return result


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _random_weight_summary(rows: list[dict[str, Any]], baseline: list[str], sigma: float, dataset_name: str) -> dict[str, Any]:
    rng = random.Random(SEED)
    run_results = []
    for _ in range(RANDOM_ROUNDS):
        weights = {
            name: CURRENT_WEIGHTS[name] * math.exp(rng.gauss(0.0, sigma))
            for name in SOURCES
        }
        with production_parameters(weights=weights):
            predictions = [row["predicted_verdict"] if _is_shortcut(row) else _calc(row)[2] for row in rows]
        run_results.append(_scenario_result(rows, baseline, predictions))
    metric_names = ("accuracy", "precision", "recall", "f1")
    change_names = ("changed_count", "changed_to_clean", "changed_to_suspicious", "changed_to_malicious", "changed_to_unknown")
    aggregates = {}
    for name in (*metric_names, *change_names):
        values = [
            float(value)
            for item in run_results
            for value in [item["metrics"][name] if name in metric_names else item[name]]
            if value is not None
        ]
        aggregates[name] = {
            "mean": sum(values) / len(values) if values else None,
            "p2_5": _percentile(values, 0.025),
            "p97_5": _percentile(values, 0.975),
            "n_defined": len(values),
        }
    identical = sum(item["changed_count"] == 0 for item in run_results) / RANDOM_ROUNDS
    baseline_metrics = _metrics(rows, baseline)
    for name in metric_names:
        mean = aggregates[name]["mean"]
        base_value = baseline_metrics[name]
        aggregates[name]["delta_mean"] = mean - base_value if mean is not None and base_value is not None else None
    per_type = {}
    for ioc_type in sorted({row.get("expected_ioc_type", row.get("ioc_type")) for row in rows} - {None}):
        selected = [index for index, row in enumerate(rows) if row.get("expected_ioc_type", row.get("ioc_type")) == ioc_type]
        type_rows = [rows[index] for index in selected]
        type_baseline = [baseline[index] for index in selected]
        base_metrics = _metrics(type_rows, type_baseline)
        type_results = [
            {"metrics": item["per_ioc_type"][ioc_type], "changed": item["per_ioc_type_changes"][ioc_type]}
            for item in run_results
        ]
        metrics = {}
        for metric in metric_names:
            values = [float(item["metrics"][metric]) for item in type_results if item["metrics"][metric] is not None]
            mean = sum(values) / len(values) if values else None
            base_value = base_metrics[metric]
            metrics[metric] = {
                "mean": mean,
                "p2_5": _percentile(values, 0.025),
                "p97_5": _percentile(values, 0.975),
                "delta_mean": mean - base_value if mean is not None and base_value is not None else None,
                "n_defined": len(values),
            }
        changed_values = [float(item["changed"]["changed_count"]) for item in type_results]
        metrics["changed_count"] = {"mean": sum(changed_values) / len(changed_values), "p2_5": _percentile(changed_values, 0.025), "p97_5": _percentile(changed_values, 0.975)}
        for change_name in ("changed_to_clean", "changed_to_suspicious", "changed_to_malicious", "changed_to_unknown"):
            values = [float(item["changed"][change_name]) for item in type_results]
            metrics[change_name] = {"mean": sum(values) / len(values), "p2_5": _percentile(values, 0.025), "p97_5": _percentile(values, 0.975)}
        metrics["all_verdicts_equal_baseline_fraction"] = sum(value == 0 for value in changed_values) / RANDOM_ROUNDS
        per_type[ioc_type] = metrics
    return {
        "factor": "lognormal_weight_perturbation",
        "value": {"sigma": sigma, "rounds": RANDOM_ROUNDS, "seed": SEED},
        "shortcut_count": sum(_is_shortcut(row) for row in rows),
        "baseline_metrics": baseline_metrics,
        "aggregates": aggregates,
        "per_ioc_type": per_type,
        "all_verdicts_equal_baseline_fraction": identical,
    }


def _full_grid(rows: list[dict[str, Any]], baseline: list[str]) -> list[dict[str, Any]]:
    results = []
    for multiplier_2 in MULTIPLIER_2_GRID:
        for multiplier_3 in MULTIPLIER_3_GRID:
            for malicious in MALICIOUS_THRESHOLD_GRID:
                for suspicious in SUSPICIOUS_THRESHOLD_GRID:
                    if suspicious > malicious:
                        continue
                    results.append(_evaluate(rows, baseline, "multiplier_x_threshold_full_grid", {
                        "multiplier_2": multiplier_2,
                        "multiplier_3": multiplier_3,
                        "malicious_threshold": malicious,
                        "suspicious_threshold": suspicious,
                    }))
    for malicious in MALICIOUS_THRESHOLD_GRID:
        for suspicious in SUSPICIOUS_THRESHOLD_GRID:
            if suspicious <= malicious:
                    results.append(_evaluate(rows, baseline, "multiplier_x_threshold_full_grid", {
                    "multiplier_2": 1.00,
                    "multiplier_3": 1.00,
                    "malicious_threshold": malicious,
                    "suspicious_threshold": suspicious,
                    }) | {"value": {
                        "multiplier_2": 1.00,
                        "multiplier_3": 1.00,
                        "malicious_threshold": malicious,
                        "suspicious_threshold": suspicious,
                        "multiplier_case": "none",
                    }})
    return results


def declared_grid() -> dict[str, Any]:
    return {
        "seed": SEED,
        "random_perturbation_rounds_per_dataset_sigma": RANDOM_ROUNDS,
        "weights": {
            "current_ahp": CURRENT_WEIGHTS,
            "equal": "1.0 for every scoring source",
            "adjacent_priority_swaps": [list(pair) for pair in ADJACENT_WEIGHT_SWAPS],
            "lognormal_sigma": [0.25, 0.5],
        },
        "multipliers": {"two_sources": MULTIPLIER_2_GRID, "three_or_more_sources": MULTIPLIER_3_GRID, "no_multiplier": [1.0, 1.0]},
        "thresholds": {"malicious": MALICIOUS_THRESHOLD_GRID, "suspicious": SUSPICIOUS_THRESHOLD_GRID, "coverage": COVERAGE_THRESHOLD, "constraint": "suspicious <= malicious"},
        "full_multiplier_x_threshold_grid": "holdout_200 only; all valid combinations, including no multiplier",
    }


def load_datasets() -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[Path]]]:
    input_paths = {name: [REPO_ROOT / relative for relative in paths] for name, paths in DATASETS.items()}
    for dataset_paths in input_paths.values():
        missing = [path for path in dataset_paths if not path.is_file()]
        if missing:
            raise FileNotFoundError("Missing input file(s): " + ", ".join(str(path) for path in missing))
    datasets = {name: read_jsonl(paths) for name, paths in input_paths.items()}
    return datasets, input_paths


def run(output_dir: Path) -> int:
    datasets, input_paths = load_datasets()
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True, capture_output=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, text=True, capture_output=True, check=True).stdout.strip())
    output_dir.mkdir(parents=True, exist_ok=True)
    shortcut_counts = {name: sum(_is_shortcut(row) for row in rows) for name, rows in datasets.items()}
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "script_git_commit": commit,
        "script_git_dirty": dirty,
        "seed": SEED,
        "grid": declared_grid(),
        "input_files": {
            name: [{"path": str(path.relative_to(REPO_ROOT)), "sha256": sha256_file(path)} for path in paths]
            for name, paths in input_paths.items()
        },
        "dataset_rows": {name: len(rows) for name, rows in datasets.items()},
        "trusted_shortcut_deviation": {
            "deviation_from_original_specification": True,
            "reason": "Trusted-shortcut rows bypassed per-source scoring in the stored evaluation; the responsible reviewer decided to retain their stored predicted_verdict in every sensitivity scenario.",
            "decision_timing": "Recorded before any sensitivity result was calculated.",
            "baseline_gate": "Applied to every non-shortcut row; shortcut rows are excluded from reproduction comparison.",
            "scenario_handling": "Shortcut rows retain their stored predicted_verdict and remain included in all metrics and dataset denominators.",
            "counts_by_dataset": shortcut_counts,
        },
        "status": "baseline_check_pending",
    }
    manifest_path = output_dir / "sensitivity_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    baseline_report = baseline_check(datasets)
    manifest["baseline_check"] = baseline_report
    if baseline_report["total_mismatches"]:
        manifest["status"] = "stopped_baseline_mismatch"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": manifest["status"],
            "mismatch_count_by_dataset": {name: item["mismatch_count"] for name, item in baseline_report.items() if isinstance(item, dict)},
            "examples": [
                {"dataset": item["dataset"], "row_index": item["row_index"], "ioc": item["ioc"], "stored": item["stored_verdict"], "recalculated": item["recalculated_verdict"]}
                for item in baseline_report["mismatch_examples"][:5]
            ],
            "manifest": str(manifest_path.relative_to(REPO_ROOT)),
        }, ensure_ascii=False, indent=2))
        return 2

    manifest["status"] = "sensitivity_complete"
    all_results: dict[str, Any] = {}
    csv_rows: list[dict[str, Any]] = []
    for dataset_name, rows in datasets.items():
        baseline = [row["predicted_verdict"] for row in rows]
        baseline_metrics = _metrics(rows, baseline)
        scenarios = []
        for weight_name, weights in WEIGHT_GRID.items():
            scenarios.append(_evaluate(rows, baseline, "weights", {"multiplier_2": 1.20, "multiplier_3": 1.30}, weights={name: float(value) for name, value in weights.items()}))
        for first, second in ADJACENT_WEIGHT_SWAPS:
            swapped = dict(CURRENT_WEIGHTS)
            swapped[first], swapped[second] = swapped[second], swapped[first]
            scenarios.append(_evaluate(rows, baseline, "weights_adjacent_swap", {"multiplier_2": 1.20, "multiplier_3": 1.30}, weights=swapped) | {"value": {"swap": [first, second], "weights": swapped}})
        random_results = [_random_weight_summary(rows, baseline, sigma, dataset_name) for sigma in (0.25, 0.5)]
        for multiplier_2 in MULTIPLIER_2_GRID:
            scenarios.append(_evaluate(rows, baseline, "multiplier_2_sources", {"multiplier_2": multiplier_2, "multiplier_3": 1.30}))
        for multiplier_3 in MULTIPLIER_3_GRID:
            scenarios.append(_evaluate(rows, baseline, "multiplier_3plus_sources", {"multiplier_2": 1.20, "multiplier_3": multiplier_3}))
        scenarios.append(_evaluate(rows, baseline, "no_consensus_multiplier", {"multiplier_2": 1.00, "multiplier_3": 1.00}))
        for malicious in MALICIOUS_THRESHOLD_GRID:
            scenarios.append(_evaluate(rows, baseline, "malicious_threshold", {"multiplier_2": 1.20, "multiplier_3": 1.30, "malicious_threshold": malicious}))
        for suspicious in SUSPICIOUS_THRESHOLD_GRID:
            scenarios.append(_evaluate(rows, baseline, "suspicious_threshold", {"multiplier_2": 1.20, "multiplier_3": 1.30, "suspicious_threshold": suspicious}))
        all_results[dataset_name] = {
            "baseline_metrics": baseline_metrics,
            "baseline_diagnostics": _baseline_diagnostics(rows),
            "scenarios": scenarios,
            "random_weight_perturbations": random_results,
        }
        for item in scenarios:
            metrics = item["metrics"]
            csv_rows.append({
                "dataset": dataset_name, "factor": item["factor"], "value": json.dumps(item["value"], ensure_ascii=False, sort_keys=True),
                "changed_count": item["changed_count"], "changed_to_clean": item["changed_to_clean"], "changed_to_suspicious": item["changed_to_suspicious"],
                "changed_to_malicious": item["changed_to_malicious"], "changed_to_unknown": item["changed_to_unknown"], "shortcut_count": item["shortcut_count"],
                **metrics,
                **{f"delta_{key}": _metric_delta(metrics[key], baseline_metrics[key]) for key in ("accuracy", "precision", "recall", "f1")},
                "per_ioc_type": json.dumps(item["per_ioc_type"], ensure_ascii=False, sort_keys=True),
                "per_ioc_type_changes": json.dumps(item["per_ioc_type_changes"], ensure_ascii=False, sort_keys=True),
            })
        for item in random_results:
            random_row = {
                "dataset": dataset_name, "factor": item["factor"],
                "value": json.dumps(item["value"], sort_keys=True),
                "shortcut_count": item["shortcut_count"],
                "random_aggregates": json.dumps(item["aggregates"], sort_keys=True),
                "per_ioc_type": json.dumps(item["per_ioc_type"], ensure_ascii=False, sort_keys=True),
                "all_verdicts_equal_baseline_fraction": item["all_verdicts_equal_baseline_fraction"],
            }
            for metric, aggregate in item["aggregates"].items():
                for statistic in ("mean", "p2_5", "p97_5", "delta_mean"):
                    if statistic in aggregate:
                        random_row[f"{metric}_{statistic}"] = aggregate[statistic]
            csv_rows.append(random_row)
        if dataset_name == "holdout_200":
            full_grid = _full_grid(rows, baseline)
            all_results[dataset_name]["multiplier_x_threshold_full_grid"] = full_grid
            for item in full_grid:
                metrics = item["metrics"]
                csv_rows.append({
                    "dataset": dataset_name, "factor": item["factor"], "value": json.dumps(item["value"], ensure_ascii=False, sort_keys=True),
                    "changed_count": item["changed_count"], "changed_to_clean": item["changed_to_clean"], "changed_to_suspicious": item["changed_to_suspicious"],
                    "changed_to_malicious": item["changed_to_malicious"], "changed_to_unknown": item["changed_to_unknown"], "shortcut_count": item["shortcut_count"],
                    **metrics,
                    **{f"delta_{key}": _metric_delta(metrics[key], baseline_metrics[key]) for key in ("accuracy", "precision", "recall", "f1")},
                    "per_ioc_type": json.dumps(item["per_ioc_type"], ensure_ascii=False, sort_keys=True),
                    "per_ioc_type_changes": json.dumps(item["per_ioc_type_changes"], ensure_ascii=False, sort_keys=True),
                })

    manifest["status"] = "sensitivity_complete"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "sensitivity_results.json").write_text(json.dumps(all_results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if csv_rows:
        with (output_dir / "sensitivity_summary.csv").open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(dict.fromkeys(key for row in csv_rows for key in row)))
            writer.writeheader()
            writer.writerows(csv_rows)
    _write_paper_summary(output_dir / "sensitivity_paper_summary.md", all_results)
    print(json.dumps({"status": manifest["status"], "rows": manifest["dataset_rows"], "output_dir": str(output_dir), "baseline_check": baseline_report}, ensure_ascii=False, indent=2))
    return 0


def _write_paper_summary(path: Path, results: dict[str, Any]) -> None:
    def fmt(value: float | int | None) -> str:
        return "ไม่นิยาม" if value is None else f"{value:.3f}"

    lines = [
        "# สรุป sensitivity analysis แบบ offline",
        "",
        "คำนวณจาก per-source records ที่บันทึกไว้ ไม่ได้รันระบบหรือแหล่งข้อมูลสดซ้ำ; ชุดทดสอบมีข้อจำกัดเรื่องการซ้อนทับของ label กับแหล่งให้คะแนนตามที่ paper ระบุ.",
        "",
        "รายละเอียดทุก dataset × factor × value รวม metrics และผลแยก IOC type อยู่ใน `sensitivity_summary.csv` และ `sensitivity_results.json`.",
        "",
        "| ชุด | N | Shortcut | Baseline A/P/R/F1 | Δ accuracy: OAT min–max | เปลี่ยน verdict: OAT min–max |",
        "|---|---:|---:|---|---:|---:|",
    ]
    for name, data in results.items():
        scenarios = data["scenarios"]
        base = data["baseline_metrics"]
        accuracy_deltas = [item["metrics"]["accuracy"] - base["accuracy"] for item in scenarios]
        changed_values = [item["changed_count"] for item in scenarios]
        shortcut_count = data["baseline_diagnostics"].get("shortcut_count", scenarios[0]["shortcut_count"])
        lines.append(
            f"| {name} | {base['n']} | {shortcut_count} | "
            f"{fmt(base['accuracy'])}/{fmt(base['precision'])}/{fmt(base['recall'])}/{fmt(base['f1'])} | "
            f"{min(accuracy_deltas):+.3f}–{max(accuracy_deltas):+.3f} | {min(changed_values)}–{max(changed_values)} |"
        )
    lines += [
        "", "ผล perturbation แบบ log-normal (1,000 รอบต่อ sigma; แสดงค่าเฉลี่ยและ P2.5–P97.5):", "",
        "| ชุด | σ | Accuracy mean [P2.5, P97.5] | Recall mean [P2.5, P97.5] | Changed rows mean [P2.5, P97.5] | รอบที่ทุก verdict ตรง baseline |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, data in results.items():
        for item in data["random_weight_perturbations"]:
            acc = item["aggregates"]["accuracy"]
            recall = item["aggregates"]["recall"]
            changed = item["aggregates"]["changed_count"]
            lines.append(
                f"| {name} | {item['value']['sigma']} | "
                f"{fmt(acc['mean'])} [{fmt(acc['p2_5'])}, {fmt(acc['p97_5'])}] | "
                f"{fmt(recall['mean'])} [{fmt(recall['p2_5'])}, {fmt(recall['p97_5'])}] | "
                f"{fmt(changed['mean'])} [{fmt(changed['p2_5'])}, {fmt(changed['p97_5'])}] | "
                f"{item['all_verdicts_equal_baseline_fraction']:.3f} |"
            )
    lines += [
        "", "ผลแยกประเภท IOC: baseline A/P/R/F1 และช่วงจำนวน verdict ที่เปลี่ยนใน deterministic OAT grid:", "",
        "| ชุด | IOC type | Baseline A/P/R/F1 | เปลี่ยน verdict: min–max |",
        "|---|---|---|---:|",
    ]
    for name, data in results.items():
        baseline_by_type = data["scenarios"][0]["per_ioc_type"]
        for ioc_type, metrics in baseline_by_type.items():
            changes = [item["per_ioc_type_changes"][ioc_type]["changed_count"] for item in data["scenarios"]]
            lines.append(
                f"| {name} | {ioc_type} | "
                f"{fmt(metrics['accuracy'])}/{fmt(metrics['precision'])}/{fmt(metrics['recall'])}/{fmt(metrics['f1'])} | "
                f"{min(changes)}–{max(changes)} |"
            )
    lines += [
        "", "Shortcut rows คง predicted_verdict ที่จัดเก็บไว้และยังนับใน N กับ metrics. ตัวเลขนี้เป็นการวิเคราะห์ sensitivity เท่านั้น ไม่ได้ปรับค่า production.", "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "evidence" / "sensitivity_2026-10-13")
    args = parser.parse_args(argv)
    return run(args.out_dir.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
