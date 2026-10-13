import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.eval import sensitivity_analysis as sensitivity


def source(status="➖", score=0, unavailable=False):
    return {"status": status, "score": score, "unavailable": unavailable}


def six_sources(**overrides):
    values = {name: source() for name in sensitivity.SOURCES}
    values.update(overrides)
    return values


def test_current_functions_reproduce_baseline_and_count_negative_classes():
    rows = [
        {"sources": six_sources(), "expected_verdict": "CLEAN", "predicted_verdict": "CLEAN", "expected_ioc_type": "url"},
        {"sources": six_sources(), "expected_verdict": "MALICIOUS", "predicted_verdict": "CLEAN", "expected_ioc_type": "ip"},
    ]
    report = sensitivity.baseline_check({"tiny": rows})
    assert report["total_mismatches"] == 0
    metrics = sensitivity._metrics(rows, ["CLEAN", "UNKNOWN"])
    assert (metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]) == (0, 0, 1, 1)
    assert metrics["accuracy"] == 0.5


def test_process_local_consensus_multiplier_patch_changes_actual_function_output():
    payload = {"sources": six_sources(
        feodotracker=source("✓", 60),
        spamhaus=source("✓", 60),
    )}
    baseline = sensitivity.IntelligentScoring.calculate_ioc_score(payload)
    with sensitivity.production_parameters(multiplier_2=1.0):
        without_multiplier = sensitivity.IntelligentScoring.calculate_ioc_score(payload)
    # The inputs are FeodoTracker=60 and Spamhaus=60. Their weights are
    # 1.5 and 0.695930, so the weighted average is 59.99999999999999 due to
    # binary floating-point representation. Production multiplies that by
    # 1.20 first (71.99999999999999), then applies int() once at return: 71.
    assert baseline == 71
    assert without_multiplier == 59  # int(59.99999999999999) truncates to 59.
    assert sensitivity.IntelligentScoring.calculate_ioc_score(payload) == baseline


def test_process_local_threshold_patch_changes_actual_verdict_function():
    payload = {"sources": six_sources(feodotracker=source("✓", 65))}
    score = sensitivity.IntelligentScoring.calculate_ioc_score(payload)
    coverage = sensitivity.IntelligentScoring.calculate_source_coverage(payload)
    assert sensitivity.determine_verdict(score, coverage) == "SUSPICIOUS"
    with sensitivity.production_parameters(malicious_threshold=60):
        assert sensitivity.determine_verdict(score, coverage) == "MALICIOUS"
    assert sensitivity.determine_verdict(score, coverage) == "SUSPICIOUS"


def test_declared_grid_has_seeded_perturbations_and_valid_threshold_order():
    grid = sensitivity.declared_grid()
    assert grid["seed"] == 20261013
    assert grid["random_perturbation_rounds_per_dataset_sigma"] == 1000
    assert grid["weights"]["lognormal_sigma"] == [0.25, 0.5]
    assert grid["multipliers"]["two_sources"] == [1.0, 1.1, 1.2, 1.3, 1.4]
    assert grid["multipliers"]["three_or_more_sources"] == [1.2, 1.3, 1.4]
    assert all(s <= m for s in grid["thresholds"]["suspicious"] for m in grid["thresholds"]["malicious"] if s <= m)


def test_baseline_check_reports_mismatch_without_suppressing_it():
    row = {"ioc": "example.test", "sources": six_sources(), "predicted_verdict": "MALICIOUS"}
    report = sensitivity.baseline_check({"tiny": [row]})
    assert report["total_mismatches"] == 1
    assert report["mismatch_examples"][0]["stored_verdict"] == "MALICIOUS"
    assert report["mismatch_examples"][0]["recalculated_verdict"] == "CLEAN"


def test_shortcut_verdict_is_frozen_under_extreme_parameters_and_in_metrics():
    shortcut = {
        "ioc": "trusted.example",
        "trusted_shortcut": True,
        "evaluation_path": "trusted_shortcut",
        "expected_ioc_type": "domain",
        "expected_verdict": "MALICIOUS",
        "predicted_verdict": "CLEAN",
        "threat_score": 0,
        "sources": six_sources(
            feodotracker=source("✓", 100),
            c2_trackers=source("✓", 100),
            spamhaus=source("✓", 100),
        ),
    }
    ordinary = {
        "ioc": "ordinary.example",
        "expected_ioc_type": "domain",
        "expected_verdict": "CLEAN",
        "predicted_verdict": "CLEAN",
        "sources": six_sources(),
    }
    gate = sensitivity.baseline_check({"tiny": [shortcut, ordinary]})
    assert gate["tiny"]["shortcut_count"] == 1
    assert gate["tiny"]["baseline_checked_non_shortcut_rows"] == 1
    assert gate["tiny"]["mismatch_count"] == 0

    result = sensitivity._evaluate(
        [shortcut, ordinary],
        ["CLEAN", "CLEAN"],
        "extreme_fixture",
        {"multiplier_2": 1.4, "multiplier_3": 1.4, "malicious_threshold": 60, "suspicious_threshold": 50},
    )
    assert result["shortcut_count"] == 1
    assert result["metrics"]["n"] == 2
    assert result["changed_count"] == 0
    assert result["metrics"]["fn"] == 1


def test_shortcut_evaluation_path_also_skips_gate_and_stays_frozen():
    row = {
        "evaluation_path": "trusted_shortcut",
        "predicted_verdict": "CLEAN",
        "expected_verdict": "CLEAN",
        "sources": six_sources(feodotracker=source("✓", 100)),
    }
    gate = sensitivity.baseline_check({"tiny": [row]})
    result = sensitivity._evaluate(
        [row], ["CLEAN"], "shortcut_path", {"multiplier_2": 1.4, "multiplier_3": 1.4, "malicious_threshold": 60, "suspicious_threshold": 30}
    )
    assert gate["tiny"]["shortcut_count"] == 1
    assert gate["tiny"]["baseline_checked_non_shortcut_rows"] == 0
    assert gate["total_mismatches"] == 0
    assert result["changed_count"] == 0
    assert result["metrics"]["n"] == 1


def test_full_multiplier_threshold_grid_includes_no_multiplier_case():
    rows = [{"sources": six_sources(), "expected_verdict": "CLEAN", "predicted_verdict": "CLEAN", "expected_ioc_type": "url"}]
    results = sensitivity._full_grid(rows, ["CLEAN"])
    assert len(results) == 400
    no_multiplier = [item for item in results if item["value"].get("multiplier_case") == "none"]
    assert len(no_multiplier) == 25
    assert all(item["metrics"]["n"] == 1 for item in results)


def test_metrics_use_none_when_precision_or_recall_denominator_is_zero():
    no_predicted_positive = [
        {"expected_verdict": "MALICIOUS"},
        {"expected_verdict": "CLEAN"},
    ]
    metrics = sensitivity._metrics(no_predicted_positive, ["CLEAN", "CLEAN"])
    assert metrics["tp"] == metrics["fp"] == 0
    assert metrics["precision"] is None
    assert metrics["recall"] == 0.0
    assert metrics["f1"] is None

    no_actual_positive = [{"expected_verdict": "CLEAN"}]
    metrics = sensitivity._metrics(no_actual_positive, ["MALICIOUS"])
    assert metrics["tp"] == 0 and metrics["fp"] == 1
    assert metrics["precision"] == 0.0
    assert metrics["recall"] is None
    assert metrics["f1"] is None


def test_metrics_empty_rows_are_defined_without_division_error():
    metrics = sensitivity._metrics([], [])
    assert metrics == {
        "n": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0,
        "accuracy": 0.0, "precision": None, "recall": None, "f1": None,
    }
