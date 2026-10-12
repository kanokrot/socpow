import json
import random
from pathlib import Path

import pytest

from scripts.eval import build_independent_url_holdout as builder
from scripts.eval import combine_clean_url_rounds as clean_round_combiner
from scripts.eval import combine_independent_url_holdout as combiner
from scripts.eval import compute_holdout_metrics as metrics
from scripts.eval import label_clean_urls_vt as vt_labeler
from scripts.eval import measure_url_overlap as overlap


def test_wilson_reference_values_and_edges():
    low, high = metrics.wilson_interval(91, 200)
    assert low == pytest.approx(0.38748, abs=5e-5)
    assert high == pytest.approx(0.52421, abs=5e-5)
    low, high = metrics.wilson_interval(6, 20)
    assert low == pytest.approx(0.14548, abs=5e-5)
    assert high == pytest.approx(0.51897, abs=5e-5)
    assert metrics.wilson_interval(0, 20) == pytest.approx((0, 0.16113), abs=5e-5)
    assert metrics.wilson_interval(20, 20) == pytest.approx((0.83887, 1), abs=5e-5)
    assert metrics.wilson_interval(0, 0) == (None, None)


def test_url_dedup_key_preserves_url_components_and_normalizes_only_host_slash():
    first = "HTTP://ExAmPle.com:8080/PaTh/%2f?Q=AbC"
    trailing_slash = "HTTP://example.COM:8080/PaTh/%2f/?Q=AbC"
    assert builder.dedup_key(first) == builder.dedup_key(trailing_slash)
    assert builder.dedup_key(first) != builder.dedup_key(first.replace("PaTh", "path"))
    assert builder.dedup_key(first) != builder.dedup_key(first.replace("Q=AbC", "q=AbC"))
    assert builder.dedup_key(first) != builder.dedup_key(first.replace(":8080", ":8081"))


@pytest.mark.parametrize("url", [
    "https://ExAmPle.com:8443/MiXeD/%2fPath?Token=AbC",
    "http://example.com:8080/a%2Fb?Case=Yes",
])
def test_output_ioc_is_original_url_byte_for_byte(url):
    row = builder._base_row(url, "OpenPhish", "openphish", "2026-10-11T00:00:00Z", "MALICIOUS")
    assert row["ioc"] == url
    assert row["ioc"].encode("utf-8") == url.encode("utf-8")


def test_url_eligibility():
    assert builder.is_eligible_url("https://Example.com:8443/PATH?q=A")
    assert builder.is_eligible_url("http://example.org/")
    assert not builder.is_eligible_url("ftp://example.org/file")
    assert not builder.is_eligible_url("https://example.org/a b")
    assert not builder.is_eligible_url("https://example.org/\x7f")
    assert not builder.is_eligible_url("https://example.org/" + "a" * 2049)


def test_seeded_sampling_is_deterministic_and_input_order_independent():
    values = [f"https://site{i:02d}.example/path" for i in range(20)]

    def sample(urls, seed):
        candidates = [{"url": url} for url in urls]
        rows, _, _ = builder._round_rows(
            "openphish", candidates, 8, seed, set(), {}, None,
            "2026-10-11T00:00:00Z",
        )
        return [row["ioc"] for row in rows]

    assert sample(values, 20261011) == sample(list(reversed(values)), 20261011)
    assert sample(values, 20261011) == sample(values, 20261011)
    assert sample(values, 20261011) != sample(values, 7)


def test_exact_and_host_exclusion_counts_are_separate():
    candidates = [
        {"url": "https://exact.example/path"},
        {"url": "https://host.example/new"},
        {"url": "https://clear.example/path"},
    ]
    rows, counts, dropped = builder._round_rows(
        "openphish", candidates, 10, 20261011,
        {"https://exact.example/path"}, {"host.example": {"exclusion.json"}},
        None, "2026-10-11T00:00:00Z",
    )
    assert [row["ioc"] for row in rows] == ["https://clear.example/path"]
    assert counts["excluded_exact_url"] == 1
    assert counts["excluded_host_only"] == 1
    assert {row["reason"] for row in dropped} >= {"exclusion_exact_url", "exclusion_host_only"}


def test_no_cross_source_backfill_and_source_shortfall(tmp_path):
    original = "https://OnlyOne.example/MiXeD/%2f?q=AbC:8443"
    input_file = tmp_path / "openphish.txt"
    input_file.write_bytes((original + "\n").encode("utf-8"))
    out_dir = tmp_path / "evidence"
    dataset, manifest_path = builder.build(
        "openphish", out_dir, 2, 20261011, input_file, [], None, 2,
    )
    rows = json.loads(dataset.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(rows) == 1
    assert rows[0]["ioc"] == original
    assert rows[0]["expected_verdict"] == "MALICIOUS"
    assert manifest["counts_by_stage"]["counts"]["shortfall"] == 1
    assert manifest["counts_by_stage"]["counts"]["selected"] == 1
    assert manifest["raw_snapshot"]["sha256"] == builder.sha256_bytes(input_file.read_bytes())


def test_builder_records_missing_exclusion_as_warning(tmp_path):
    input_file = tmp_path / "openphish.txt"
    input_file.write_text("https://keep.example/path\n", encoding="utf-8")
    missing = tmp_path / "missing-exclusion.json"
    _dataset, manifest_path = builder.build(
        "openphish", tmp_path / "out", 1, 20261011, input_file, [missing], None, 1,
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["exclusion_files"] == [{"path": str(missing), "exists": False, "row_count": 0}]
    assert manifest["warnings"] == [f"exclusion file missing: {missing}"]


def test_combiner_refuses_unfinalized_rows_and_duplicates(tmp_path):
    row = {
        "ioc": "https://sample.example/MiXeD?Q=AbC", "ioc_type": "url",
        "expected_verdict": "MALICIOUS", "source": "OpenPhish",
        "sampling_source": "openphish", "label_source": "openphish",
        "collected_at": "2026-10-11T00:00:00Z", "round": "openphish",
    }
    files = {}
    for name in combiner.INPUT_ORDER:
        path = tmp_path / f"{name}.json"
        value = [dict(row)]
        if name == "clean":
            value[0].update(expected_verdict="PENDING", label_source="pending_virustotal_3tier")
        elif name == "phishtank":
            value[0].update(round="phishtank", sampling_source="phishtank",
                            source="PhishTank", label_source="phishtank")
        path.write_text(json.dumps(value), encoding="utf-8")
        files[name] = path
    with pytest.raises(ValueError, match="refusing combined output"):
        combiner.combine(files, tmp_path / "out")
    assert not (tmp_path / "out" / "combined_holdout.json").exists()

    clean = json.loads(files["clean"].read_text(encoding="utf-8"))
    clean[0].update(expected_verdict="CLEAN", label_source="virustotal_3tier", vt_label="CLEAN")
    files["clean"].write_text(json.dumps(clean), encoding="utf-8")
    with pytest.raises(ValueError, match="refusing combined output"):
        combiner.combine(files, tmp_path / "out")


def test_combiner_preserves_order_and_hashes_inputs_and_output(tmp_path):
    inputs = {}
    rows = {}
    for name in combiner.INPUT_ORDER:
        label = "CLEAN" if name == "clean" else "MALICIOUS"
        row = {
            "ioc": f"https://{name}.example/MiXeD/%2f?Q=AbC", "ioc_type": "url",
            "expected_verdict": label, "source": name, "sampling_source": name,
            "label_source": "virustotal_3tier" if name == "clean" else name,
            "collected_at": "2026-10-11T00:00:00Z", "round": name,
        }
        if name == "clean":
            row["vt_label"] = "CLEAN"
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps([row], ensure_ascii=False), encoding="utf-8")
        inputs[name] = path
        rows[name] = row
    output, manifest_path = combiner.combine(inputs, tmp_path / "out")
    combined = json.loads(output.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert [row["ioc"] for row in combined] == [rows[name]["ioc"] for name in combiner.INPUT_ORDER]
    assert all(combined[index] == rows[name] for index, name in enumerate(combiner.INPUT_ORDER))
    assert manifest["output"]["sha256"] == builder.sha256_bytes(output.read_bytes())
    assert all(manifest["inputs"][name]["sha256"] == builder.sha256_bytes(path.read_bytes())
               for name, path in inputs.items())


def test_phishtank_requires_verified_and_online_yes(tmp_path):
    records = [
        {"url": "https://keep.example/MiXeD?q=AbC", "verified": "yes", "online": "yes"},
        {"url": "https://offline.example/x", "verified": "yes", "online": "no"},
        {"url": "https://unverified.example/x", "verified": "no", "online": "yes"},
    ]
    input_file = tmp_path / "phishtank.json"
    input_file.write_text(json.dumps(records), encoding="utf-8")
    dataset, manifest_path = builder.build(
        "phishtank", tmp_path / "phish-evidence", 3, 20261011,
        input_file, [], None, 2,
    )
    rows = json.loads(dataset.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert [row["ioc"] for row in rows] == [records[0]["url"]]
    assert manifest["counts_by_stage"]["counts"]["verified_yes"] == 2
    assert manifest["counts_by_stage"]["counts"]["online_yes"] == 1


def test_tranco_deep_url_selection_uses_local_fixture_only(tmp_path, monkeypatch):
    html = (b'<a href="/LogIn/%2f?Token=AbC#remove">deep</a>'
            b'<a href="/">home</a>'
            b'<a href="https://outside.example/path">external</a>'
            b'<a href="https://sub.example.com/Page?Q=MiX">subdomain</a>')
    monkeypatch.setattr(
        builder, "_fetch_homepage",
        lambda domain, timeout: (html, f"https://{domain}/", builder.sha256_bytes(html), 200),
    )
    rows, manifest, dropped = builder.build_tranco(
        b"1000,example.com\n", out_dir=tmp_path, target=1, seed=20261011,
        fetched_at="2026-10-11T00:00:00Z", timeout=1, sample_domains=1,
    )
    candidate_urls = [item["url"] for item in manifest["candidate_links"]]
    assert "https://example.com/LogIn/%2f?Token=AbC" in candidate_urls
    assert "https://sub.example.com/Page?Q=MiX" in candidate_urls
    assert all("#" not in url for url in candidate_urls)
    assert rows[0]["ioc"] in candidate_urls
    assert rows[0]["expected_verdict"] == "PENDING"
    assert dropped == []


def test_tranco_non_2xx_homepage_response_is_snapshotted_before_drop(tmp_path, monkeypatch):
    body = b"fixture unavailable response body"
    monkeypatch.setattr(builder, "_fetch_homepage", lambda domain, timeout: (
        body, f"https://{domain}/", builder.sha256_bytes(body), 503
    ))
    rows, manifest, dropped = builder.build_tranco(
        b"1000,example.com\n", out_dir=tmp_path, target=1, seed=20261011,
        fetched_at="2026-10-11T00:00:00Z", timeout=1, sample_domains=1,
    )
    raw_path = tmp_path / "homepage_raw" / next((tmp_path / "homepage_raw").iterdir()).name
    assert raw_path.read_bytes() == body
    assert rows == []
    assert dropped[0]["reason"] == "homepage_http_error"
    assert manifest["counts"]["shortfall"] == 1


def test_tranco_round2_window_matches_frozen_first_round_and_is_disjoint():
    evidence = builder.REPO_ROOT / "evidence" / "independent_url_holdout_2026-10-11"
    csv_path = evidence / "tranco_8P4GV.csv"
    manifest_path = evidence / "build_tranco_manifest.json"
    candidates_path = evidence / "clean_candidates_tranco.json"
    assert builder.sha256_bytes(csv_path.read_bytes()).upper() == builder.ROUND2_TRANCO_SHA256
    domains, _ = builder._tranco_domains(csv_path.read_bytes())
    domains.sort(key=lambda item: item[1])
    first_window, _ = builder.sample_tranco_window(domains, 20261011, domain_offset=0, domain_count=400)
    second_window, _ = builder.sample_tranco_window(domains, 20261011, domain_offset=400, domain_count=400)
    frozen = json.loads(manifest_path.read_text(encoding="utf-8"))
    first_400 = frozen["tranco_sampling"]["sampled_domains"]
    assert first_window == [(row["rank"], row["domain"]) for row in first_400]
    assert len(second_window) == 400
    assert not ({domain for _rank, domain in first_window} &
                {domain for _rank, domain in second_window})
    # The stored first-round candidates remain the frozen output; round two starts
    # after the same 400-domain sample prefix and cannot rewrite that file.
    old_candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    assert len(old_candidates) == 170
    sampled_domain_order = {domain: position for position, (_rank, domain) in enumerate(first_window)}
    candidate_positions = [sampled_domain_order[row["domain"]] for row in old_candidates]
    assert candidate_positions == sorted(candidate_positions)
    assert all(row["domain"] in sampled_domain_order for row in old_candidates)
    old_bytes = candidates_path.read_bytes()
    assert candidates_path.read_bytes() == old_bytes


def test_tranco_round2_build_uses_separate_names_and_preserves_round1(tmp_path, monkeypatch):
    domains = [(1000 + index, f"site{index:03d}.example") for index in range(10)]
    csv_body = "".join(f"{rank},{domain}\n" for rank, domain in domains).encode()
    input_file = tmp_path / "tranco.csv"
    input_file.write_bytes(csv_body)
    monkeypatch.setattr(builder, "ROUND2_TRANCO_SHA256", builder.sha256_bytes(csv_body).upper())
    html = b'<a href="/deep/path?Q=AbC">deep</a>'
    monkeypatch.setattr(builder, "_fetch_homepage", lambda domain, timeout: (
        html, f"https://{domain}/", builder.sha256_bytes(html), 200
    ))
    first_path, first_manifest = builder.build(
        "tranco", tmp_path / "rounds", 4, 20261011, input_file, [], None, 1,
        domain_count=4,
    )
    first_bytes = first_path.read_bytes()
    first_manifest_bytes = first_manifest.read_bytes()
    second_path, second_manifest = builder.build(
        "tranco", tmp_path / "rounds", 4, 20261011, input_file, [], None, 1,
        domain_offset=4, domain_count=4,
    )
    assert first_path.name == "clean_candidates_tranco.json"
    assert second_path.name == "clean_candidates_tranco_round2.json"
    assert second_manifest.name == "build_tranco_round2_manifest.json"
    assert first_path.read_bytes() == first_bytes
    assert first_manifest.read_bytes() == first_manifest_bytes
    first_rows = json.loads(first_bytes)
    second_rows = json.loads(second_path.read_text(encoding="utf-8"))
    assert not ({row["domain"] for row in first_rows} & {row["domain"] for row in second_rows})
    assert json.loads(second_manifest.read_text(encoding="utf-8"))["tranco_sampling"]["sampling_window"]["first_position_one_based"] == 5


def test_tranco_round2_refuses_wrong_frozen_csv_hash(tmp_path, monkeypatch):
    csv_body = b"1000,site.example\n"
    input_file = tmp_path / "tranco.csv"
    input_file.write_bytes(csv_body)
    monkeypatch.setattr(builder, "ROUND2_TRANCO_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="requires the frozen Tranco 8P4GV CSV"):
        builder.build(
            "tranco", tmp_path / "out", 1, 20261011, input_file, [], None, 1,
            domain_offset=400, domain_count=400,
        )
    assert not (tmp_path / "out" / "clean_candidates_tranco_round2.json").exists()


def test_clean_round_combiner_preserves_round_counts_and_refuses_duplicates(tmp_path):
    paths = []
    manifests = []
    for round_name, ioc in (("round1", "https://one.example/a"),
                            ("round2", "https://two.example/b")):
        row = {"ioc": ioc, "ioc_type": "url", "expected_verdict": "CLEAN",
               "vt_label": "CLEAN", "sampling_source": "tranco",
               "label_source": "virustotal_3tier", "round": round_name,
               "collected_at": "2026-10-12T00:00:00Z"}
        data_path = tmp_path / f"{round_name}.json"
        manifest_path = tmp_path / f"{round_name}_manifest.json"
        data_path.write_text(json.dumps([row]), encoding="utf-8")
        manifest_path.write_text(json.dumps({"counts_by_stage": {"CLEAN": 1}}), encoding="utf-8")
        paths.append(data_path)
        manifests.append(manifest_path)
    output, manifest_path = clean_round_combiner.combine_clean_rounds(
        paths[0], manifests[0], paths[1], manifests[1], tmp_path / "final"
    )
    assert [row["round"] for row in json.loads(output.read_text(encoding="utf-8"))] == ["round1", "round2"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["counts_by_round"]["round1"]["counts_by_stage"] == {"CLEAN": 1}
    assert manifest["counts_by_round"]["round2"]["clean_rows"] == 1
    duplicate_rows = json.loads(paths[0].read_text(encoding="utf-8"))
    paths[1].write_text(json.dumps(duplicate_rows), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate clean IOC across rounds"):
        clean_round_combiner.combine_clean_rounds(
            paths[0], manifests[0], paths[1], manifests[1], tmp_path / "duplicate_final"
        )


def test_vt_three_tier_excludes_named_engines_and_404_is_no_report():
    engines = {
        "MalwareURL": {"category": "malicious"},
        "Hunt.io Intelligence": {"category": "malicious"},
        "Criminal IP": {"category": "malicious"},
        "EngineA": {"category": "malicious"},
        "EngineB": {"category": "malicious"},
    }
    payload = {"data": {"attributes": {"last_analysis_results": engines}}}
    label, count, reason = vt_labeler.label_report(payload, 200)
    assert label == "AMBIGUOUS"
    assert count == 2
    assert reason is None
    assert vt_labeler.label_report({}, 404) == ("NO_REPORT", None, "http_404")
    assert vt_labeler.label_report({"data": {"attributes": {}}}, 200) == (
        "NO_REPORT", None, "missing_last_analysis_results"
    )


def test_vt_labeler_resumes_raw_json_without_network(tmp_path, monkeypatch):
    ioc = "https://MiXeD.example:9443/Login/%2f?User=AbC"
    candidates = tmp_path / "candidates.json"
    candidates.write_text(json.dumps([{"ioc": ioc, "source": "Tranco", "round": "tranco"}]), encoding="utf-8")
    out_dir = tmp_path / "vt"
    raw_dir = out_dir / "virustotal_raw"
    raw_dir.mkdir(parents=True)
    raw_path = raw_dir / (vt_labeler.hashlib.sha256(ioc.encode()).hexdigest() + ".json")
    body = json.dumps({"data": {"attributes": {"last_analysis_results": {}}}}).encode()
    raw_path.write_bytes(body)
    metadata = {"http_status": 404, "fetched_at_utc": "2026-10-11T00:00:00Z"}
    (raw_dir / (raw_path.stem + ".metadata.json")).write_text(json.dumps(metadata), encoding="utf-8")
    monkeypatch.setattr(vt_labeler, "_request_report", lambda *args, **kwargs: pytest.fail("network must not run"))
    output, manifest_path = vt_labeler.label_candidates(candidates, out_dir, api_key="fixture-key", delay=0)
    assert json.loads(output.read_text(encoding="utf-8")) == []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["counts_by_stage"]["resumed"] == 1
    assert manifest["counts_by_stage"]["NO_REPORT"] == 1


def test_threatfox_response_errors_are_not_misses():
    assert overlap.threatfox_status(b'{"query_status":"no_result"}', 200) == ("miss", [])
    assert overlap.threatfox_status(b'{"query_status":"no_result"}', 429) == ("error", [])
    assert overlap.threatfox_status(b'{"query_status":"ok","data":[]}', 200) == ("error", [])
    assert metrics._overlap_flags({
        "c2": {"status": "partial", "exact_url_match": False, "host_level_match": False},
        "threatfox": {"exact_url": {"status": "error", "hit": False},
                      "host": {"status": "error", "hit": False}},
    }) == {"exact": None, "host": None, "any": None}


def test_c2_matcher_is_case_insensitive_literal_substring():
    feeds = {"feed": {"status": "ok", "text": "prefix HTTPS://EXAMPLE.COM/Path?Q=AbC suffix"}}
    result = overlap._c2_flags("https://example.com/Path?Q=AbC", feeds)
    assert result["exact_url_match"] is True
    assert result["host_level_match"] is True
    assert result["matcher"] == "case-insensitive literal substring over raw frozen feed text"


def test_metrics_treat_suspicious_and_unknown_as_negative(tmp_path):
    eval_rows = [
        {"ioc": "https://m1.example/x", "expected_verdict": "MALICIOUS", "predicted_verdict": "MALICIOUS",
         "sources": {"threatfox": {"unavailable": False}}},
        {"ioc": "https://m2.example/x", "expected_verdict": "MALICIOUS", "predicted_verdict": "UNKNOWN",
         "sources": {"threatfox": {"unavailable": True}}},
        {"ioc": "https://c1.example/x", "expected_verdict": "CLEAN", "predicted_verdict": "MALICIOUS",
         "sources": {"c2_trackers": {"unavailable": False}}},
        {"ioc": "https://c2.example/x", "expected_verdict": "CLEAN", "predicted_verdict": "SUSPICIOUS",
         "sources": {"threatfox": {"unavailable": False}}},
    ]
    result = metrics.confusion_metrics(eval_rows)
    assert result["confusion_matrix"] == {"TP": 1, "FP": 1, "TN": 1, "FN": 1}
    assert result["precision"] == pytest.approx(0.5)
    assert result["recall"] == pytest.approx(0.5)
    assert result["f1"] == pytest.approx(0.5)
    assert result["predicted_3class_counts"] == {"MALICIOUS": 2, "UNKNOWN": 1, "SUSPICIOUS": 1}
    assert result["rows_with_any_source_unavailable"] == 1

    results_path = tmp_path / "eval.jsonl"
    results_path.write_text("\n".join(json.dumps(row) for row in eval_rows) + "\n", encoding="utf-8")
    overlap_path = tmp_path / "flags.json"
    flags = []
    for row in eval_rows:
        flags.append({"ioc": row["ioc"], "round": "openphish", "c2": {
            "status": "ok",
            "exact_url_match": False, "host_level_match": False}, "threatfox": {
            "exact_url": {"status": "miss", "hit": False},
            "host": {"status": "miss", "hit": False}}})
    overlap_path.write_text(json.dumps(flags), encoding="utf-8")
    output, _manifest = metrics.compute(results_path, overlap_path, tmp_path / "metrics.json")
    rendered = json.loads(output.read_text(encoding="utf-8"))
    assert rendered["metrics"]["overall"]["confusion_matrix"]["TN"] == 1
    assert rendered["malicious_overlap_coverage"]["either"]["trials"] == 2
    assert rendered["non_overlap_note"] == metrics.NON_OVERLAP_NOTE
