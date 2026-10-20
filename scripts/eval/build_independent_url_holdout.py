#!/usr/bin/env python3
"""Build frozen, reproducible URL holdout inputs without changing IOC strings."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html.parser
import json
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlsplit
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SEED = 20261011
ROUND2_TRANCO_SHA256 = "2AB4810272C7B00E93D1BCC94C00CF64B050BBC188BD5167CD2BC58AB0D2B061"
TRANCO_LIST_ID = "8P4GV"
TRANCO_URL = f"https://tranco-list.eu/list/{TRANCO_LIST_ID}/1000000"
OPENPHISH_URL = "https://openphish.com/feed.txt"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"
USER_AGENT = "SOCPOW-Independent-URL-Holdout/1.0 (research reproducibility)"
DEFAULT_EXCLUSIONS = (
    "data/benchmark/benchmark_iocs_v2.json",
    "data/benchmark/benchmark_iocs_v2_backup.json",
    "data/benchmark/benchmark_iocs_clean_additions_2026-09-22.json",
    "evidence/vt_independent_holdout_2026-09-25/holdout_labeled_221.json",
    "evidence/vt_independent_holdout_2026-09-25/vt_holdout_scoring_input.json",
)
DEFAULT_EXCLUSION_NOTES = {
    "evidence/vt_independent_holdout_2026-09-25/holdout_labeled_221.json":
        "221 labeled rows; verified to contain all 179 + 21 IOC strings in the stored eval result files",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_metadata() -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True,
            text=True, check=True,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True,
            text=True, check=True,
        ).stdout.strip())
        return {"script_git_commit": commit, "script_git_dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"script_git_commit": None, "script_git_dirty": None}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_rows(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value = value.get("records", value.get("iocs", []))
    if not isinstance(value, list):
        raise ValueError(f"expected a JSON list or an object with records: {path}")
    return [row for row in value if isinstance(row, dict)]


def url_host(value: str) -> str | None:
    candidate = value if "://" in value else f"//{value}"
    try:
        return urlsplit(candidate).hostname
    except ValueError:
        return None


def dedup_key(url: str) -> tuple[Any, ...]:
    """Normalize only host case and trailing path slashes; preserve path/query case."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = "invalid-port"
    path = parsed.path.rstrip("/")
    return parsed.scheme, parsed.username, parsed.password, host, port, path, parsed.query, parsed.fragment


def is_eligible_url(url: Any) -> bool:
    if not isinstance(url, str) or not url or len(url.encode("utf-8")) > 2048:
        return False
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        return False
    try:
        parsed = urlsplit(url)
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
    except ValueError:
        return False


def _ioc_value(row: dict[str, Any]) -> str | None:
    value = row.get("ioc")
    if isinstance(value, str):
        return value
    value = row.get("url")
    return value if isinstance(value, str) else None


def load_exclusion_data(paths: Iterable[Path]) -> tuple[set[str], dict[str, set[str]], list[dict[str, Any]]]:
    exact: set[str] = set()
    host_map: dict[str, set[str]] = {}
    audit: list[dict[str, Any]] = []
    for path in paths:
        if not path.exists():
            audit.append({"path": str(path), "exists": False, "row_count": 0})
            continue
        try:
            rows = read_rows(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            audit.append({"path": str(path), "exists": True, "row_count": None, "error": type(exc).__name__})
            continue
        values = []
        for row in rows:
            value = _ioc_value(row)
            if value is None:
                continue
            values.append(value)
            exact.add(value)
            host = url_host(value)
            if host:
                host_map.setdefault(host.lower(), set()).add(str(path))
        audit.append({"path": str(path), "exists": True, "row_count": len(rows), "ioc_count": len(values)})
    return exact, host_map, audit


def raw_snapshot(path: Path, body: bytes, source_url: str, fetched_at: str) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    metadata = {
        "fetched_at_utc": fetched_at,
        "source_url": source_url,
        "sha256": sha256_bytes(body),
        "byte_count": len(body),
    }
    write_json(path.with_suffix(path.suffix + ".metadata.json"), metadata)
    return metadata


def fetch_bytes(url: str, *, timeout: float = 30, user_agent: str = USER_AGENT) -> tuple[bytes, int, dict[str, str]]:
    request = Request(url, headers={"User-Agent": user_agent})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read(), int(response.status), dict(response.headers.items())
    except HTTPError as exc:
        return exc.read(), int(exc.code), dict(exc.headers.items())
    except URLError as exc:
        raise RuntimeError(f"download failed for {url}: {exc.reason}") from exc


def _read_phishtank(body: bytes) -> list[dict[str, Any]]:
    value = json.loads(body.decode("utf-8-sig"))
    if not isinstance(value, list):
        raise ValueError("PhishTank online-valid.json must contain a JSON list")
    return [row for row in value if isinstance(row, dict)]


class LinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value is not None:
                    self.hrefs.append(value)
                    break


def _base_row(ioc: str, source: str, round_name: str, collected_at: str, verdict: str) -> dict[str, Any]:
    return {
        "ioc": ioc,
        "ioc_type": "url",
        "expected_verdict": verdict,
        "source": source,
        "sampling_source": source,
        "label_source": source if verdict == "MALICIOUS" else "pending_virustotal_3tier",
        "collected_at": collected_at,
        "round": round_name,
    }


def _candidate_rows(source: str, body: bytes, fetched_at: str) -> list[dict[str, Any]]:
    if source == "openphish":
        return [{"url": line, "source_row": index} for index, line in enumerate(body.decode("utf-8-sig").splitlines(), 1) if line]
    return _read_phishtank(body)


def _prior_round_sets(paths: list[Path] | Path | None) -> tuple[set[str], set[tuple[Any, ...]], set[str]]:
    if paths is None:
        normalized: list[Path] = []
    elif isinstance(paths, Path):
        normalized = [paths]
    else:
        normalized = paths
    values: set[str] = set()
    keys: set[tuple[Any, ...]] = set()
    hosts: set[str] = set()
    for path in normalized:
        for row in read_rows(path):
            value = _ioc_value(row)
            if not value:
                continue
            values.add(value)
            keys.add(dedup_key(value))
            host = url_host(value)
            if host:
                hosts.add(host.lower())
    return values, keys, hosts


def _round_rows(source: str, candidates: list[dict[str, Any]], target: int, seed: int,
                exclusions: set[str], exclusion_hosts: dict[str, set[str]],
                other_round_path: list[Path] | Path | None, fetched_at: str) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    counts = {"raw": len(candidates), "eligible": 0, "duplicate_within_source": 0,
              "excluded_exact_url": 0, "excluded_host_only": 0,
              "other_round_overlap": 0, "selected": 0, "shortfall": 0}
    dropped: list[dict[str, Any]] = []
    eligible: list[tuple[str, dict[str, Any]]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in candidates:
        value = row.get("url") if source == "openphish" else row.get("url")
        if not isinstance(value, str):
            dropped.append({"ioc": None, "reason": "missing_url"})
            continue
        if not is_eligible_url(value):
            dropped.append({"ioc": value, "reason": "ineligible_url"})
            continue
        key = dedup_key(value)
        if key in seen:
            counts["duplicate_within_source"] += 1
            dropped.append({"ioc": value, "reason": "duplicate_within_source"})
            continue
        seen.add(key)
        counts["eligible"] += 1
        if value in exclusions:
            counts["excluded_exact_url"] += 1
            dropped.append({"ioc": value, "reason": "exclusion_exact_url"})
            continue
        host = url_host(value)
        if host and host.lower() in exclusion_hosts:
            counts["excluded_host_only"] += 1
            dropped.append({"ioc": value, "reason": "exclusion_host_only",
                            "exclusion_files": sorted(exclusion_hosts[host.lower()])})
            continue
        eligible.append((value, row))

    other_iocs, other_keys, other_hosts = _prior_round_sets(other_round_path)
    filtered = []
    for value, row in eligible:
        host = url_host(value)
        if value in other_iocs or dedup_key(value) in other_keys or (host and host.lower() in other_hosts):
            counts["other_round_overlap"] += 1
            dropped.append({"ioc": value, "reason": "other_round_overlap"})
        else:
            filtered.append((value, row))

    filtered.sort(key=lambda pair: pair[0])
    rng = random.Random(seed)
    if source == "tranco":
        selected = filtered
        if len(selected) > target:
            selected = rng.sample(selected, target)
    else:
        selected = rng.sample(filtered, min(target, len(filtered)))
    counts["selected"] = len(selected)
    counts["shortfall"] = max(0, target - len(selected))
    if counts["shortfall"]:
        dropped.append({"reason": "source_shortfall", "target": target,
                        "selected": len(selected), "shortfall": counts["shortfall"]})
    rows = [
        _base_row(value, "OpenPhish" if source == "openphish" else "PhishTank",
                  source, fetched_at, "MALICIOUS")
        for value, _ in selected
    ]
    return rows, counts, dropped


def _tranco_domains(body: bytes) -> tuple[list[tuple[int, str]], dict[str, int]]:
    domains: list[tuple[int, str]] = []
    counts = {"raw_rows": 0, "valid_rows": 0, "in_rank_range": 0, "duplicate_domains": 0}
    seen: set[str] = set()
    text = body.decode("utf-8-sig")
    for row in csv.reader(text.splitlines()):
        counts["raw_rows"] += 1
        if len(row) < 2:
            continue
        try:
            rank = int(row[0])
        except (TypeError, ValueError):
            continue
        domain = row[1]
        if not domain or any(ch.isspace() for ch in domain):
            continue
        counts["valid_rows"] += 1
        if not 1000 <= rank <= 50000:
            continue
        counts["in_rank_range"] += 1
        key = domain.lower().rstrip(".")
        if key in seen:
            counts["duplicate_domains"] += 1
            continue
        seen.add(key)
        domains.append((rank, domain))
    return domains, counts


def _fetch_homepage(domain: str, timeout: float) -> tuple[bytes, str, str, int]:
    homepage_url = f"https://{domain}/"
    body, status, _headers = fetch_bytes(homepage_url, timeout=timeout)
    return body, homepage_url, sha256_bytes(body), status


def sample_tranco_window(domains: list[tuple[int, str]], seed: int, *,
                         domain_offset: int = 0, domain_count: int = 400
                         ) -> tuple[list[tuple[int, str]], int]:
    """Return a zero-based window from the canonical seeded sample order."""
    if domain_offset < 0 or domain_count < 1:
        raise ValueError("domain offset must be non-negative and domain count must be positive")
    sample_end = domain_offset + domain_count
    sampled_prefix = random.Random(seed).sample(domains, min(sample_end, len(domains)))
    return sampled_prefix[domain_offset:sample_end], len(sampled_prefix)


def build_tranco(input_body: bytes, *, out_dir: Path, target: int, seed: int,
                 fetched_at: str, timeout: float, sample_domains: int = 400,
                 exclusions: set[str] | None = None,
                 exclusion_hosts: dict[str, set[str]] | None = None,
                 other_round_path: list[Path] | Path | None = None,
                 domain_offset: int = 0, domain_count: int | None = None) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    domains, stage_counts = _tranco_domains(input_body)
    domains.sort(key=lambda item: item[1])
    requested_count = sample_domains if domain_count is None else domain_count
    # Sample the same prefix as round 1, then select the requested window.
    sampled_domains, sampled_prefix_count = sample_tranco_window(
        domains, seed, domain_offset=domain_offset, domain_count=requested_count
    )
    counts: dict[str, Any] = {**stage_counts, "domains_sampled": len(sampled_domains),
                              "homepages_fetched": 0, "domains_with_internal_links": 0,
                              "candidate_links": 0, "excluded_exact_url": 0,
                              "excluded_host_only": 0, "other_round_overlap": 0,
                              "duplicate_candidate_url": 0, "selected": 0, "shortfall": 0}
    dropped: list[dict[str, Any]] = []
    candidate_links: list[dict[str, Any]] = []
    selected_rows: list[dict[str, Any]] = []
    exclusions = exclusions or set()
    exclusion_hosts = exclusion_hosts or {}
    other_iocs, other_keys, other_hosts = _prior_round_sets(other_round_path)
    seen_candidates: set[tuple[Any, ...]] = set()
    rng_links = random.Random(seed)
    raw_dir = out_dir / ("homepage_raw_round2" if domain_offset else "homepage_raw")
    for index, (rank, domain) in enumerate(sampled_domains):
        home_path = raw_dir / f"{rank:05d}_{hashlib.sha256(domain.encode()).hexdigest()[:12]}.html"
        try:
            html_body, homepage_url, homepage_hash, homepage_status = _fetch_homepage(domain, timeout)
            homepage_meta = raw_snapshot(home_path, html_body, homepage_url, utc_now())
            homepage_meta["http_status"] = homepage_status
            counts["homepages_fetched"] += 1
        except Exception as exc:
            dropped.append({"domain": domain, "rank": rank, "reason": "homepage_fetch_failed",
                            "error": type(exc).__name__})
            continue
        if homepage_status < 200 or homepage_status >= 300:
            dropped.append({"domain": domain, "rank": rank, "reason": "homepage_http_error",
                            "http_status": homepage_status,
                            "homepage_sha256": homepage_meta["sha256"],
                            "raw_file": str(home_path)})
            continue
        parser = LinkParser()
        try:
            parser.feed(html_body.decode("utf-8", errors="replace"))
        except Exception as exc:
            dropped.append({"domain": domain, "rank": rank, "reason": "html_parse_failed",
                            "error": type(exc).__name__, "homepage_sha256": homepage_hash})
            continue
        candidates = []
        domain_lower = domain.lower().rstrip(".")
        for href in parser.hrefs:
            if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in href):
                continue
            resolved = urljoin(homepage_url, href)
            parsed = urlsplit(resolved)
            host = parsed.hostname or ""
            if parsed.scheme.lower() not in {"http", "https"}:
                continue
            if not (host.lower() == domain_lower or host.lower().endswith("." + domain_lower)):
                continue
            if not (parsed.path not in {"", "/"} or parsed.query):
                continue
            # Protocol drops fragments at collection time; preserve the chosen string afterward.
            resolved, _fragment = urldefrag(resolved)
            if not is_eligible_url(resolved):
                continue
            candidates.append(resolved)
        candidates = sorted(set(candidates))
        counts["candidate_links"] += len(candidates)
        for url in candidates:
            candidate_links.append({"domain": domain, "rank": rank, "url": url,
                                    "homepage_sha256": homepage_hash,
                                    "homepage_fetched_at_utc": homepage_meta["fetched_at_utc"]})
        if not candidates:
            dropped.append({"domain": domain, "rank": rank, "reason": "no_internal_deep_link",
                            "homepage_sha256": homepage_hash})
            continue
        counts["domains_with_internal_links"] += 1
        chosen = rng_links.choice(candidates)
        key = dedup_key(chosen)
        if key in seen_candidates:
            counts["duplicate_candidate_url"] += 1
            dropped.append({"ioc": chosen, "domain": domain, "rank": rank,
                            "reason": "duplicate_candidate_url"})
            continue
        seen_candidates.add(key)
        if chosen in exclusions:
            counts["excluded_exact_url"] += 1
            dropped.append({"ioc": chosen, "domain": domain, "rank": rank,
                            "reason": "exclusion_exact_url"})
            continue
        host = url_host(chosen)
        if host and host.lower() in exclusion_hosts:
            counts["excluded_host_only"] += 1
            dropped.append({"ioc": chosen, "domain": domain, "rank": rank,
                            "reason": "exclusion_host_only",
                            "exclusion_files": sorted(exclusion_hosts[host.lower()])})
            continue
        if chosen in other_iocs or key in other_keys or (host and host.lower() in other_hosts):
            counts["other_round_overlap"] += 1
            dropped.append({"ioc": chosen, "domain": domain, "rank": rank,
                            "reason": "other_round_overlap"})
            continue
        row = _base_row(chosen, "Tranco", "tranco", homepage_meta["fetched_at_utc"], "PENDING")
        row["label_source"] = "pending_virustotal_3tier"
        row["domain"] = domain
        row["tranco_rank"] = rank
        row["homepage_sha256"] = homepage_hash
        selected_rows.append(row)
    # Preserve seeded domain order; only the per-domain href list is sorted.
    if len(selected_rows) > target:
        selected_rows = selected_rows[:target]
    counts["selected"] = len(selected_rows)
    counts["shortfall"] = max(0, target - len(selected_rows))
    if counts["shortfall"]:
        dropped.append({"reason": "candidate_shortfall", "target": target,
                        "selected": len(selected_rows), "shortfall": counts["shortfall"]})
    return selected_rows, {"counts": counts, "candidate_links": candidate_links,
                           "sampled_domains": [{"rank": rank, "domain": domain} for rank, domain in sampled_domains],
                           "sampling_window": {"seed": seed, "domain_offset_zero_based": domain_offset,
                                               "first_position_one_based": domain_offset + 1,
                                               "last_position_one_based": domain_offset + len(sampled_domains),
                                               "requested_domain_count": requested_count,
                                               "sampled_prefix_count": sampled_prefix_count}}, dropped


def build(source: str, out_dir: Path, target: int, seed: int, input_file: Path | None,
          exclusion_files: list[Path], other_round: list[Path] | Path | None, timeout: float,
          sample_domains: int = 400, domain_offset: int = 0,
          domain_count: int | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    exclusions, exclusion_hosts, exclusion_audit = load_exclusion_data(exclusion_files)
    if source == "tranco":
        source_url = f"file:{input_file}" if input_file else TRANCO_URL
        if input_file:
            raw_body = input_file.read_bytes()
            if domain_offset:
                actual_sha256 = sha256_bytes(raw_body).upper()
                if actual_sha256 != ROUND2_TRANCO_SHA256:
                    raise ValueError("round 2 requires the frozen Tranco 8P4GV CSV with SHA-256 "
                                     f"{ROUND2_TRANCO_SHA256}; got {actual_sha256}")
        else:
            raw_body, status, _headers = fetch_bytes(source_url, timeout=timeout)
            if status < 200 or status >= 300:
                fetched_at = utc_now()
                raw_snapshot(out_dir / "tranco_full_list.raw.csv", raw_body, source_url, fetched_at)
                raise RuntimeError(f"Tranco download returned HTTP {status}; no fallback was attempted")
        fetched_at = utc_now()
        is_round2 = domain_offset > 0
        raw_path = out_dir / ("tranco_full_list_round2.raw.csv" if is_round2 else "tranco_full_list.raw.csv")
        dataset_name = "clean_candidates_tranco_round2.json" if is_round2 else "clean_candidates_tranco.json"
        manifest_name = "build_tranco_round2_manifest.json" if is_round2 else "build_tranco_manifest.json"
        if is_round2:
            protected_outputs = [raw_path, out_dir / dataset_name, out_dir / manifest_name]
            existing = [str(path) for path in protected_outputs if path.exists()]
            if existing:
                raise FileExistsError("refusing to overwrite round 2 outputs: " + ", ".join(existing))
        source_meta = raw_snapshot(raw_path, raw_body, source_url, fetched_at)
        rows, stages, dropped = build_tranco(raw_body, out_dir=out_dir, target=target,
                                             seed=seed, fetched_at=fetched_at,
                                             timeout=timeout, sample_domains=sample_domains,
                                             exclusions=exclusions, exclusion_hosts=exclusion_hosts,
                                             other_round_path=other_round,
                                             domain_offset=domain_offset, domain_count=domain_count)
        counts = stages["counts"]
    else:
        source_url = OPENPHISH_URL if source == "openphish" else PHISHTANK_URL
        if input_file:
            raw_body = input_file.read_bytes()
            source_url = f"file:{input_file}"
            status = 200
        else:
            raw_body, status, _headers = fetch_bytes(source_url, timeout=timeout)
        fetched_at = utc_now()
        raw_path = out_dir / f"{source}_source.raw"
        source_meta = raw_snapshot(raw_path, raw_body, source_url, fetched_at)
        if status == 429 or status < 200 or status >= 300:
            raise RuntimeError(f"{source} download returned HTTP {status}; use --input-file for an explicit local fallback")
        candidates = _candidate_rows(source, raw_body, fetched_at)
        if source == "phishtank":
            verified = [row for row in candidates if str(row.get("verified", "")).lower() == "yes"]
            online = [row for row in verified if str(row.get("online", "")).lower() == "yes"]
            candidates = [{"url": row.get("url"), "source_row": row} for row in online]
            eligibility_counts = {"raw_rows": len(_read_phishtank(raw_body)),
                                  "verified_yes": len(verified), "online_yes": len(online)}
        else:
            eligibility_counts = {"raw_rows": len(candidates)}
        rows, counts, dropped = _round_rows(
            source, candidates, target, seed, exclusions, exclusion_hosts,
            other_round, fetched_at,
        )
        counts.update(eligibility_counts)
        stages = {"counts": counts}
    dataset_path = out_dir / (dataset_name if source == "tranco" else f"malicious_{source}.json")
    write_json(dataset_path, rows)
    manifest_path = out_dir / (manifest_name if source == "tranco" else f"build_{source}_manifest.json")
    manifest = {
        "script": Path(__file__).name,
        "source": source,
        "source_url": source_url,
        "fetched_at_utc": fetched_at,
        "raw_snapshot": {"path": str(raw_path.relative_to(out_dir)), **source_meta},
        "seed": seed,
        "target": target,
        "domain_offset_zero_based": domain_offset if source == "tranco" else None,
        "domain_count": (domain_count if domain_count is not None else sample_domains) if source == "tranco" else None,
        "counts_by_stage": stages,
        "exclusion_files": exclusion_audit,
        "warnings": [
            f"exclusion file missing: {item['path']}"
            for item in exclusion_audit if not item.get("exists")
        ],
        "exclusion_notes": DEFAULT_EXCLUSION_NOTES,
        "dedup_against_round": [str(path) for path in other_round] if isinstance(other_round, list) else str(other_round) if other_round else None,
        "output_file": str(dataset_path.relative_to(out_dir)),
        "output_sha256": sha256_bytes(dataset_path.read_bytes()),
        "dropped_items": dropped,
        **git_metadata(),
    }
    if source == "tranco":
        manifest["tranco_sampling"] = stages
    write_json(manifest_path, manifest)
    return dataset_path, manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("openphish", "phishtank", "tranco"), required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--target", type=int)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--input-file", type=Path)
    parser.add_argument("--exclusion-files", nargs="*", type=Path)
    parser.add_argument("--dedup-against-round", nargs="+", type=Path)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--sample-domains", type=int, default=400)
    parser.add_argument("--domain-offset", type=int, default=0,
                        help="zero-based position in the same seeded Tranco sample; nonzero selects a later window")
    parser.add_argument("--domain-count", type=int,
                        help="number of sampled Tranco domains in the requested window")
    args = parser.parse_args()
    target = args.target if args.target is not None else (300 if args.source == "tranco" else 100)
    if target < 1:
        parser.error("--target must be at least 1")
    if args.domain_offset and (args.source != "tranco" or not args.input_file):
        parser.error("a nonzero --domain-offset requires --source tranco and the frozen local --input-file")
    exclusion_files = args.exclusion_files
    if exclusion_files is None:
        exclusion_files = [REPO_ROOT / path for path in DEFAULT_EXCLUSIONS]
    else:
        exclusion_files = [path if path.is_absolute() else REPO_ROOT / path for path in exclusion_files]
    other_round = args.dedup_against_round
    if other_round:
        other_round = [path if path.is_absolute() else REPO_ROOT / path for path in other_round]
    try:
        dataset, manifest = build(
            args.source, args.out_dir, target, args.seed, args.input_file,
            exclusion_files, other_round, args.timeout,
            args.sample_domains, args.domain_offset, args.domain_count,
        )
    except Exception as exc:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        failure_name = ("build_tranco_round2_manifest.json" if args.source == "tranco" and args.domain_offset
                        else f"build_{args.source}_manifest.json")
        failure_path = args.out_dir / failure_name
        if not failure_path.exists():
            write_json(failure_path, {
                "script": Path(__file__).name, "source": args.source, "seed": args.seed,
                "target": args.target if args.target is not None else (300 if args.source == "tranco" else 100),
                "counts_by_stage": {},
                "dropped_items": [{"reason": "run_failed", "error": type(exc).__name__}],
                **git_metadata(),
            })
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"Wrote {dataset} and {manifest}")


if __name__ == "__main__":
    main()
