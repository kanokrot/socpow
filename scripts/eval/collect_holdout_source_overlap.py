#!/usr/bin/env python3
"""Collect target-source overlap for a frozen public-data holdout.

The frozen manifest is never modified.  This runner writes a separate result
artifact and preserves fetched source responses under ``--raw-dir``.  It does
not use SOCPOW's IOC cache and it does not use any target-source response as a
label.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import aiohttp
import certifi

REPO_ROOT = Path(__file__).resolve().parents[2]
TARGET_SOURCES = ("feodotracker", "tor_exit_nodes", "sslblacklist", "usom", "spamhaus", "c2_trackers")
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
TOR_URL = "https://check.torproject.org/torbulkexitlist"
SSLBL_CERT_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
SSLBL_IP_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
USOM_URL = "https://siberguvenlik.gov.tr/api/address/index"
C2_URLS = {
    "montysecurity_combined": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/combined.csv",
    "drb_ra_30day": "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
    "jmousqueton": "https://raw.githubusercontent.com/jmousqueton/C2-Tracker/main/c2-tracker.csv",
    "stamparm_maltrail": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/c2.txt",
    "c2_all_ips": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/ips/all.txt",
    "c2_cobalt_strike": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Cobalt%20Strike.csv",
    "c2_metasploit": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Metasploit.csv",
    "c2_sliver": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver.csv",
    "c2_brute_ratel": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Brute%20Ratel%20C4.csv",
    "c2_havoc": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Havoc.csv",
}
SSL_CONTEXT = __import__("ssl").create_default_context(cafile=certifi.where())


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def applicable(ioc_type: str, source: str) -> bool:
    if ioc_type == "ip":
        return source in TARGET_SOURCES
    if ioc_type == "domain":
        return source in {"usom", "c2_trackers"}
    if ioc_type == "sha1":
        return source == "sslblacklist"
    return False


def load_manifest(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    artifact = json.loads(raw.decode("utf-8"))
    if artifact.get("status") != "ready_for_overlap_checks":
        raise ValueError(f"manifest status is not ready_for_overlap_checks: {artifact.get('status')}")
    records = artifact.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("frozen manifest must contain a non-empty records list")
    for record in records:
        if record.get("target_source_overlap_status") != "pending_source_calls":
            raise ValueError(f"record {record.get('record_id')} is already annotated")
        if any(value is not None for value in record.get("target_source_overlap", {}).values()):
            raise ValueError(f"record {record.get('record_id')} has non-null overlap fields")
    return artifact, sha256_bytes(raw)


async def fetch_bytes(session: aiohttp.ClientSession, url: str, timeout: int = 30) -> tuple[int, bytes | None, str | None]:
    try:
        async with session.get(url, timeout=timeout) as response:
            body = await response.read()
            if response.status != 200:
                return response.status, body, f"HTTP {response.status}"
            return response.status, body, None
    except Exception as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def write_raw(raw_dir: Path, filename: str, body: bytes) -> dict:
    path = raw_dir / filename
    path.write_bytes(body)
    return {"path": str(path.relative_to(REPO_ROOT)), "bytes": len(body), "sha256": sha256_bytes(body)}


def parse_feodo(body: bytes) -> dict[str, dict]:
    data = json.loads(body.decode("utf-8"))
    rows = data if isinstance(data, list) else data.get("data", [])
    result = {}
    for row in rows:
        if isinstance(row, dict) and is_ipv4(norm(row.get("ip_address"))):
            result[norm(row["ip_address"])] = row
    return result


def parse_tor(body: bytes) -> set[str]:
    return {norm(line) for line in body.decode("utf-8", errors="replace").splitlines() if is_ipv4(norm(line))}


def parse_sslbl(body: bytes) -> tuple[set[str], set[str], bool]:
    sha1s: set[str] = set()
    ips: set[str] = set()
    text = body.decode("utf-8", errors="replace")
    deprecated = "deprecated" in text.lower()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{40}", parts[1]):
            sha1s.add(parts[1].lower())
        for part in parts[:2]:
            if is_ipv4(part):
                ips.add(part)
    return sha1s, ips, deprecated


def spamhaus_lookup(ip: str, timeout: float = 3.0) -> dict:
    query = ".".join(reversed(ip.split("."))) + ".zen.spamhaus.org"
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        answer = socket.gethostbyname_ex(query)
        return {"status": "found", "found": True, "query": query, "answer": answer[2]}
    except socket.gaierror:
        return {"status": "not_found", "found": False, "query": query}
    except OSError as exc:
        return {"status": "error", "found": False, "query": query, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        socket.setdefaulttimeout(old_timeout)


def exact_line_match(ioc: str, text: str) -> bool:
    escaped = re.escape(ioc)
    return any(re.search(rf"(?<![A-Za-z0-9_.:-]){escaped}(?![A-Za-z0-9_.:-])", line, re.IGNORECASE) for line in text.splitlines())


async def collect(args: argparse.Namespace) -> dict:
    manifest, manifest_sha256 = load_manifest(args.manifest)
    records = manifest["records"]
    args.raw_dir.mkdir(parents=True, exist_ok=True)
    connector = aiohttp.TCPConnector(ssl=SSL_CONTEXT, limit=20)
    timeout = aiohttp.ClientTimeout(total=30)
    raw_sources: dict[str, dict] = {}
    static_data: dict[str, object] = {}
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers={"User-Agent": "socpow-independent-holdout/1.0"}) as session:
        static_urls = {
            "feodotracker": FEODO_URL,
            "tor_exit_nodes": TOR_URL,
            "sslblacklist_cert": SSLBL_CERT_URL,
            "sslblacklist_ip": SSLBL_IP_URL,
        }
        async def fetch_snapshot(name: str, url: str, request_timeout: int) -> tuple[str, dict, bytes | None]:
            status, body, error = await fetch_bytes(session, url, timeout=request_timeout)
            item = {"url": url, "http_status": status, "error": error}
            if body is not None:
                item["raw"] = write_raw(args.raw_dir, f"{name}.raw", body)
            return name, item, body

        static_results = await asyncio.gather(*(fetch_snapshot(name, url, 20) for name, url in static_urls.items()))
        for name, item, body in static_results:
            raw_sources[name] = item
            if item["http_status"] == 200 and body is not None:
                if name == "feodotracker":
                    static_data[name] = parse_feodo(body)
                elif name == "tor_exit_nodes":
                    static_data[name] = parse_tor(body)
                elif name == "sslblacklist_cert":
                    static_data["sslblacklist_cert"] = parse_sslbl(body)
                elif name == "sslblacklist_ip":
                    static_data["sslblacklist_ip"] = parse_sslbl(body)

        c2_texts: dict[str, str] = {}
        c2_results = await asyncio.gather(*(fetch_snapshot(f"c2_{name}", url, 10) for name, url in C2_URLS.items()))
        for name, item, body in c2_results:
            source_name = name.removeprefix("c2_")
            raw_sources[f"c2:{source_name}"] = item
            if body is not None and item["http_status"] == 200:
                c2_texts[source_name] = body.decode("utf-8", errors="replace")
        static_data["c2_trackers"] = c2_texts

        semaphore = asyncio.Semaphore(args.concurrency)
        usom_rows: dict[str, dict] = {}

        async def usom_one(record: dict) -> None:
            ioc = norm(record["ioc"])
            ioc_type = "ip" if record["ioc_type"] == "ip" else "domain"
            async with semaphore:
                await asyncio.sleep(args.delay)
                try:
                    async with session.get(USOM_URL, params={"q": ioc, "type": ioc_type, "per-page": "10"}) as response:
                        body = await response.read()
                        filename = f"usom_{record['record_id']}.json"
                        raw_meta = write_raw(args.raw_dir, filename, body)
                        try:
                            payload = json.loads(body.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            payload = None
                        usom_rows[record["record_id"]] = {
                            "url": str(response.url), "http_status": response.status,
                            "raw": raw_meta, "payload": payload,
                        }
                except Exception as exc:
                    usom_rows[record["record_id"]] = {"url": USOM_URL, "http_status": 0, "error": f"{type(exc).__name__}: {exc}"}

        await asyncio.gather(*(usom_one(record) for record in records if applicable(record["ioc_type"], "usom")))

    feodo = static_data.get("feodotracker", {})
    tor = static_data.get("tor_exit_nodes", set())
    ssl_cert = static_data.get("sslblacklist_cert", (set(), set(), False))
    ssl_ip = static_data.get("sslblacklist_ip", (set(), set(), False))
    ssl_sha1s = ssl_cert[0] if isinstance(ssl_cert, tuple) else set()
    ssl_ips = (ssl_cert[1] if isinstance(ssl_cert, tuple) else set()) | (ssl_ip[1] if isinstance(ssl_ip, tuple) else set())
    ssl_deprecated = bool(ssl_ip[2]) if isinstance(ssl_ip, tuple) else False
    c2_texts = static_data.get("c2_trackers", {})

    spamhaus_ips = sorted({norm(record["ioc"]) for record in records if record["ioc_type"] == "ip"})
    spamhaus_results = dict(zip(spamhaus_ips, await asyncio.gather(*(asyncio.to_thread(spamhaus_lookup, ip) for ip in spamhaus_ips))))

    enriched = []
    for record in records:
        ioc = norm(record["ioc"])
        result = {}
        for source in TARGET_SOURCES:
            if not applicable(record["ioc_type"], source):
                result[source] = {"not_applicable": True}
                continue
            if source == "feodotracker":
                hit = feodo.get(ioc) if isinstance(feodo, dict) else None
                result[source] = {"found": bool(hit), "status": "found" if hit else "not_found", "entry": hit}
            elif source == "tor_exit_nodes":
                result[source] = {"found": ioc in tor, "status": "found" if ioc in tor else "not_found"}
            elif source == "sslblacklist":
                if record["ioc_type"] == "sha1":
                    result[source] = {"found": ioc in ssl_sha1s, "status": "found" if ioc in ssl_sha1s else "not_found", "feed_deprecated": False}
                else:
                    result[source] = {"found": False, "status": "unavailable", "feed_deprecated": ssl_deprecated, "error": "SSLBL IP feed is deprecated" if ssl_deprecated else "no usable IP feed"}
            elif source == "spamhaus":
                result[source] = spamhaus_results.get(ioc, {"status": "error", "found": False, "error": "missing lookup result"})
            elif source == "usom":
                row = usom_rows.get(record["record_id"], {})
                payload = row.get("payload")
                models = payload.get("models") if isinstance(payload, dict) else None
                found = isinstance(models, list) and any(norm((entry.get("url") or entry.get("value"))) == ioc for entry in models if isinstance(entry, dict))
                result[source] = {**{key: value for key, value in row.items() if key != "payload"}, "found": found, "status": "found" if found else "not_found" if row.get("http_status") == 200 else "error"}
            elif source == "c2_trackers":
                hits = [name for name, text in c2_texts.items() if exact_line_match(ioc, text)]
                result[source] = {"found": bool(hits), "status": "found" if hits else "not_found", "sources_found": hits, "sources_checked": len(c2_texts)}
        enriched.append({"record_id": record["record_id"], "ioc": record["ioc"], "ioc_type": record["ioc_type"], "expected_label": record["expected_label"], "label_quality": record["label_quality"], "source_results": result})

    summary = {}
    for source in TARGET_SOURCES:
        applicable_rows = [row for row in enriched if not row["source_results"][source].get("not_applicable")]
        found = sum(bool(row["source_results"][source].get("found")) for row in applicable_rows)
        unavailable = sum(row["source_results"][source].get("status") == "unavailable" for row in applicable_rows)
        errors = sum(row["source_results"][source].get("status") == "error" or row["source_results"][source].get("http_status") == 0 for row in applicable_rows)
        summary[source] = {"applicable_records": len(applicable_rows), "found": found, "not_found": len(applicable_rows) - found - unavailable - errors, "unavailable": unavailable, "errors": errors}

    return {
        "generated_at_utc": now_utc(),
        "status": "overlap_collected",
        "frozen_manifest": {"path": str(args.manifest.relative_to(REPO_ROOT)), "sha256": manifest_sha256},
        "policy": {"target_source_results_are_not_labels": True, "cache_writes": False, "circular_labeling": False},
        "source_fetches": raw_sources,
        "summary": summary,
        "records": enriched,
        "limitations": [
            "CLEAN labels remain public popularity/DNS/TLS proxy labels.",
            "SSLBL IP responses are unavailable/deprecated; SHA1 results are the usable SSLBL dimension.",
            "Overlap shows source coverage/detection, not ground-truth correctness.",
            "This artifact is exploratory until independent holdout adequacy and calibration gates pass.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args()
    args.manifest = args.manifest.resolve()
    args.output = args.output.resolve()
    args.raw_dir = args.raw_dir.resolve()
    artifact = asyncio.run(collect(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": artifact["status"], "summary": artifact["summary"], "output": str(args.output), "raw_dir": str(args.raw_dir)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
