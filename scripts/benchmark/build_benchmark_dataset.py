#!/usr/bin/env python3
"""
scripts/adhoc/build_benchmark_dataset.py

Builds a fixed benchmark/fixture dataset of IOCs with known-expected verdicts,
for use in SOCPOW's pytest benchmark suite and thesis test report.

Sources:
  - CIRCL MISP feed-osint (public feed, no auth) -> MALICIOUS IOCs
  - abuse.ch ThreatFox API (public, no auth)      -> MALICIOUS IOCs
  - Hardcoded known-good list                     -> CLEAN IOCs

Output: JSON list of records:
  {
    "ioc": "1.2.3.4",
    "ioc_type": "ip" | "domain" | "url" | "md5" | "sha256",
    "expected_verdict": "MALICIOUS" | "CLEAN",
    "source": "circl_misp_feed_osint" | "threatfox" | "manual_known_good",
    "tags": [...],
    "first_seen": "..." (if available),
    "collected_at": "<ISO timestamp>"
  }

Usage:
  python scripts/adhoc/build_benchmark_dataset.py --output data/benchmark/benchmark_iocs.json
  python scripts/adhoc/build_benchmark_dataset.py --malicious-count 15 --no-clean
  python scripts/adhoc/build_benchmark_dataset.py --threatfox-days 3 --misp-events 10

NOTE:
  - This script makes outbound HTTPS calls to circl.lu and threatfox-api.abuse.ch.
    Run it from a machine/network that allows those domains (it does NOT go
    through SOCPOW's MCP tools, so it is unaffected by the circl_misp_feed_check
    / threatfox_ioc_lookup timeout bug currently tracked as an open issue).
  - This is a read-only, standalone script. It does not touch config.yaml,
    src/mcp_servers/, or mcp_client.py, and writes only to --output.
  - ThreatFox Auth-Key resolution checks THREATFOX_AUTH_KEY first, then reads
    config.yaml api_keys.threatfox read-only via yaml.safe_load. If neither is
    available, the ThreatFox source is skipped with a warning.
"""

import argparse
import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from zipfile import BadZipFile, ZipFile

try:
    import yaml
except ImportError:
    yaml = None

CIRCL_MANIFEST_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
CIRCL_EVENT_URL_TMPL = "https://www.circl.lu/doc/misp/feed-osint/{filename}.json"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
TRANCO_TOP_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"
UMBRELLA_TOP_LIST_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
TOP_SITE_RANK_LIMIT = 1000
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_YAML_PATH = os.path.join(REPO_ROOT, "config.yaml")

USER_AGENT = "socpow-benchmark-builder/1.0"

# Known-good IOCs for false-positive testing (public DNS, well-known CDNs, etc.)
# Deliberately boring/stable so the "clean" side of the benchmark doesn't churn.
KNOWN_CLEAN_IOCS = [
    {"ioc": "8.8.8.8", "ioc_type": "ip", "tags": ["google-public-dns"]},
    {"ioc": "1.1.1.1", "ioc_type": "ip", "tags": ["cloudflare-public-dns"]},
    {"ioc": "9.9.9.9", "ioc_type": "ip", "tags": ["quad9-public-dns"]},
    {"ioc": "google.com", "ioc_type": "domain", "tags": ["alexa-top", "search-engine"]},
    {"ioc": "cloudflare.com", "ioc_type": "domain", "tags": ["cdn"]},
    {"ioc": "microsoft.com", "ioc_type": "domain", "tags": ["vendor"]},
    {"ioc": "wikipedia.org", "ioc_type": "domain", "tags": ["reference-site"]},
    {"ioc": "github.com", "ioc_type": "domain", "tags": ["dev-platform"]},
    {"ioc": "amazon.com", "ioc_type": "domain", "tags": ["ecommerce"]},
    {"ioc": "apple.com", "ioc_type": "domain", "tags": ["vendor"]},
]


def resolve_threatfox_auth_key():
    auth_key = os.getenv("THREATFOX_AUTH_KEY")
    if auth_key:
        print("[threatfox] using Auth-Key from THREATFOX_AUTH_KEY")
        return auth_key

    if yaml is None:
        print("[threatfox] WARN PyYAML is unavailable; cannot read config.yaml", file=sys.stderr)
        return None

    if not os.path.exists(CONFIG_YAML_PATH):
        print(f"[threatfox] WARN config.yaml not found: {CONFIG_YAML_PATH}", file=sys.stderr)
        return None

    try:
        with open(CONFIG_YAML_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        auth_key = cfg.get("api_keys", {}).get("threatfox")
        if auth_key:
            print("[threatfox] using Auth-Key from config.yaml api_keys.threatfox")
            return auth_key
        return None
    except Exception as e:
        print(f"[threatfox] WARN failed to read config.yaml: {e}", file=sys.stderr)
        return None


def http_get_json(url, timeout=20):
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_post_json(url, payload, timeout=20, extra_headers=None):
    data = json.dumps(payload).encode("utf-8")
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    req = Request(
        url,
        data=data,
        headers=headers,
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get_bytes(url, timeout=30):
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def classify_misp_attribute_type(misp_type):
    """Map MISP attribute types to SOCPOW's simplified ioc_type."""
    mapping = {
        "ip-dst": "ip",
        "ip-src": "ip",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
    }
    return mapping.get(misp_type)


def fetch_circl_misp_iocs(max_events=10, max_iocs=50, per_event_cap=20):
    """Pull IOCs from CIRCL's public MISP feed-osint (unauthenticated feed export)."""
    print(f"[circl] fetching manifest: {CIRCL_MANIFEST_URL}")
    try:
        manifest = http_get_json(CIRCL_MANIFEST_URL)
    except (URLError, HTTPError, TimeoutError) as e:
        print(f"[circl] ERROR fetching manifest: {e}", file=sys.stderr)
        return []

    def manifest_timestamp(item):
        metadata = item[1]
        if not isinstance(metadata, dict):
            return 0
        try:
            return int(metadata.get("timestamp", 0) or 0)
        except (TypeError, ValueError):
            return 0

    event_files = sorted(
        manifest.items(),
        key=manifest_timestamp,
        reverse=True,
    )[:max_events]
    print(f"[circl] {len(manifest)} events in manifest, sampling {len(event_files)}")

    iocs = []
    for i, (filename, _) in enumerate(event_files):
        if len(iocs) >= max_iocs:
            break
        event_url = CIRCL_EVENT_URL_TMPL.format(filename=filename)
        try:
            event_data = http_get_json(event_url)
        except (URLError, HTTPError, TimeoutError) as e:
            print(f"[circl] WARN skipping {filename}: {e}", file=sys.stderr)
            continue

        event = event_data.get("Event", {})
        event_info = event.get("info", "")
        attrs = event.get("Attribute", [])
        event_iocs = 0

        for attr in attrs:
            if len(iocs) >= max_iocs or event_iocs >= per_event_cap:
                break
            ioc_type = classify_misp_attribute_type(attr.get("type"))
            if not ioc_type:
                continue
            iocs.append({
                "ioc": attr.get("value"),
                "ioc_type": ioc_type,
                "expected_verdict": "MALICIOUS",
                "source": "circl_misp_feed_osint",
                "tags": [event_info] if event_info else [],
                "first_seen": event.get("date"),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })
            event_iocs += 1
        time.sleep(0.3)  # be polite to circl.lu
        print(f"[circl] event {i+1}/{len(event_files)} -> {len(attrs)} attrs, {len(iocs)} iocs so far")

    return iocs


def fetch_threatfox_iocs(days=1, max_iocs=50):
    """Pull recent IOCs from abuse.ch ThreatFox public API."""
    print(f"[threatfox] fetching last {days} day(s) of IOCs")
    auth_key = resolve_threatfox_auth_key()
    if not auth_key:
        print(
            "[threatfox] ERROR no Auth-Key found; checked THREATFOX_AUTH_KEY and "
            "config.yaml api_keys.threatfox",
            file=sys.stderr,
        )
        return []
    try:
        result = http_post_json(
            THREATFOX_API_URL,
            {"query": "get_iocs", "days": days},
            extra_headers={"Auth-Key": auth_key},
        )
    except (URLError, HTTPError, TimeoutError) as e:
        print(f"[threatfox] ERROR: {e}", file=sys.stderr)
        return []

    if result.get("query_status") != "ok":
        print(f"[threatfox] WARN unexpected query_status: {result.get('query_status')}", file=sys.stderr)
        return []

    iocs = []
    for entry in result.get("data", []):
        if len(iocs) >= max_iocs:
            break
        tf_type = entry.get("ioc_type")  # e.g. "ip:port", "domain", "url", "md5_hash", "sha256_hash"
        ioc_type = {
            "ip:port": "ip",
            "domain": "domain",
            "url": "url",
            "md5_hash": "md5",
            "sha256_hash": "sha256",
        }.get(tf_type)
        if not ioc_type:
            continue
        ioc_value = entry.get("ioc")
        if ioc_type == "ip" and ioc_value and ":" in ioc_value:
            ioc_value = ioc_value.split(":")[0]  # strip port
        iocs.append({
            "ioc": ioc_value,
            "ioc_type": ioc_type,
            "expected_verdict": "MALICIOUS",
            "source": "threatfox",
            "tags": [entry.get("malware_printable")] if entry.get("malware_printable") else [],
            "first_seen": entry.get("first_seen_utc"),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })

    print(f"[threatfox] collected {len(iocs)} iocs")
    return iocs


def _parse_top_site_zip(payload, source_url, rank_limit=TOP_SITE_RANK_LIMIT):
    """Parse a rank,domain CSV ZIP and return domains in the top rank range."""
    try:
        with ZipFile(io.BytesIO(payload)) as archive:
            csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if not csv_names:
                raise ValueError("ZIP contains no CSV file")
            csv_bytes = archive.read(csv_names[0])
    except (BadZipFile, KeyError, OSError, ValueError) as e:
        raise ValueError(f"invalid top-site ZIP from {source_url}: {e}") from e

    try:
        rows = csv.reader(io.TextIOWrapper(io.BytesIO(csv_bytes), encoding="utf-8-sig", newline=""))
        domains = []
        for row in rows:
            if len(row) < 2:
                continue
            try:
                rank = int(row[0].strip())
            except ValueError:
                # Both supported feeds have a header in some versions.
                continue
            domain = row[1].strip().lower().rstrip(".")
            if 1 <= rank <= rank_limit and domain:
                domains.append((rank, domain))
    except (UnicodeDecodeError, csv.Error) as e:
        raise ValueError(f"invalid rank,domain CSV from {source_url}: {e}") from e

    if not domains:
        raise ValueError(f"rank,domain CSV from {source_url} contained no usable top-{rank_limit} domains")
    return [domain for _, domain in sorted(domains)]


def _fetch_top_site_domains(url, source_name):
    try:
        payload = http_get_bytes(url)
        domains = _parse_top_site_zip(payload, url)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as e:
        raise RuntimeError(f"{source_name} endpoint failed ({url}): {e}") from e
    print(f"[{source_name}] fetched {len(domains)} usable domains from top-{TOP_SITE_RANK_LIMIT}")
    return domains


def fetch_tranco_clean_domains(n: int = 25):
    """Fetch n new CLEAN domain entries from Tranco, falling back to Umbrella."""
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise ValueError("n must be a non-negative integer")
    if n == 0:
        return []

    existing_domains = {
        item["ioc"].lower()
        for item in KNOWN_CLEAN_IOCS
        if item["ioc_type"] == "domain"
    }
    try:
        domains = _fetch_top_site_domains(TRANCO_TOP_LIST_URL, "tranco")
        source = "tranco_top_sites"
    except RuntimeError as tranco_error:
        print(f"[tranco] WARN {tranco_error}; trying Cisco Umbrella fallback", file=sys.stderr)
        try:
            domains = _fetch_top_site_domains(UMBRELLA_TOP_LIST_URL, "umbrella")
            source = "cisco_umbrella_top_sites"
        except RuntimeError as umbrella_error:
            raise RuntimeError(
                "unable to fetch CLEAN domains: Tranco failed: "
                f"{tranco_error}; Cisco Umbrella fallback failed: {umbrella_error}"
            ) from umbrella_error

    selected = []
    seen = set(existing_domains)
    now = datetime.now(timezone.utc).isoformat()
    for domain in domains:
        if domain in seen:
            continue
        seen.add(domain)
        selected.append({
            "ioc": domain,
            "ioc_type": "domain",
            "expected_verdict": "CLEAN",
            "source": source,
            "tags": ["top-site", "top-1000"],
            "first_seen": None,
            "collected_at": now,
        })
        if len(selected) >= n:
            break

    if len(selected) < n:
        raise RuntimeError(
            f"top-site sources provided only {len(selected)} new CLEAN domains; "
            f"needed {n} after deduplicating the existing CLEAN set"
        )
    print(f"[clean] fetched {len(selected)} additional domains from {source}")
    return selected


def build_clean_iocs(additional_count=25):
    now = datetime.now(timezone.utc).isoformat()
    manual = [
        {
            "ioc": item["ioc"],
            "ioc_type": item["ioc_type"],
            "expected_verdict": "CLEAN",
            "source": "manual_known_good",
            "tags": item["tags"],
            "first_seen": None,
            "collected_at": now,
        }
        for item in KNOWN_CLEAN_IOCS
    ]
    return manual + fetch_tranco_clean_domains(additional_count)


def dedupe(records):
    seen = set()
    out = []
    for r in records:
        key = (r["ioc_type"], (r["ioc"] or "").lower())
        if key in seen or not r["ioc"]:
            continue
        seen.add(key)
        out.append(r)
    return out


def main():
    parser = argparse.ArgumentParser(description="Build SOCPOW benchmark IOC dataset")
    parser.add_argument("--output", default="data/benchmark/benchmark_iocs.json",
                         help="Output JSON path (default: data/benchmark/benchmark_iocs.json)")
    parser.add_argument("--malicious-count", type=int, default=20,
                         help="Target number of malicious IOCs total, combined across sources (default: 20)")
    parser.add_argument("--misp-events", type=int, default=10,
                         help="Number of CIRCL MISP events to sample (default: 10)")
    parser.add_argument("--misp-per-event-cap", type=int, default=20,
                         help="Maximum CIRCL MISP IOCs to collect per event (default: 20)")
    parser.add_argument("--threatfox-days", type=int, default=1,
                         help="How many days back to pull from ThreatFox (default: 1)")
    parser.add_argument("--clean-count", type=int, default=25,
                        help="Number of additional top-site CLEAN domains (default: 25; plus 10 manual CLEAN IOCs)")
    parser.add_argument("--no-clean", action="store_true",
                         help="Skip adding the known-clean IOC set")
    parser.add_argument("--sources", choices=["circl", "threatfox", "both"], default="both",
                         help="Which malicious source(s) to pull from (default: both)")
    args = parser.parse_args()

    per_source_cap = args.malicious_count if args.sources != "both" else max(1, args.malicious_count // 2 + 5)

    malicious = []
    if args.sources in ("circl", "both"):
        malicious += fetch_circl_misp_iocs(
            max_events=args.misp_events,
            max_iocs=per_source_cap,
            per_event_cap=args.misp_per_event_cap,
        )
    if args.sources in ("threatfox", "both"):
        malicious += fetch_threatfox_iocs(days=args.threatfox_days, max_iocs=per_source_cap)

    malicious = dedupe(malicious)[: args.malicious_count]

    records = list(malicious)
    if not args.no_clean:
        records += build_clean_iocs(args.clean_count)

    if not malicious:
        print("[!] WARNING: no malicious IOCs collected. Check network access to "
              "circl.lu / threatfox-api.abuse.ch, or your machine's outbound firewall rules.",
              file=sys.stderr)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    n_mal = sum(1 for r in records if r["expected_verdict"] == "MALICIOUS")
    n_clean = sum(1 for r in records if r["expected_verdict"] == "CLEAN")
    print(f"\n[done] wrote {len(records)} records to {args.output}")
    print(f"       MALICIOUS: {n_mal}  CLEAN: {n_clean}")


if __name__ == "__main__":
    main()
