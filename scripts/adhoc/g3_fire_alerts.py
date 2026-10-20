#!/usr/bin/env python3
"""G3: fire a fixed alert set at alert_triage and record the outcome per alert.

Run once per account, then compare:
  python scripts/adhoc/g3_fire_alerts.py --label IR    --token <IR bearer token>
  python scripts/adhoc/g3_fire_alerts.py --label admin --token <admin bearer token>
  python scripts/adhoc/g3_fire_alerts.py --compare g3_IR.csv g3_admin.csv

Auth (pick one):
  --token / env SOCPOW_TOKEN                      Bearer access token
  --session + --csrf / env SOCPOW_SESSION, SOCPOW_CSRF
      values of the socpow_session and socpow_csrf cookies copied from the browser

The script never approves anything. A run that pauses at an approval gate is
recorded with whatever status the API reports at that point.
"""
import argparse
import csv
import json
import os
import re
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path
import urllib.error
import urllib.request

ALERTS = [
    {
        "id": "A1-cve-log4shell",
        "expect": "CVE steps (cve_lookup/kev/epss) run; high priority",
        "expected_decision": True,
        "params": {
            "alert_text": "IDS alert: CVE-2021-44228 (Log4Shell) exploit attempt, JNDI lookup "
                          "string in User-Agent from 203.0.113.45 to web01.corp.test:8080",
            "alert_source": "SIEM",
            "alert_severity": "high",
        },
    },
    {
        "id": "A2-ioc-ip-domain",
        "expect": "IOC enrichment on IP + domain; verdict depends on real TI data",
        "params": {
            "alert_text": "Outbound connection from host WS-114 to 198.51.100.77:4444, then "
                          "download from update-example.test/payload.bin",
            "alert_source": "EDR",
            "alert_severity": "high",
        },
    },
    {
        "id": "A3-no-ioc-wazuh13",
        "expect": "known gap: level 12+ with no IOC is rated low priority",
        "expected_decision": False,
        "params": {
            "alert_text": "Wazuh rule 100210 level 13: repeated failed logins then a successful "
                          "login for user svc_backup on host FS-02, followed by a new scheduled task",
            "alert_source": "Wazuh",
            "alert_severity": "critical",
        },
    },
    {
        "id": "A4-benign-scan",
        "expect": "low priority / false positive",
        "expected_decision": False,
        "params": {
            "alert_text": "Authenticated vulnerability scan from internal scanner 10.20.4.5 "
                          "against 10.20.4.0/24 during the approved maintenance window",
            "alert_source": "IDS",
            "alert_severity": "low",
        },
    },
    {
        "id": "A5-phish-sender",
        "expect": "sender-domain path; email_security step is skipped (sender_domains key)",
        "params": {
            "alert_text": "User reported email from billing@paypa1-secure.test with link "
                          "hxxps://paypa1-secure[.]test/login, SPF fail",
            "alert_source": "Email gateway",
            "alert_severity": "medium",
        },
    },
    {
        "id": "A6-hash-eicar",
        "expect": "hash lookup; EICAR test file should come back detected",
        "params": {
            "alert_text": "AV detection on WS-088: file invoice.exe SHA256 "
                          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f "
                          "quarantined by the endpoint agent",
            "alert_source": "EDR",
            "alert_severity": "medium",
        },
    },
]

RUNNING = {"running", "processing", "pending", "queued", "starting", "active"}
FIELDS = ["label", "alert_id", "session_id", "status", "seconds", "decision",
          "expected_decision", "decision_match", "decision_error", "warn_count",
          "warn_steps", "step_rows", "tools", "summary", "expect"]


def headers(args):
    h = {"Content-Type": "application/json"}
    if args.token:
        h["Authorization"] = "Bearer " + args.token
    elif args.session:
        h["Cookie"] = f"socpow_session={args.session}; socpow_csrf={args.csrf}"
        h["X-CSRF-Token"] = args.csrf or ""
    return h


def call(method, url, hdrs, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode(errors="replace")[:500]}
    except Exception as e:  # network error, bad JSON
        return 0, {"error": str(e)}


def parse_summary(summary):
    warn_count, warn_steps = 0, ""
    m = re.search(r"WARNING:\s*(\d+) step\(s\) failed or were denied:\s*(.*?)(?: — |$)", summary or "")
    if m:
        warn_count, warn_steps = int(m.group(1)), m.group(2).strip()
    return warn_count, warn_steps


def read_priority_decision(db_path, session_id):
    """Read the alert_triage decision step from the agent's local SQLite DB."""
    path = Path(db_path).expanduser()
    if not path.is_file():
        return None, f"database not found: {path}"
    try:
        with closing(sqlite3.connect(str(path), timeout=5)) as conn:
            conn.execute("PRAGMA query_only = ON")
            row = conn.execute(
                """SELECT tool_result FROM agent_steps
                   WHERE session_id = ? AND step_type = 'decision'
                     AND content LIKE 'priority_evaluation:%'
                   ORDER BY step_number DESC LIMIT 1""",
                (session_id,),
            ).fetchone()
    except sqlite3.Error as exc:
        return None, f"SQLite read failed: {exc}"
    if not row:
        return None, "priority_evaluation decision row not found"
    try:
        result = json.loads(row[0] or "")
    except (TypeError, json.JSONDecodeError):
        return None, "priority_evaluation tool_result is not valid JSON"
    decision = result.get("decision") if isinstance(result, dict) else None
    if type(decision) is not bool:
        return None, "priority_evaluation tool_result has no boolean decision"
    return decision, ""


def run_one(args, alert):
    hdrs = headers(args)
    base = args.base.rstrip("/")
    t0 = time.time()
    code, resp = call("POST", f"{base}/api/playbooks/alert_triage/run", hdrs,
                      {"params": alert["params"]})
    row = {"label": args.label, "alert_id": alert["id"], "expect": alert["expect"],
           "session_id": "", "status": "", "seconds": 0, "decision": "",
           "expected_decision": alert.get("expected_decision", ""),
           "decision_match": "", "decision_error": "",
           "warn_count": 0, "warn_steps": "", "step_rows": 0, "summary": ""}
    sid = resp.get("session_id")
    if code != 200 or not sid:
        row["status"] = f"START_FAILED http={code}"
        row["summary"] = str(resp)[:300]
        return row
    row["session_id"] = sid
    data = {}
    while True:
        time.sleep(args.poll)
        code, data = call("GET", f"{base}/api/playbooks/sessions/{sid}", hdrs)
        sess = data.get("session", data) if isinstance(data, dict) else {}
        status = str(sess.get("status", "")).lower()
        if code == 200 and status and status not in RUNNING:
            break
        if time.time() - t0 > args.timeout:
            status = f"TIMEOUT(last={status or code})"
            break
    sess = data.get("session", data) if isinstance(data, dict) else {}
    steps = data.get("steps") or sess.get("steps") or []
    row["status"] = status
    row["seconds"] = round(time.time() - t0, 1)
    row["summary"] = (sess.get("summary") or "").replace("\n", " ")
    row["step_rows"] = len(steps)
    row["tools"] = ";".join(str(s.get("tool_name")) for s in steps if s.get("tool_name"))
    row["warn_count"], row["warn_steps"] = parse_summary(row["summary"])
    db_path = args.db or os.environ.get("SOCPOW_AGENT_DB") or (
        Path.home() / ".blue-team-assistant" / "cache" / "agent.db"
    )
    decision, decision_error = read_priority_decision(db_path, sid)
    row["decision"] = decision if decision is not None else ""
    row["decision_error"] = decision_error
    if row["expected_decision"] != "":
        row["decision_match"] = decision is row["expected_decision"]
    return row


def fire(args):
    token = args.token or os.environ.get("SOCPOW_TOKEN")
    args.token = token
    args.session = args.session or os.environ.get("SOCPOW_SESSION")
    args.csrf = args.csrf or os.environ.get("SOCPOW_CSRF")
    if not (args.token or (args.session and args.csrf)):
        sys.exit("need --token, or --session and --csrf (or the SOCPOW_* env vars)")
    only = set(args.only.split(",")) if args.only else None
    rows = []
    for alert in ALERTS:
        if only and alert["id"] not in only and alert["id"].split("-")[0] not in only:
            continue
        print(f"[{args.label}] firing {alert['id']} ...", flush=True)
        row = run_one(args, alert)
        print(f"    status={row['status']} decision={row['decision']!s} "
              f"expected={row['expected_decision']!s} match={row['decision_match']!s} "
              f"warn={row['warn_count']} {row['warn_steps']} ({row['seconds']}s)", flush=True)
        if row["decision_error"]:
            print(f"    decision read: {row['decision_error']}", flush=True)
        rows.append(row)
    out = f"g3_{args.label}"
    with open(out + ".csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    with open(out + ".json", "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"\nwrote {out}.csv and {out}.json")


def compare(a_path, b_path):
    def load(p):
        with open(p, newline="", encoding="utf-8-sig") as f:
            return {r["alert_id"]: r for r in csv.DictReader(f)}
    a, b = load(a_path), load(b_path)
    print(f"{'alert':<20} | {'A status/decision/warn':<44} | B status/decision/warn")
    for aid in a:
        ra, rb = a[aid], b.get(aid, {})
        fa = f"{ra['status']}/{ra.get('decision') or '-'}/{ra['warn_count']}"
        fb = f"{rb.get('status','-')}/{rb.get('decision') or '-'}/{rb.get('warn_count','-')}"
        print(f"{aid:<20} | {fa:<44} | {fb}")
        if ra.get("warn_steps") or rb.get("warn_steps"):
            print(f"{'':<20} |   A warn: {ra.get('warn_steps','')}")
            print(f"{'':<20} |   B warn: {rb.get('warn_steps','')}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default="http://127.0.0.1:3003")
    p.add_argument("--label", default="run", help="e.g. IR or admin (names the output files)")
    p.add_argument("--token")
    p.add_argument("--session")
    p.add_argument("--csrf")
    p.add_argument("--only", help="comma list, e.g. A1,A3")
    p.add_argument("--poll", type=float, default=5.0)
    p.add_argument("--timeout", type=float, default=600.0)
    p.add_argument("--db", help="agent SQLite DB path (default: SOCPOW_AGENT_DB or ~/.blue-team-assistant/cache/agent.db)")
    p.add_argument("--compare", nargs=2, metavar=("A_CSV", "B_CSV"))
    a = p.parse_args()
    if a.compare:
        compare(*a.compare)
    else:
        fire(a)
