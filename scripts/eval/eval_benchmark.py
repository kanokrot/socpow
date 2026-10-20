"""
scripts/eval/eval_benchmark.py  (stratified sampling version)

รัน IOC จาก benchmark dataset ผ่าน IOCInvestigator.investigate() จริง
แล้วบันทึกผลแบบ incremental (resumable) ไม่แก้โค้ด production ใดๆ

เปลี่ยนจากเดิม: ใช้ stratified sampling แทน pure random —
ดึง CLEAN ทั้งหมดเสมอ (n เล็ก ไม่อยากสุ่มทิ้ง) + สุ่ม MALICIOUS
ตามจำนวนที่ต้องการ เพื่อให้วัด precision/recall ได้มีความหมาย

Usage:
  python scripts/eval/eval_benchmark.py --malicious-limit 0 --seed 42
  python scripts/eval/eval_benchmark.py --malicious-limit 0 --seed 42 --resume
  python scripts/eval/eval_benchmark.py --malicious-limit 50 --seed 42  # optional sample
"""
import argparse
import asyncio
import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.tools.ioc_investigator import IOCInvestigator
from src.scoring.intelligent_scoring import IntelligentScoring
from src.utils.config import load_config

BENCHMARK_PATH = REPO_ROOT / "data" / "benchmark" / "benchmark_iocs_v2.json"
GROUP_A_EVAL_SOURCES = frozenset(
    {
        "feodotracker",
        "tor_exit_nodes",
        "c2_trackers",
        "sslblacklist",
        "spamhaus",
        "threatfox",
    }
)

SCORING_SOURCES = (
    "feodotracker",
    "c2_trackers",
    "spamhaus",
    "tor_exit_nodes",
    "sslblacklist",
    "threatfox",
)


def export_scoring_sources(result, observed_at):
    """Export the six active scoring-source fields for each eval record."""
    if result.get("trusted_shortcut") is True or result.get("trusted_hostname"):
        # The production path returned before source checks. Do not fabricate
        # unavailable source results for a policy-based trusted shortcut.
        return {}

    raw_sources = result.get("sources")
    if not isinstance(raw_sources, dict):
        raw_sources = {}

    exported = {}
    for source_name in SCORING_SOURCES:
        source_data = raw_sources.get(source_name)
        if not isinstance(source_data, dict):
            exported[source_name] = {
                "status": None,
                "score": 0,
                "unavailable": True,
                "observed_at": observed_at,
            }
            continue

        score = source_data.get("score")
        if not isinstance(score, (int, float)):
            # Preserve current production fallback semantics, e.g. Spamhaus
            # uses listed=True even when no explicit score field exists.
            score = IntelligentScoring._get_source_score(source_data)

        unavailable = source_data.get("unavailable") is True
        if source_name == "sslblacklist" and source_data.get("status") == "⚠":
            unavailable = True
        exported[source_name] = {
            "status": source_data.get("status"),
            "score": int(score),
            "unavailable": unavailable,
            "observed_at": source_data.get("observed_at") or observed_at,
        }

    return exported


def load_benchmark_stratified(malicious_limit, seed, benchmark_path=BENCHMARK_PATH):
    """
    Stratified sample: เอา CLEAN ทั้งหมดเสมอ (dataset เล็ก ไม่อยากสุ่มทิ้ง)
    + สุ่ม MALICIOUS ตามจำนวนที่ขอ (malicious_limit=0 แปลว่าเอาหมด)
    """
    records = json.loads(benchmark_path.read_text(encoding="utf-8"))

    clean_records = [r for r in records if r["expected_verdict"] == "CLEAN"]
    malicious_records = [r for r in records if r["expected_verdict"] == "MALICIOUS"]
    other_records = [r for r in records if r["expected_verdict"] not in ("CLEAN", "MALICIOUS")]

    if other_records:
        print(f"[warn] พบ {len(other_records)} record ที่ expected_verdict ไม่ใช่ "
              f"CLEAN/MALICIOUS (เช่น BENIGN) — รวมเข้าไปด้วยทั้งหมด")

    if malicious_limit and malicious_limit < len(malicious_records):
        rng = random.Random(seed)
        malicious_records = rng.sample(malicious_records, malicious_limit)

    combined = clean_records + malicious_records + other_records
    print(f"[sample] CLEAN={len(clean_records)} (ทั้งหมด, ไม่สุ่มทิ้ง) "
          f"MALICIOUS={len(malicious_records)} (สุ่ม seed={seed}) "
          f"OTHER={len(other_records)} -> รวม {len(combined)}")

    # สลับลำดับเพื่อไม่ให้ CLEAN ทั้งหมดติดกันตอนรัน (เผื่อพังกลางทางจะได้มีทั้งสองฝั่งใน partial results)
    rng2 = random.Random(seed + 1)
    rng2.shuffle(combined)
    return combined


def load_existing_results(results_path):
    done = {}
    if results_path.exists():
        for line_number, line in enumerate(
            results_path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if line.strip():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    preview = line[:200]
                    if len(line) > 200:
                        preview += "..."
                    print(
                        f"[warn] skipping invalid JSON at line {line_number}: "
                        f"{preview!r} ({exc.msg})"
                    )
                    continue
                done[row["ioc"]] = row
    return done


def normalize_output_ioc_type(value):
    return "ip" if value == "ipv4" else value


def evaluation_path(result):
    if "trusted_hostname" in result:
        return "trusted_shortcut"
    if result.get("error"):
        return "record_error"
    return "source_checks"


async def evaluate(
    records,
    delay_seconds,
    resume,
    output_path,
    allowed_sources=None,
):
    config = load_config()
    investigator = IOCInvestigator(config)

    done = load_existing_results(output_path) if resume else {}
    mode = "a" if resume else "w"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written_count = 0

    with output_path.open(mode, encoding="utf-8") as out:
        try:
            for i, rec in enumerate(records, 1):
                ioc = rec["ioc"]
                if ioc in done:
                    print(f"[{i}/{len(records)}] skip (already done): {ioc}")
                    continue
                print(f"[{i}/{len(records)}] investigating ({rec['expected_verdict']}): {ioc}")
                try:
                    if allowed_sources is None:
                        result = await investigator.investigate(ioc)
                    else:
                        result = await investigator.investigate(
                            ioc, allowed_sources=allowed_sources
                        )
                except Exception as exc:
                    result = {"error": str(exc)}

                observed_at = datetime.now(timezone.utc).isoformat()
                predicted_ioc_type_raw = result.get("ioc_type")
                row = {
                    "ioc": ioc,
                    "expected_verdict": rec["expected_verdict"],
                    "expected_ioc_type": rec["ioc_type"],
                    "source": rec.get("source"),
                    "label_collected_at": rec.get("collected_at"),
                    "evaluation_observed_at": observed_at,
                    "predicted_verdict": result.get("verdict"),
                    "predicted_ioc_type_raw": predicted_ioc_type_raw,
                    "predicted_ioc_type": normalize_output_ioc_type(predicted_ioc_type_raw),
                    "threat_score": result.get("threat_score"),
                    "sources_checked": result.get("sources_checked"),
                    "sources_flagged": result.get("sources_flagged"),
                    "sources": export_scoring_sources(result, observed_at),
                    "trusted_shortcut": (
                        result.get("trusted_shortcut") is True
                        or bool(result.get("trusted_hostname"))
                    ),
                    "evaluation_path": evaluation_path(result),
                    "error": result.get("error"),
                }
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
                out.flush()
                written_count += 1
                time.sleep(delay_seconds)  # กัน rate limit (VT free tier = 4 req/min)
        except (KeyboardInterrupt, asyncio.CancelledError):
            out.flush()
            print(
                f"\n[stop] Ctrl+C received; flushed output and wrote "
                f"{written_count} new record(s) in this run."
            )


def main():
    parser = argparse.ArgumentParser(description="Evaluate SOCPOW scoring against benchmark dataset (stratified)")
    parser.add_argument("--malicious-limit", type=int, default=0,
                         help="จำนวน MALICIOUS ที่จะสุ่ม (default 0 = เอาทั้งหมด). "
                              "CLEAN จะถูกดึงมาทั้งหมดเสมอไม่ว่าจะตั้งค่านี้เป็นอะไร")
    parser.add_argument("--seed", type=int, default=42,
                         help="random seed สำหรับ reproducible subsample")
    parser.add_argument("--delay", type=float, default=16.0,
                         help="วินาทีหน่วงระหว่าง IOC (default 16 = ~4/min, ตาม VT free tier)")
    parser.add_argument(
        "--output",
        type=Path,
        default="eval_results.jsonl",
        help="output JSONL path (default: eval_results.jsonl)",
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=BENCHMARK_PATH,
        help="benchmark JSON path (default: data/benchmark/benchmark_iocs_v2.json)",
    )
    parser.add_argument("--resume", action="store_true",
                         help="ข้าม IOC ที่ทำไปแล้วใน eval_results.jsonl")
    parser.add_argument(
        "--group-a-only",
        action="store_true",
        help="เรียกเฉพาะ locked Group A source allowlist (ไม่เรียก Group B หรือตาลอส)",
    )
    args = parser.parse_args()

    records = load_benchmark_stratified(
        args.malicious_limit or None,
        args.seed,
        args.benchmark,
    )
    allowed_sources = GROUP_A_EVAL_SOURCES if args.group_a_only else None
    print(
        f"Evaluating {len(records)} IOC(s) total, delay={args.delay}s, "
        f"resume={args.resume}, group_a_only={args.group_a_only}"
    )
    asyncio.run(
        evaluate(
            records,
            args.delay,
            args.resume,
            args.output,
            allowed_sources,
        )
    )
    print(f"\nDone. Raw results: {args.output}")


if __name__ == "__main__":
    main()
