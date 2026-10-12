#!/usr/bin/env python3
"""Combine already-labeled clean URL rounds without issuing new VT requests."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_metadata() -> dict[str, Any]:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                                capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT,
                                    capture_output=True, text=True, check=True).stdout.strip())
    except Exception:
        commit, dirty = None, None
    return {"script_git_commit": commit, "script_git_dirty": dirty}


def combine_clean_rounds(round1: Path, round1_manifest: Path,
                         round2: Path, round2_manifest: Path,
                         out_dir: Path) -> tuple[Path, Path]:
    inputs = {"round1": round1, "round1_manifest": round1_manifest,
              "round2": round2, "round2_manifest": round2_manifest}
    rows_by_round: dict[str, list[dict[str, Any]]] = {}
    manifests: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for name, path in (("round1", round1), ("round2", round2)):
        rows = _read_json(path)
        if not isinstance(rows, list):
            raise ValueError(f"{name} labeled input must be a JSON array")
        for index, row in enumerate(rows):
            ioc = row.get("ioc") if isinstance(row, dict) else None
            if not isinstance(ioc, str) or not ioc:
                raise ValueError(f"{name} row {index} has no string ioc")
            if ioc in seen:
                raise ValueError(f"duplicate clean IOC across rounds: {ioc}")
            seen.add(ioc)
            if row.get("vt_label") != "CLEAN" or row.get("expected_verdict") != "CLEAN":
                raise ValueError(f"{name} row {index} is not finalized CLEAN")
        rows_by_round[name] = rows
        manifest = _read_json(round1_manifest if name == "round1" else round2_manifest)
        if not isinstance(manifest, dict):
            raise ValueError(f"{name} label manifest must be a JSON object")
        manifests[name] = manifest

    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / "clean_labeled_final.json"
    manifest_path = out_dir / "combine_clean_url_rounds_manifest.json"
    if output_path.exists() or manifest_path.exists():
        raise FileExistsError("refusing to overwrite clean-round combination outputs")
    combined = rows_by_round["round1"] + rows_by_round["round2"]
    output_bytes = (json.dumps(combined, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    output_path.write_bytes(output_bytes)
    manifest = {
        "script": Path(__file__).name,
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "inputs": {name: {"path": str(path), "sha256": _sha256(path)}
                   for name, path in inputs.items()},
        "counts_by_round": {
            name: {"clean_rows": len(rows_by_round[name]),
                   "counts_by_stage": manifests[name].get("counts_by_stage", {})}
            for name in ("round1", "round2")
        },
        "combined": {"clean_rows": len(combined),
                     "sha256": hashlib.sha256(output_bytes).hexdigest(),
                     "output_file": output_path.name},
        **_git_metadata(),
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
    return output_path, manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--round1", type=Path, required=True)
    parser.add_argument("--round1-manifest", type=Path, required=True)
    parser.add_argument("--round2", type=Path, required=True)
    parser.add_argument("--round2-manifest", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    output, manifest = combine_clean_rounds(args.round1, args.round1_manifest,
                                             args.round2, args.round2_manifest,
                                             args.out_dir)
    print(f"Wrote {output} and {manifest}")


if __name__ == "__main__":
    main()
