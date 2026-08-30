#!/usr/bin/env python3
"""
core/checkpoint.py — scan checkpointing & resume (spec §22).

Deep assessments can take a while; a crash shouldn't lose everything. The
orchestrator writes a checkpoint after each pipeline stage into
~/.cache/overwatch/scans/<scan-id>.json capturing stage status
(completed/running/failed/skipped/blocked) and the findings gathered so far.

    overwatch target --resume <scan-id>

On resume, stages already marked "completed" are skipped and their findings are
restored, so the scan continues from where it stopped.
"""

from __future__ import annotations

import json
import os
import time

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "overwatch", "scans")

STAGE_STATES = ("pending", "running", "completed", "failed", "skipped", "blocked")


def _path(scan_id: str) -> str:
    return os.path.join(CACHE_DIR, f"{scan_id}.json")


def new_scan_id(target: str) -> str:
    import hashlib
    h = hashlib.sha1(f"{target}|{time.time()}".encode()).hexdigest()[:8]
    return f"SCAN-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{h}"


class Checkpoint:
    def __init__(self, scan_id: str, meta: dict | None = None):
        self.scan_id = scan_id
        self.meta = meta or {}
        self.stages: dict[str, dict] = {}
        self.findings: list[dict] = []
        self.updated = ""

    # ---- persistence ------------------------------------------------------
    def save(self) -> str:
        os.makedirs(CACHE_DIR, exist_ok=True)
        self.updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(_path(self.scan_id), "w") as fh:
            json.dump({"scan_id": self.scan_id, "meta": self.meta, "stages": self.stages,
                       "findings": self.findings, "updated": self.updated}, fh, indent=2)
        return _path(self.scan_id)

    @classmethod
    def load(cls, scan_id: str) -> "Checkpoint | None":
        p = _path(scan_id)
        if not os.path.isfile(p):
            return None
        try:
            with open(p) as fh:
                d = json.load(fh)
        except Exception:
            return None
        c = cls(d.get("scan_id", scan_id), d.get("meta", {}))
        c.stages = d.get("stages", {})
        c.findings = d.get("findings", [])
        c.updated = d.get("updated", "")
        return c

    # ---- stage tracking ---------------------------------------------------
    def mark(self, stage: str, state: str, detail: str = "") -> None:
        self.stages[stage] = {"state": state, "detail": detail,
                              "time": time.strftime("%H:%M:%S", time.gmtime())}
        self.save()

    def is_completed(self, stage: str) -> bool:
        return self.stages.get(stage, {}).get("state") == "completed"

    def store_findings(self, findings) -> None:
        """Persist findings-so-far (accepts Finding objects or dicts)."""
        self.findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
        self.save()

    def restore_findings(self):
        """Rehydrate Finding objects from the checkpoint."""
        from .findings import Finding
        import dataclasses
        valid = {f.name for f in dataclasses.fields(Finding)}
        out = []
        for d in self.findings:
            out.append(Finding(**{k: v for k, v in d.items() if k in valid}))
        return out

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for s in self.stages.values():
            counts[s["state"]] = counts.get(s["state"], 0) + 1
        return {"scan_id": self.scan_id, "updated": self.updated,
                "stages": counts, "findings": len(self.findings)}


BASELINE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "overwatch", "baselines")


def _baseline_key(target: str) -> str:
    import hashlib
    import re
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", target)[:40]
    return f"{safe}-{hashlib.sha1(target.encode()).hexdigest()[:8]}"


def save_baseline(target: str, report_json_path: str) -> str | None:
    """Save a report.json as the retest baseline for this target."""
    import shutil
    if not os.path.isfile(report_json_path):
        return None
    os.makedirs(BASELINE_DIR, exist_ok=True)
    dst = os.path.join(BASELINE_DIR, _baseline_key(target) + ".json")
    shutil.copy(report_json_path, dst)
    return dst


def find_baseline(target: str) -> str | None:
    """Locate the most recent baseline for a target (for --retest)."""
    p = os.path.join(BASELINE_DIR, _baseline_key(target) + ".json")
    return p if os.path.isfile(p) else None


def list_scans() -> list[dict]:
    out = []
    if not os.path.isdir(CACHE_DIR):
        return out
    for fn in sorted(os.listdir(CACHE_DIR)):
        if fn.endswith(".json"):
            c = Checkpoint.load(fn[:-5])
            if c:
                out.append(c.summary())
    return out
