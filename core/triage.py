#!/usr/bin/env python3
"""
core/triage.py — persistent finding triage across scans (spec §17).

Analysts mark findings as false_positive / accepted_risk / fixed / etc. Those
decisions must survive re-scans so noise doesn't come back every run. This store
maps a finding's stable fingerprint -> a triage record, persisted as JSON.

    store = TriageStore.load("triage.json")
    store.mark("<fingerprint>", "false_positive", note="WAF blocks it")
    store.apply(assessment.findings)   # sets .status on matching findings
    store.save()
"""

from __future__ import annotations

import json
import os
import time

from .findings import STATUSES


class TriageStore:
    def __init__(self, path: str | None = None, records: dict | None = None):
        self.path = path
        self.records: dict[str, dict] = records or {}

    # ---- persistence ------------------------------------------------------
    @classmethod
    def load(cls, path: str | None) -> "TriageStore":
        if path and os.path.isfile(path):
            try:
                with open(path, "r") as fh:
                    data = json.load(fh)
                return cls(path, data.get("records", {}))
            except Exception:
                pass
        return cls(path, {})

    def save(self, path: str | None = None) -> str | None:
        p = path or self.path
        if not p:
            return None
        with open(p, "w") as fh:
            json.dump({"version": 1, "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "records": self.records}, fh, indent=2)
        return p

    # ---- operations -------------------------------------------------------
    def mark(self, fingerprint: str, status: str, note: str = "") -> bool:
        status = status.lower()
        if status not in STATUSES:
            raise ValueError(f"invalid status '{status}'; choose from {', '.join(STATUSES)}")
        self.records[fingerprint] = {
            "status": status, "note": note,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return True

    def get(self, fingerprint: str) -> dict | None:
        return self.records.get(fingerprint)

    def apply(self, findings) -> int:
        """Overlay stored triage decisions onto findings. Returns count applied."""
        n = 0
        for f in findings:
            rec = self.records.get(f.fingerprint())
            if rec:
                f.status = rec["status"]
                if rec.get("note"):
                    f.tags.append(f"triage:{rec['note']}"[:60])
                n += 1
        return n

    def active_findings(self, findings) -> list:
        """Findings still worth attention (exclude fixed/false_positive/accepted_risk)."""
        muted = {"false_positive", "fixed", "accepted_risk"}
        return [f for f in findings if f.status not in muted]

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for r in self.records.values():
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        return {"total": len(self.records), "by_status": counts}
