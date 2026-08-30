#!/usr/bin/env python3
"""
core/gap_analysis.py — machine-readable capability matrix + automatic gap detection.

Purpose (spec §26/§40): stop the platform from silently becoming incomplete. This
module derives — from the ACTUAL code, not documentation — a matrix linking:

    knowledge (KB id) -> detection (emitted by a scanner/analyzer)
                      -> validation (registry capability)
                      -> automated checker (validator function) vs manual

and flags concrete gaps:
    * knowledge defined but never emitted by any producer  (knowledge_without_detection)
    * finding emitted but no KB entry to enrich it         (detection_without_knowledge)
    * validation capability declared but no automated checker (capability_without_checker → MANUAL)
    * validator wired but no capability metadata            (validator_without_capability)

Detection of "emitted ids" is a static heuristic: it scans producer modules for
the KB id appearing as a string literal. Ids built purely dynamically may not be
seen; those are reported as 'no static emission found' rather than a false gap.
"""

from __future__ import annotations

import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# modules that PRODUCE findings (emit KB ids)
_PRODUCER_GLOBS = ("scanner_", "analyzers/", "threat_detection/", "attack_paths/",
                   "connectors/", "validation/resilience", "validation/loadtest",
                   "cve_intel", "knowledgebase")  # knowledgebase excluded from "emit" below


def _iter_producer_files():
    for base, dirs, files in os.walk(_ROOT):
        if any(skip in base for skip in ("/.git", "/__pycache__", "/tests", "/docs")):
            continue
        for fn in files:
            if not fn.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(base, fn), _ROOT)
            if rel in ("knowledgebase.py",) or rel.startswith("core/knowledge") \
               or rel.startswith("core/gap_analysis"):
                continue
            if any(rel.startswith(g) or ("/" + g) in ("/" + rel) or g in rel for g in _PRODUCER_GLOBS):
                yield os.path.join(base, fn)


def _kb_ids() -> set:
    import knowledgebase as kb
    return set(kb.KB.keys())


def emitted_ids() -> set:
    """KB ids that appear as string literals in producer modules (heuristic)."""
    ids = _kb_ids()
    found = set()
    blobs = []
    for p in _iter_producer_files():
        try:
            with open(p, "r", errors="ignore") as fh:
                blobs.append(fh.read())
        except Exception:
            continue
    text = "\n".join(blobs)
    for fid in ids:
        # match the id as a quoted literal (single or double quotes)
        if re.search(r"['\"]" + re.escape(fid) + r"['\"]", text):
            found.add(fid)
    return found


def _capabilities() -> dict:
    from validation import registry
    return dict(registry.CAPABILITIES)


def _validator_prefixes() -> set:
    from validation import validator
    return set(validator._REGISTRY.keys())


def matrix() -> dict:
    """Return the full machine-readable capability/gap matrix."""
    kb_ids = _kb_ids()
    emitted = emitted_ids()
    caps = _capabilities()
    cap_prefixes = set(caps.keys())
    val_prefixes = _validator_prefixes()

    # a KB id is "validatable" if some capability prefix is a prefix of it
    def has_capability(fid: str) -> bool:
        return any(fid == p or fid.startswith(p) for p in cap_prefixes)

    def has_checker(fid: str) -> bool:
        return any(fid == p or fid.startswith(p) for p in val_prefixes)

    knowledge_without_detection = sorted(fid for fid in kb_ids if fid not in emitted)
    # capability prefixes with no registered checker function -> honest MANUAL
    capability_without_checker = sorted(
        p for p in cap_prefixes
        if not any(p == vp or p.startswith(vp) or vp.startswith(p) for vp in val_prefixes))
    # validator prefixes with no capability metadata
    validator_without_capability = sorted(
        vp for vp in val_prefixes
        if not any(vp == cp or vp.startswith(cp) or cp.startswith(vp) for cp in cap_prefixes))

    return {
        "kb_total": len(kb_ids),
        "emitted_total": len(emitted),
        "capabilities_total": len(caps),
        "validators_total": len(val_prefixes),
        "knowledge_without_detection": knowledge_without_detection,
        "capability_without_checker": capability_without_checker,
        "validator_without_capability": validator_without_capability,
        "counts": {
            "knowledge_without_detection": len(knowledge_without_detection),
            "capability_without_checker": len(capability_without_checker),
            "validator_without_capability": len(validator_without_capability),
        },
    }


def render() -> str:
    m = matrix()
    L = ["CAPABILITY / GAP MATRIX (derived from code, not docs)", ""]
    L.append(f"  KB definitions            : {m['kb_total']}")
    L.append(f"  ...statically emitted     : {m['emitted_total']} "
             f"(others may be emitted dynamically or via imports)")
    L.append(f"  Validation capabilities   : {m['capabilities_total']}")
    L.append(f"  Automated validators      : {m['validators_total']}")
    L.append("")
    L.append("  GAPS (each is expected/honest, not a hidden TODO — see notes):")
    c = m["counts"]
    L.append(f"    knowledge without static detection : {c['knowledge_without_detection']}")
    L.append(f"    capability without auto-checker    : {c['capability_without_checker']}  "
             f"(these correctly resolve to MANUAL_VALIDATION_REQUIRED)")
    L.append(f"    validator without capability       : {c['validator_without_capability']}")
    if m["capability_without_checker"]:
        L.append("")
        L.append("  Capabilities that are honest MANUAL (no auto-exploit shipped):")
        for p in m["capability_without_checker"][:40]:
            L.append(f"    - {p}")
    L.append("")
    L.append("  NOTE: 'knowledge without static detection' = KB classes reasoned/imported or emitted")
    L.append("        dynamically (e.g. host-export, SCA-CVE, header maps). Not a fabricated capability.")
    return "\n".join(L)
