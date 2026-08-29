#!/usr/bin/env python3
"""
cve_intel.py — CVE intelligence enrichment.

Turns a bare CVE id into actionable intelligence by consulting authoritative,
continuously-updated feeds:

  - CISA KEV  : Known Exploited Vulnerabilities catalog — is this CVE being
                ACTIVELY exploited in the wild right now? (defensive priority
                signal; sourced from CISA, not an exploit itself)
  - NVD       : CVSS base score + severity + summary (NIST National Vuln DB)

Design goals:
  - OFFLINE-SAFE: every network call is wrapped; if there is no internet (or the
    feed is down) enrichment degrades gracefully and the scan still completes.
  - CACHED: the KEV catalog is fetched once per run and reused; NVD lookups are
    memoized. A local disk cache (~/.cache/vulnscan) avoids repeat downloads.

This module NEVER downloads or runs exploit code. It only reads vulnerability
metadata to prioritize findings and guide patching.
"""

from __future__ import annotations

import json
import os
import re
import time

# HTTP: prefer requests, fall back to urllib
try:
    import requests  # type: ignore

    _HAS_REQUESTS = True
except Exception:  # pragma: no cover
    _HAS_REQUESTS = False
    import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "vulnscan")
KEV_CACHE = os.path.join(CACHE_DIR, "kev.json")
KEV_TTL = 24 * 3600  # refresh KEV at most once/day

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

_kev_set: set[str] | None = None
_nvd_cache: dict[str, dict] = {}
_online = True  # flips to False after a failed fetch to avoid repeated hangs


def _http_json(url: str, timeout: int = 12):
    """Fetch JSON, or return None on any failure (offline-safe)."""
    global _online
    if not _online:
        return None
    headers = {"User-Agent": "vulnscan-cve-intel/1.0"}
    try:
        if _HAS_REQUESTS:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                return r.json()
            return None
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        # Network unavailable / rate-limited / DNS fail — go offline for the rest of the run.
        _online = False
        return None


def _load_kev() -> set[str]:
    """Load the CISA KEV catalog as a set of CVE ids. Cached on disk (1 day)."""
    global _kev_set
    if _kev_set is not None:
        return _kev_set

    # Disk cache
    try:
        if os.path.isfile(KEV_CACHE) and (time.time() - os.path.getmtime(KEV_CACHE)) < KEV_TTL:
            with open(KEV_CACHE) as fh:
                _kev_set = set(json.load(fh))
                return _kev_set
    except Exception:
        pass

    data = _http_json(KEV_URL, timeout=15)
    ids: set[str] = set()
    if data and isinstance(data, dict):
        for v in data.get("vulnerabilities", []):
            cid = v.get("cveID")
            if cid:
                ids.add(cid.upper())
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(KEV_CACHE, "w") as fh:
                json.dump(sorted(ids), fh)
        except Exception:
            pass
    _kev_set = ids
    return _kev_set


def is_actively_exploited(cve_id: str) -> bool:
    """True if the CVE is in the CISA Known Exploited Vulnerabilities catalog."""
    return cve_id.upper() in _load_kev()


def _nvd_lookup(cve_id: str) -> dict:
    cid = cve_id.upper()
    if cid in _nvd_cache:
        return _nvd_cache[cid]
    result = {"cvss": None, "severity": None, "summary": None}
    data = _http_json(NVD_URL.format(cid), timeout=12)
    try:
        vulns = data.get("vulnerabilities", []) if data else []
        if vulns:
            cve = vulns[0]["cve"]
            # description
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    result["summary"] = d.get("value")
                    break
            # CVSS (prefer v3.1 > v3.0 > v2)
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    m = metrics[key][0]["cvssData"]
                    result["cvss"] = m.get("baseScore")
                    result["severity"] = (m.get("baseSeverity")
                                          or _sev_from_score(result["cvss"])).lower() if result["cvss"] else None
                    break
    except Exception:
        pass
    _nvd_cache[cid] = result
    return result


def _sev_from_score(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"


def enrich(cve_id: str) -> dict:
    """
    Return intelligence for a CVE:
        { cve, kev(bool), cvss(float|None), severity(str|None), summary(str|None) }
    Fully offline-safe: fields are None when feeds are unreachable.
    """
    cid = cve_id.upper()
    kev = is_actively_exploited(cid)
    nvd = _nvd_lookup(cid)
    sev = nvd["severity"]
    if sev is None and nvd["cvss"] is not None:
        sev = _sev_from_score(nvd["cvss"])
    # KEV entries are, by definition, high-urgency regardless of base score.
    if kev and sev in (None, "low", "medium"):
        sev = "high"
    return {
        "cve": cid,
        "kev": kev,
        "cvss": nvd["cvss"],
        "severity": sev,
        "summary": nvd["summary"],
    }


def extract_cves(text: str) -> list[str]:
    """Pull unique CVE ids out of arbitrary tool output."""
    seen, out = set(), []
    for m in CVE_RE.findall(text or ""):
        u = m.upper()
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def describe(intel: dict) -> str:
    """Short human string for a report line."""
    bits = [intel["cve"]]
    if intel["cvss"] is not None:
        bits.append(f"CVSS {intel['cvss']}")
    if intel["severity"]:
        bits.append(intel["severity"].upper())
    if intel["kev"]:
        bits.append("ACTIVELY EXPLOITED (CISA KEV)")
    return " | ".join(bits)


def is_online() -> bool:
    return _online
