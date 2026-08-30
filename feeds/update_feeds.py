#!/usr/bin/env python3
"""
feeds/update_feeds.py — refresh overwatch's vulnerability data feeds.

This is the job a scheduler (GitHub Actions / cron / systemd timer) runs so the
scanner stays current WITHOUT any manual run — it only downloads public
vulnerability *data*, it never runs exploits.

What it refreshes into <repo>/data/:
  - kev.json          : CISA Known Exploited Vulnerabilities (actively-exploited)
  - nvd_recent.json   : recently modified CVEs from NVD (rolling window) with CVSS
  - manifest.json     : timestamps + counts (so you can see freshness at a glance)

And, if the tools are installed, it refreshes their local vuln databases:
  - nuclei -update-templates
  - trivy  --download-db-only
  - grype  db update

Everything is best-effort and offline-safe: a feed that fails to download leaves
the previous cached copy in place and is reported in the run summary.

Usage:
  python3 feeds/update_feeds.py            # refresh everything (default)
  python3 feeds/update_feeds.py --kev      # only CISA KEV
  python3 feeds/update_feeds.py --nvd-days 3
  python3 feeds/update_feeds.py --no-tools # skip nuclei/trivy/grype DB updates
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

try:
    import requests  # type: ignore

    _HAS_REQUESTS = True
except Exception:
    _HAS_REQUESTS = False
    import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(REPO_ROOT, "data")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_MOD_URL = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
               "?lastModStartDate={start}&lastModEndDate={end}&resultsPerPage=2000&startIndex={idx}")


def log(m: str) -> None:
    print(f"[feeds] {m}", flush=True)


def _get(url: str, timeout: int = 30):
    headers = {"User-Agent": "overwatch-feeds/1.0"}
    if _HAS_REQUESTS:
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _write(name: str, obj) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, name), "w") as fh:
        json.dump(obj, fh, indent=0, separators=(",", ":"))


def update_kev(summary: dict) -> None:
    try:
        data = _get(KEV_URL)
        ids = sorted({v["cveID"].upper() for v in data.get("vulnerabilities", []) if v.get("cveID")})
        _write("kev.json", ids)
        summary["kev"] = {"status": "ok", "count": len(ids)}
        log(f"KEV updated: {len(ids)} actively-exploited CVEs")
    except Exception as e:
        summary["kev"] = {"status": "failed", "error": str(e)[:120]}
        log(f"KEV update failed (keeping previous): {e}")


def update_nvd_recent(days: int, summary: dict) -> None:
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        idx, total, cves = 0, None, {}
        while True:
            url = NVD_MOD_URL.format(start=start.strftime(fmt), end=end.strftime(fmt), idx=idx)
            data = _get(url, timeout=40)
            total = data.get("totalResults", 0)
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                cid = cve["id"]
                score = sev = None
                metrics = cve.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(key):
                        cd = metrics[key][0]["cvssData"]
                        score = cd.get("baseScore")
                        sev = (cd.get("baseSeverity") or "").lower() or None
                        break
                cves[cid] = {"cvss": score, "severity": sev}
            idx += 2000
            if idx >= (total or 0):
                break
        _write("nvd_recent.json", cves)
        summary["nvd"] = {"status": "ok", "count": len(cves), "window_days": days}
        log(f"NVD recent updated: {len(cves)} CVEs (last {days}d)")
    except Exception as e:
        summary["nvd"] = {"status": "failed", "error": str(e)[:120]}
        log(f"NVD update failed (keeping previous): {e}")


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1200)
        return p.returncode == 0, p.stdout[-400:]
    except FileNotFoundError:
        return False, "not installed"
    except Exception as e:
        return False, str(e)[:200]


def update_tool_dbs(summary: dict) -> None:
    jobs = {
        "nuclei": ["nuclei", "-update-templates"],
        "trivy": ["trivy", "--download-db-only"],
        "grype": ["grype", "db", "update"],
    }
    out = {}
    for tool, cmd in jobs.items():
        if shutil.which(tool):
            okk, tail = _run(cmd)
            out[tool] = "updated" if okk else f"failed: {tail.strip()[:60]}"
            log(f"{tool} db: {out[tool]}")
        else:
            out[tool] = "not installed"
    summary["tool_dbs"] = out


def main() -> int:
    ap = argparse.ArgumentParser(description="Refresh overwatch vulnerability feeds.")
    ap.add_argument("--kev", action="store_true", help="update CISA KEV only")
    ap.add_argument("--nvd-days", type=int, default=7, help="NVD rolling window in days (default 7)")
    ap.add_argument("--no-nvd", action="store_true", help="skip NVD refresh")
    ap.add_argument("--no-tools", action="store_true", help="skip nuclei/trivy/grype DB updates")
    args = ap.parse_args()

    summary: dict = {"updated_at": datetime.now(timezone.utc).isoformat()}
    only_kev = args.kev

    update_kev(summary)
    if not only_kev and not args.no_nvd:
        update_nvd_recent(args.nvd_days, summary)
    if not only_kev and not args.no_tools:
        update_tool_dbs(summary)

    _write("manifest.json", summary)
    log("manifest written to data/manifest.json")
    # Exit non-zero only if EVERYTHING failed (so CI can alert), else success.
    feed_states = [v.get("status") for k, v in summary.items() if isinstance(v, dict) and "status" in v]
    if feed_states and all(s == "failed" for s in feed_states):
        log("all feed downloads failed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
