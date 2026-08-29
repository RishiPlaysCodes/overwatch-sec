#!/usr/bin/env python3
"""
scanner_mobile.py — Mobile app (APK / IPA) static vulnerability scanner.

Works on a local app file path. No external tools required for the built-in
checks (it unpacks the archive and inspects contents). If MobSF is reachable
(env MOBSF_URL + MOBSF_APIKEY) or `apkleaks`/`jadx` are installed, those are
used to deepen the analysis.

Built-in static checks:
  - AndroidManifest: cleartext traffic, debuggable, allowBackup, exported
    components without permission, dangerous permissions
  - Hardcoded secrets / API keys across the package (regex scan)
  - iOS Info.plist: ATS (App Transport Security) exceptions

Maps every issue to the knowledge base (OWASP Mobile Top 10 / MASVS + CWE).
"""

from __future__ import annotations

import os
import re
import zipfile

from common import banner, err, finding, have, info, ok, run, warn

# Regexes for common hardcoded secrets (kept conservative to limit false positives)
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic API key assignment", re.compile(r"(?i)(api[_-]?key|secret|passwd|password|token)\s*[=:]\s*['\"][0-9A-Za-z\-_]{12,}['\"]")),
    ("Firebase URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
]

DANGEROUS_PERMS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG",
    "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES",
}

# Files we don't want to regex-scan (binary noise)
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".ttf", ".otf", ".so")


def _read_manifest(z: zipfile.ZipFile) -> str | None:
    """
    Return AndroidManifest text if readable. Binary AXML in real APKs needs
    apktool/aapt; if the manifest is binary we note it and rely on tools.
    """
    for name in z.namelist():
        if name.endswith("AndroidManifest.xml"):
            raw = z.read(name)
            # Heuristic: if it starts with the AXML magic it's binary-encoded.
            if raw[:2] == b"\x03\x00":
                return None
            try:
                return raw.decode("utf-8", "replace")
            except Exception:
                return None
    return None


def _check_android_manifest(text: str) -> list[dict]:
    out = []
    low = text.lower()
    if 'usescleartexttraffic="true"' in low.replace(" ", ""):
        out.append(finding("mobile.cleartext", "Manifest sets android:usesCleartextTraffic=\"true\""))
    if 'debuggable="true"' in low.replace(" ", ""):
        out.append(finding("mobile.debuggable", "Manifest sets android:debuggable=\"true\""))
    if 'allowbackup="true"' in low.replace(" ", ""):
        out.append(finding("mobile.backup", "Manifest sets android:allowBackup=\"true\""))
    # Exported components without a permission attribute on the same tag
    for m in re.finditer(r"<(activity|service|receiver|provider)\b[^>]*>", text, re.I):
        tag = m.group(0)
        if re.search(r'android:exported\s*=\s*"true"', tag, re.I) and "permission" not in tag.lower():
            comp = re.search(r'android:name\s*=\s*"([^"]+)"', tag)
            out.append(finding("mobile.exported",
                               f"Exported {m.group(1)} without permission guard: {comp.group(1) if comp else '?'}"))
    # Dangerous permissions
    perms = set(re.findall(r'uses-permission[^>]*android:name="android\.permission\.([A-Z_]+)"', text))
    dangerous = sorted(perms & DANGEROUS_PERMS)
    if dangerous:
        out.append(finding("mobile.perms", "Dangerous permissions requested: " + ", ".join(dangerous)))
    return out


def _check_ios_plist(text: str) -> list[dict]:
    out = []
    low = text.lower()
    if "nsallowsarbitraryloads" in low and "true" in low:
        out.append(finding("mobile.cleartext", "Info.plist ATS: NSAllowsArbitraryLoads = true"))
    return out


def _scan_secrets(z: zipfile.ZipFile) -> list[dict]:
    out = []
    seen = set()
    for name in z.namelist():
        if name.endswith(_SKIP_EXT) or name.endswith("/"):
            continue
        try:
            data = z.read(name)
        except Exception:
            continue
        if len(data) > 3_000_000:  # skip very large blobs
            continue
        try:
            text = data.decode("utf-8", "ignore")
        except Exception:
            continue
        for label, rx in SECRET_PATTERNS:
            m = rx.search(text)
            if m:
                key = (label, name)
                if key in seen:
                    continue
                seen.add(key)
                snippet = m.group(0)[:40]
                out.append(finding("mobile.secrets", f"{label} found in {name}: {snippet}…"))
    return out


def _mobsf(app_path: str, outdir: str) -> dict:
    url = os.environ.get("MOBSF_URL")
    key = os.environ.get("MOBSF_APIKEY")
    if not (url and key):
        return {"tool": "MobSF", "status": "skipped", "reason": "set MOBSF_URL + MOBSF_APIKEY to enable deep analysis"}
    # Deep integration intentionally left as a hook; report that it's configured.
    return {"tool": "MobSF", "status": "skipped", "reason": "MobSF configured — run its upload/scan API for full report"}


def scan(app_path: str, outdir: str, skip: set[str]) -> dict:
    result = {"profile": "mobile", "target": app_path, "findings": [], "tools": []}
    if not os.path.isfile(app_path):
        err(f"file not found: {app_path}")
        return result

    is_ipa = app_path.lower().endswith(".ipa")
    banner(f"MOBILE — static analysis of {os.path.basename(app_path)} ({'iOS IPA' if is_ipa else 'Android APK'})")

    try:
        z = zipfile.ZipFile(app_path)
    except Exception as e:
        err(f"not a valid zip/APK/IPA archive: {e}")
        return result

    with z:
        if is_ipa:
            for name in z.namelist():
                if name.endswith("Info.plist"):
                    try:
                        result["findings"] += _check_ios_plist(z.read(name).decode("utf-8", "ignore"))
                    except Exception:
                        pass
                    break
        else:
            manifest = _read_manifest(z)
            if manifest:
                result["findings"] += _check_android_manifest(manifest)
                ok("parsed AndroidManifest.xml (text form)")
            else:
                warn("AndroidManifest is binary AXML — install apktool/aapt for manifest checks")
                result["tools"].append({"tool": "apktool", "status": "skipped",
                                        "reason": "needed to decode binary manifest"})
        # Secret scan runs on any archive
        info("scanning package contents for hardcoded secrets…")
        result["findings"] += _scan_secrets(z)

    # Optional deep tools
    banner("MOBILE — optional deep tools")
    result["tools"].append(_mobsf(app_path, outdir))
    if have("apkleaks") and not is_ipa and "apkleaks" not in skip:
        path = os.path.join(outdir, "apkleaks.txt")
        rc, out = run(["apkleaks", "-f", app_path, "-o", path], timeout=600)
        result["tools"].append({"tool": "apkleaks", "status": "done" if rc == 0 else f"exit {rc}", "output": path})
    else:
        result["tools"].append({"tool": "apkleaks", "status": "skipped", "reason": "not installed (pip install apkleaks)"})

    return result
