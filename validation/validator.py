#!/usr/bin/env python3
"""
validation/validator.py — safe, policy-gated finding validators.

Each validator performs a NON-DESTRUCTIVE re-check to confirm (or refute) a
finding, then updates its validation state + confidence. Nothing here exploits:
we only re-observe deterministic facts. Validators run only when the Policy
permits the "validation" safety level; otherwise findings are annotated
"manual validation required".

Registry maps a finding-id prefix -> validator callable(finding) -> str result:
    "validated" | "not_exploitable" | "manual" | "skipped"

Extensible: plugins can register more validators via register().
"""

from __future__ import annotations

from . import confidence as conf

try:
    from common import http_get
except Exception:  # minimal fallback
    def http_get(url, timeout=15):
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-validate/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "replace"), None


_REGISTRY: dict = {}


def register(prefix: str, fn) -> None:
    _REGISTRY[prefix] = fn


def _validator_for(fid: str):
    if fid in _REGISTRY:
        return _REGISTRY[fid]
    for k, fn in _REGISTRY.items():
        if fid.startswith(k):
            return fn
    return None


# ---------------------------------------------------------------------------
# built-in safe validators
# ---------------------------------------------------------------------------
def _validate_missing_header(f) -> str:
    """Confirm a security header really is absent by re-requesting the asset."""
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    header = f.id.split(".")[-1]  # e.g. web.header.csp -> csp
    name = {"csp": "content-security-policy", "hsts": "strict-transport-security",
            "xfo": "x-frame-options", "nosniff": "x-content-type-options",
            "referrer": "referrer-policy", "permissions": "permissions-policy"}.get(header)
    if not name:
        return "manual"
    try:
        _, headers, _, _ = http_get(url)
    except Exception:
        return "manual"
    if name not in headers:
        conf.mark_validated(f, f"'{name}' absent on re-check")
        return "validated"
    conf.mark_not_exploitable(f, f"'{name}' present on re-check (likely fixed)")
    f.status = "fixed"
    return "not_exploitable"


def _validate_reflection(f) -> str:
    """Confirm an input is reflected unescaped (XSS indicator) with a benign marker."""
    from urllib.parse import urljoin
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    marker = "vscnVALz991"
    try:
        _, _, body, _ = http_get(urljoin(url, f"?q={marker}"))
    except Exception:
        return "manual"
    if marker in body:
        conf.mark_validated(f, "benign marker reflected unescaped (verify output context manually)")
        return "validated"
    return "manual"


def _validate_dir_listing(f) -> str:
    """Confirm a directory index is actually served."""
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    try:
        status, _, body, _ = http_get(url)
    except Exception:
        return "manual"
    low = body.lower()
    if status == 200 and ("index of /" in low or "<title>directory listing" in low):
        conf.mark_validated(f, "directory index served")
        return "validated"
    return "manual"


def _validate_cors(f) -> str:
    """Confirm the API reflects an arbitrary Origin with credentials (safe GET)."""
    import urllib.request
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    probe = "https://vulnscan-probe.example"
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-validate/1.0", "Origin": probe})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            h = {k.lower(): v for k, v in r.headers.items()}
    except Exception:
        return "manual"
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == probe and acac == "true":
        conf.mark_validated(f, "arbitrary Origin reflected with credentials")
        return "validated"
    if acao in ("*", "") and acac != "true":
        conf.mark_not_exploitable(f, "no credentialed cross-origin reflection on re-check")
        return "not_exploitable"
    return "manual"


def _validate_cookie(f) -> str:
    """Re-fetch and confirm the Set-Cookie really lacks Secure/HttpOnly/SameSite."""
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    try:
        _, headers, _, _ = http_get(url)
    except Exception:
        return "manual"
    sc = headers.get("set-cookie", "")
    if not sc:
        return "manual"
    low = sc.lower()
    missing = [x for x in ("secure", "httponly", "samesite") if x not in low]
    if missing:
        conf.mark_validated(f, "Set-Cookie missing: " + ", ".join(missing))
        return "validated"
    conf.mark_not_exploitable(f, "cookie now has Secure/HttpOnly/SameSite")
    f.status = "fixed"
    return "not_exploitable"


register("web.header", _validate_missing_header)
register("web.xss.reflected", _validate_reflection)
register("recon.dir_listing", _validate_dir_listing)
register("api.cors", _validate_cors)
register("web.cookie", _validate_cookie)


# ---------------------------------------------------------------------------
def validate(findings, policy, coverage=None) -> dict:
    """
    Run safe validators over findings IF the policy permits validation.
    Returns counts and annotates findings in place.
    """
    stats = {"validated": 0, "not_exploitable": 0, "manual": 0, "skipped": 0}
    allowed = policy.allows_level("validation")
    for f in findings:
        fn = _validator_for(f.id)
        if fn is None:
            continue
        if not allowed:
            conf.mark_manual(f)
            stats["manual"] += 1
            continue
        try:
            result = fn(f)
        except Exception:
            result = "manual"
        if result == "validated":
            stats["validated"] += 1
        elif result == "not_exploitable":
            stats["not_exploitable"] += 1
        elif result == "manual":
            conf.mark_manual(f)
            stats["manual"] += 1
        else:
            stats["skipped"] += 1
    if coverage is not None:
        if allowed:
            coverage.ran("validation", detail=f"validated={stats['validated']} "
                                              f"not_exploitable={stats['not_exploitable']}")
        else:
            coverage.skipped("validation", "policy_disallowed",
                             "validation level not permitted by policy")
    return stats
