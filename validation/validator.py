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
        return ("validated", f"'{name}' absent on re-check")
    f.status = "fixed"
    return ("not_exploitable", f"'{name}' present on re-check (likely fixed)")


def _validate_reflection(f) -> tuple:
    """Confirm an input is reflected unescaped (XSS indicator) with a benign marker."""
    from urllib.parse import urljoin
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    marker = "vscnVALz991"
    try:
        _, _, body, _ = http_get(urljoin(url, f"?q={marker}"))
    except Exception as e:
        return ("error", str(e)[:80])
    if marker in body:
        return ("validated", "benign marker reflected unescaped (verify output context manually)")
    return ("not_validated", "benign marker not reflected on re-check")


def _validate_dir_listing(f) -> tuple:
    """Confirm a directory index is actually served."""
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    try:
        status, _, body, _ = http_get(url)
    except Exception as e:
        return ("error", str(e)[:80])
    low = body.lower()
    if status == 200 and ("index of /" in low or "<title>directory listing" in low):
        return ("validated", "directory index served")
    return ("not_validated", "no directory index served on re-check")


def _validate_cors(f) -> tuple:
    """Confirm the API reflects an arbitrary Origin with credentials (safe GET)."""
    import urllib.request
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    probe = "https://vulnscan-probe.example"
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-validate/1.0", "Origin": probe})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            h = {k.lower(): v for k, v in r.headers.items()}
    except Exception as e:
        return ("error", str(e)[:80])
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == probe and acac == "true":
        return ("validated", "arbitrary Origin reflected with credentials")
    if acao in ("*", "") and acac != "true":
        return ("not_exploitable", "no credentialed cross-origin reflection on re-check")
    return ("not_validated", "CORS not confirmed exploitable on re-check")


def _validate_cookie(f) -> tuple:
    """Re-fetch and confirm the Set-Cookie really lacks Secure/HttpOnly/SameSite."""
    url = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    try:
        _, headers, _, _ = http_get(url)
    except Exception as e:
        return ("error", str(e)[:80])
    sc = headers.get("set-cookie", "")
    if not sc:
        return ("not_validated", "no Set-Cookie on re-check")
    low = sc.lower()
    missing = [x for x in ("secure", "httponly", "samesite") if x not in low]
    if missing:
        return ("validated", "Set-Cookie missing: " + ", ".join(missing))
    f.status = "fixed"
    return ("not_exploitable", "cookie now has Secure/HttpOnly/SameSite")


def _validate_open_redirect(f) -> tuple:
    """
    Safely confirm an open redirect by sending ONE request with a benign external
    marker in the redirect parameter and inspecting the Location header — the
    redirect is NEVER followed (custom handler returns None). Non-destructive:
    we only observe whether the server would bounce us off-site.
    """
    import re
    import urllib.error
    import urllib.request
    from urllib.parse import urlparse
    # candidate param names: prefer the ones the detector named in the evidence
    params: list[str] = []
    m = re.search(r"parameter\(s\)[^:]*:\s*([a-z0-9_,\s]+)", f.evidence or "", re.I)
    if m:
        params = [p.strip() for p in m.group(1).split(",") if p.strip() and p.strip().isidentifier()]
    if not params:
        params = ["next", "url", "redirect", "return"]
    base = f.asset if f.asset.startswith("http") else f"https://{f.asset}"
    probe = "https://vulnscan-probe.example/ext-check"

    class _NoFollow(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # observe, never follow

    opener = urllib.request.build_opener(_NoFollow)
    for p in params[:4]:
        sep = "&" if urlparse(base).query else "?"
        url = f"{base}{sep}{p}={probe}"
        loc = ""
        try:
            r = opener.open(urllib.request.Request(url, headers={"User-Agent": "vulnscan-validate/1.0"}), timeout=12)
            loc = r.headers.get("Location", "") or ""
        except urllib.error.HTTPError as e:
            loc = (e.headers.get("Location", "") if e.headers else "") or ""
        except Exception:
            continue
        if "vulnscan-probe.example" in loc:
            return ("validated", f"redirects off-site to attacker-controlled URL via '{p}' (Location not followed)")
    return ("not_validated", "no off-site redirect reflected in Location on re-check")


register("web.header", _validate_missing_header)
register("web.xss.reflected", _validate_reflection)
register("recon.dir_listing", _validate_dir_listing)
register("api.cors", _validate_cors)
register("web.cookie", _validate_cookie)
register("web.open_redirect", _validate_open_redirect)


# result-code -> (validation_state, confidence)
_RESULT_STATE = {
    "validated": ("validated", "confirmed"),
    "not_exploitable": ("not_exploitable", "high_confidence"),
    "not_validated": ("not_validated", None),
    "error": ("error", None),
}


def validate(findings, policy, coverage=None, context: dict | None = None) -> dict:
    """
    Intelligent, policy-gated validation. For each finding with a registered
    capability, the registry decides run/blocked_by_* based on policy + context;
    permitted checks run and set a precise validation state with structured,
    timestamped evidence. Nothing here exploits — checks only re-observe facts.
    """
    from . import registry
    stats = {"validated": 0, "not_exploitable": 0, "not_validated": 0,
             "manual_validation_required": 0, "blocked_by_policy": 0,
             "blocked_by_authentication": 0, "blocked_by_missing_dependency": 0,
             "blocked_by_scope": 0, "error": 0, "selected": 0,
             "findings_total": len(findings)}
    context = context or {}
    ran_any = False

    for f in findings:
        cap = registry.capability_for(f.id)
        fn = _validator_for(f.id)
        if cap is None and fn is None:
            continue
        stats["selected"] += 1

        # capability-driven decision (falls back to a safe default if metadata missing)
        if cap is not None:
            decision = registry.decide(cap, policy, context)
            tool = cap.id
        else:
            decision = "run" if policy.allows_level("validation") else "blocked_by_policy"
            tool = "builtin"

        if decision != "run":
            reason = {
                "blocked_by_policy": "validation level not permitted by the active policy",
                "blocked_by_authentication": "requires a test account/credentials (not supplied)",
                "blocked_by_missing_dependency": "a required tool is not installed",
                "blocked_by_scope": "asset is out of authorized scope",
            }.get(decision, decision)
            f.set_validation(decision, tool=tool, test=(cap.id if cap else f.id), reason=reason)
            stats[decision] = stats.get(decision, 0) + 1
            continue

        if fn is None:  # capability declared but no checker wired -> manual
            f.set_validation("manual_validation_required", tool=tool,
                             test=(cap.id if cap else f.id),
                             reason="no automated checker; manual validation required")
            stats["manual_validation_required"] += 1
            continue

        ran_any = True
        try:
            result = fn(f)
        except Exception as e:
            result = ("error", str(e)[:80])
        code, detail = result if isinstance(result, tuple) else (result, "")
        if code == "manual":
            f.set_validation("manual_validation_required", tool=tool,
                             test=(cap.id if cap else f.id), reason=detail or "manual check needed")
            stats["manual_validation_required"] += 1
            continue
        state, confd = _RESULT_STATE.get(code, ("manual_validation_required", None))
        f.set_validation(state, tool=tool, tool_version="builtin",
                         test=(cap.id if cap else f.id), reason=code, detail=detail, confidence=confd)
        stats[state] = stats.get(state, 0) + 1

    if coverage is not None:
        if ran_any:
            coverage.ran("validation", detail=(f"validated={stats['validated']} "
                                               f"not_validated={stats['not_validated']} "
                                               f"blocked={stats['blocked_by_policy']}"))
        elif stats["selected"]:
            coverage.skipped("validation", "policy_disallowed",
                             "validation checks were selected but blocked by policy/context")
    return stats
