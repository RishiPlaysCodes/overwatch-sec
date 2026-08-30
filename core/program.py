#!/usr/bin/env python3
"""
core/program.py — bug-bounty PROGRAM configuration.

One file describes a program's rules; the bug-bounty profile then auto-respects
them so the operator only has to point at a target. A program config captures:

  scope:        in-scope hosts/domains/CIDRs (wildcards + '!' exclusions)
  out_of_scope: extra out-of-scope patterns (host-level)
  headers:      required request headers (e.g. X-Request-Purpose)  -> sent on ALL traffic
  rate_per_min: polite request rate cap                             -> throttles traffic
  exclude_findings: finding-id patterns the program declares OUT OF SCOPE / not rewarded
                    (e.g. web.header*, web.cookie*, web.tls*, availability*, recon.waf) —
                    the engine keeps them but marks them out-of-scope so they don't
                    pollute the actionable results.
  focus_findings:  finding-id patterns the program is especially interested in.
  notes:        free text shown in the banner.

Loads YAML if PyYAML is present, else the built-in tiny-yaml (see core.config).
So `overwatch <target> --program programs/foo.yaml` is all the operator needs.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field

from .config import _load_yaml_file
from .scope import Scope

# common bug-bounty "won't pay / noise" finding families used as a default when a
# program doesn't list its own exclusions (matches typical VDP/OOS language).
DEFAULT_OOS_PATTERNS = (
    "web.header*", "web.cookie*", "web.tls*", "web.infoleak*",
    "availability*", "recon.waf*",
)


@dataclass
class Program:
    name: str = "program"
    scope: Scope = field(default_factory=lambda: Scope())
    headers: dict = field(default_factory=dict)
    rate_per_min: int = 0
    exclude_findings: tuple = ()
    focus_findings: tuple = ()
    notes: str = ""

    # ---- finding classification ------------------------------------------
    def is_out_of_scope_finding(self, finding_id: str) -> bool:
        return any(fnmatch.fnmatch(finding_id, pat) for pat in self.exclude_findings)

    def is_focus_finding(self, finding_id: str) -> bool:
        return any(fnmatch.fnmatch(finding_id, pat) for pat in self.focus_findings)

    def summary(self) -> str:
        bits = [f"program={self.name}", f"scope=[{self.scope.describe()}]"]
        if self.headers:
            bits.append("headers=" + ",".join(self.headers))
        if self.rate_per_min:
            bits.append(f"rate<={self.rate_per_min}/min")
        if self.exclude_findings:
            bits.append(f"oos-findings={len(self.exclude_findings)}")
        return " ".join(bits)


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [s.strip() for s in str(v).splitlines() if s.strip()]


def load(path: str) -> Program | None:
    """Load a program config from YAML (or a plain scope .txt as a minimal program)."""
    if not path or not os.path.isfile(path):
        return None

    # plain text file => treat every non-comment line as an in-scope entry
    if path.lower().endswith(".txt"):
        return Program(name=os.path.basename(path), scope=Scope.from_file(path),
                       exclude_findings=DEFAULT_OOS_PATTERNS)

    d = _load_yaml_file(path) or {}
    allowed = _as_list(d.get("scope")) or _as_list((d.get("targets") or {}))
    excluded = _as_list(d.get("out_of_scope"))
    scope = Scope(allowed=allowed, excluded=excluded) if (allowed or excluded) else Scope()
    headers = d.get("headers") or {}
    if isinstance(headers, list):  # ["K: V", ...] form
        parsed = {}
        for h in headers:
            if ":" in str(h):
                k, _, v = str(h).partition(":")
                parsed[k.strip()] = v.strip()
        headers = parsed
    excl = tuple(_as_list(d.get("exclude_findings"))) or DEFAULT_OOS_PATTERNS
    return Program(
        name=str(d.get("name", os.path.basename(path))),
        scope=scope,
        headers={str(k): str(v) for k, v in (headers or {}).items()},
        rate_per_min=int(d.get("rate_per_min", 0) or 0),
        exclude_findings=excl,
        focus_findings=tuple(_as_list(d.get("focus_findings"))),
        notes=str(d.get("notes", "")),
    )


def apply_to_request_context(program: Program) -> None:
    """Push the program's headers + rate limit into the global request context."""
    from common import set_request_context
    set_request_context(program.headers, program.rate_per_min or None)
