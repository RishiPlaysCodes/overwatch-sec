#!/usr/bin/env python3
"""
core/scope.py — bug-bounty-grade scope enforcement.

A Scope decides whether a discovered asset (host / IP / URL) is allowed to be
tested. It supports:
  - exact domains          example.com
  - wildcards              *.example.com
  - IPs and CIDRs          10.0.0.5 , 192.168.0.0/16
  - explicit exclusions    !admin.example.com , !10.0.0.1
  - URL/path prefixes      https://example.com/api/

The golden rule (spec §3): never automatically expand outside scope. If no
scope is supplied, only the primary target's own apex is in scope.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


def _host_of(asset: str) -> str:
    a = asset.strip()
    if "://" in a:
        return (urlparse(a).hostname or "").lower()
    return a.split("/")[0].split(":")[0].lower()


class Scope:
    def __init__(self, allowed: list[str] | None = None, excluded: list[str] | None = None):
        self.allowed_domains: list[str] = []
        self.allowed_wildcards: list[str] = []
        self.allowed_nets: list[ipaddress._BaseNetwork] = []
        self.allowed_urls: list[str] = []
        self.excluded_domains: list[str] = []
        self.excluded_wildcards: list[str] = []
        self.excluded_nets: list[ipaddress._BaseNetwork] = []
        for item in (allowed or []):
            self._add(item, excluded=item.startswith("!"))
        for item in (excluded or []):
            self._add(item, excluded=True)

    # ---- construction -----------------------------------------------------
    def _add(self, item: str, excluded: bool) -> None:
        item = item.strip()
        if not item or item.startswith("#"):
            return
        if item.startswith("!"):
            item, excluded = item[1:].strip(), True
        if item.startswith("http://") or item.startswith("https://"):
            (self.excluded_domains if excluded else self.allowed_urls).append(item.rstrip("/") if not excluded else _host_of(item))
            if not excluded:
                return
        # CIDR / IP
        try:
            net = ipaddress.ip_network(item, strict=False)
            (self.excluded_nets if excluded else self.allowed_nets).append(net)
            return
        except ValueError:
            pass
        low = item.lower().lstrip("*.")
        if item.startswith("*."):
            (self.excluded_wildcards if excluded else self.allowed_wildcards).append(low)
        else:
            (self.excluded_domains if excluded else self.allowed_domains).append(low)

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        allowed: list[str] = []
        try:
            with open(path, "r", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        allowed.append(line)
        except Exception:
            pass
        return cls(allowed=allowed)

    @classmethod
    def single(cls, target: str) -> "Scope":
        """Default scope: just the target's own apex/host (never auto-expand)."""
        host = _host_of(target) or target
        # allow the apex and its subdomains
        parts = host.split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else host
        return cls(allowed=[apex, f"*.{apex}"]) if apex else cls(allowed=[host])

    def is_empty(self) -> bool:
        return not (self.allowed_domains or self.allowed_wildcards or self.allowed_nets or self.allowed_urls)

    # ---- decisions --------------------------------------------------------
    def _match_nets(self, host: str, nets) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in n for n in nets)

    def _excluded(self, host: str) -> bool:
        if host in self.excluded_domains:
            return True
        if any(host == w or host.endswith("." + w) for w in self.excluded_wildcards):
            return True
        if self._match_nets(host, self.excluded_nets):
            return True
        return False

    def allows(self, asset: str) -> bool:
        host = _host_of(asset)
        if not host:
            return False
        if self._excluded(host):
            return False
        if self.is_empty():
            return True  # no allow-list configured => permissive (single-target default sets one)
        if host in self.allowed_domains:
            return True
        if any(host == w or host.endswith("." + w) for w in self.allowed_wildcards):
            return True
        if self._match_nets(host, self.allowed_nets):
            return True
        if any(asset.rstrip("/").startswith(u) for u in self.allowed_urls):
            return True
        return False

    def filter(self, assets: list[str]) -> tuple[list[str], list[str]]:
        """Return (in_scope, out_of_scope)."""
        ins, outs = [], []
        for a in assets:
            (ins if self.allows(a) else outs).append(a)
        return ins, outs

    def describe(self) -> str:
        parts = []
        if self.allowed_domains:
            parts.append("domains=" + ",".join(self.allowed_domains))
        if self.allowed_wildcards:
            parts.append("wildcards=" + ",".join("*." + w for w in self.allowed_wildcards))
        if self.allowed_nets:
            parts.append("nets=" + ",".join(str(n) for n in self.allowed_nets))
        excl = self.excluded_domains + ["*." + w for w in self.excluded_wildcards] + [str(n) for n in self.excluded_nets]
        if excl:
            parts.append("excluded=" + ",".join(excl))
        return "; ".join(parts) or "(permissive)"
