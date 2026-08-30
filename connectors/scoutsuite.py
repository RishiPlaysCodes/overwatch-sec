#!/usr/bin/env python3
"""
connectors/scoutsuite.py — ScoutSuite report -> vulnscan threat data.

ScoutSuite emits a big JSON of cloud config + flagged items per service. We
extract the security-relevant bits into the threat_detection input shape:
    {"access_keys":[...], "accounts":[...]}
and also surface obvious risky items. Pure parser (offline).
"""

from __future__ import annotations


def looks_like(raw) -> bool:
    return isinstance(raw, dict) and ("services" in raw or "account_id" in raw or "last_run" in raw)


def to_threat(raw) -> dict:
    out = {"access_keys": [], "accounts": [], "listening": [], "processes": [], "connections": []}
    services = raw.get("services", {}) if isinstance(raw, dict) else {}

    iam = services.get("iam", {}) if isinstance(services, dict) else {}
    # access keys
    for uid, user in (iam.get("users", {}) or {}).items():
        for kid, key in (user.get("access_keys", {}) or {}).items() if isinstance(user.get("access_keys"), dict) else []:
            out["access_keys"].append({
                "id": key.get("id", kid),
                "age_days": key.get("age_days", 0),
                "last_used": key.get("LastUsedDate") or key.get("last_used"),
                "admin": bool(user.get("is_admin") or user.get("admin")),
            })
        # unexpected/over-privileged users
        if user.get("is_admin") and not user.get("mfa_active", True):
            out["accounts"].append({"name": user.get("name", uid), "privileged": True,
                                    "unexpected": True, "uid": None})
    return out
