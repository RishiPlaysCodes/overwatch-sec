#!/usr/bin/env python3
"""
core/config.py — profile & policy loading with a no-hard-dependency fallback.

Profiles (what to scan / how deep) live in profiles/*.yaml and policies (what's
allowed / safety) in policies/*.yaml. Loading is resilient:
  1. if PyYAML is installed, parse the YAML file;
  2. else, a tiny built-in flat-YAML reader handles our simple key: value files;
  3. and if a file is missing entirely, safe Python defaults are used.

So the platform runs correctly even on a machine without PyYAML.
"""

from __future__ import annotations

import os

from .policy import Policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES_DIR = os.path.join(ROOT, "profiles")
POLICIES_DIR = os.path.join(ROOT, "policies")

try:
    import yaml  # type: ignore

    _HAS_YAML = True
except Exception:
    _HAS_YAML = False


# ---- built-in defaults (used when files are absent) -----------------------
DEFAULT_PROFILES = {
    "bugbounty": {"mode": "fast", "scanners": ["recon", "web", "api"], "scope_required": True},
    "redteam":   {"mode": "deep", "scanners": ["recon", "web", "network", "cloud"], "scope_required": True},
    "enterprise":{"mode": "deep", "scanners": ["recon", "web", "network", "cloud", "code", "container"]},
    "web":       {"mode": "fast", "scanners": ["web", "api"]},
    "mobile":    {"mode": "fast", "scanners": ["mobile"]},
    "cloud":     {"mode": "fast", "scanners": ["cloud"]},
    "network":   {"mode": "fast", "scanners": ["network"]},
    "code":      {"mode": "fast", "scanners": ["code"]},
}


def _tiny_yaml(text: str) -> dict:
    """
    Minimal parser for our simple YAML (key: value, indent-nested maps, and
    `- item` block lists). Not a general YAML parser — only for our own files.
    Correctly distinguishes an empty-valued key that becomes a *list* (followed
    by `- items`) from one that becomes a nested *map*.
    """
    root: dict = {}
    stack = [(-1, root)]          # (indent, container)
    pending = None                # (indent, key, parent_container) awaiting list/map
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        if line.startswith("- "):
            # a block-list item belongs to the most recent empty-valued key
            if pending is not None:
                _, pkey, pcont = pending
                lst = pcont.get(pkey)
                if not isinstance(lst, list):
                    lst = []
                    pcont[pkey] = lst
                lst.append(_coerce(_strip_inline_comment(line[2:].strip())))
            continue

        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), _strip_inline_comment(val.strip())

        # descend to the correct parent for this indent
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if val == "":
            new: dict = {}
            parent[key] = new                 # provisional map (may become list)
            stack.append((indent, new))
            pending = (indent, key, parent)
        else:
            parent[key] = _coerce(val)
            pending = None
    return root


def _strip_inline_comment(v: str) -> str:
    """Remove a trailing ' # comment' from an unquoted scalar value."""
    if not v or v[0] in "\"'":
        return v
    # cut at the first '#' that follows whitespace (or starts the token)
    for i, ch in enumerate(v):
        if ch == "#" and (i == 0 or v[i - 1] in " \t"):
            return v[:i].strip()
    return v


def _coerce(v: str):
    low = v.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "none", "~", ""):
        return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v.strip('"\'')


def _load_yaml_file(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r") as fh:
            text = fh.read()
        if _HAS_YAML:
            return yaml.safe_load(text) or {}
        return _tiny_yaml(text)
    except Exception:
        return {}


def load_profile(name: str) -> dict:
    name = (name or "bugbounty").lower()
    data = _load_yaml_file(os.path.join(PROFILES_DIR, f"{name}.yaml"))
    if not data:
        data = DEFAULT_PROFILES.get(name, DEFAULT_PROFILES["bugbounty"]).copy()
        data["name"] = name
    data.setdefault("name", name)
    return data


def load_policy(profile: str, mode: str, policy_file: str | None = None) -> Policy:
    """Policy precedence: explicit --policy file > profile's policy yaml > safe preset."""
    if policy_file:
        d = _load_yaml_file(policy_file)
        if d:
            return Policy.from_dict(d)
    d = _load_yaml_file(os.path.join(POLICIES_DIR, f"{profile}.yaml"))
    if d:
        p = Policy.from_dict(d)
        # mode can still tighten/loosen validation within policy bounds
        if mode == "fast" and profile in ("bugbounty", "web", "mobile", "cloud", "network", "code"):
            p.validation = False
        return p
    return Policy.for_profile(profile, mode)


def list_profiles() -> list[str]:
    names = set(DEFAULT_PROFILES)
    if os.path.isdir(PROFILES_DIR):
        for f in os.listdir(PROFILES_DIR):
            if f.endswith(".yaml"):
                names.add(f[:-5])
    return sorted(names)
