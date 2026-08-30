#!/usr/bin/env python3
"""
core/plugins.py — lightweight plugin loader (spec §31 extensibility).

Drop a `*.py` file in the `plugins/` directory that defines a `register(reg)`
function. On load it receives a Registry object and can add:

    reg.add_scanner(kind, scanner_module_name)      # new target kind -> scanner
    reg.add_mitre(finding_id_prefix, technique_tuple)
    reg.add_validator(finding_id_prefix, callable)
    reg.add_objective(finding_id_prefix, (name, criticality, pivots))

This lets new techniques/target-types be added WITHOUT touching the core engine
— which is the whole point: the platform is continuously extensible, not a fixed
list that goes stale.
"""

from __future__ import annotations

import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGINS_DIR = os.path.join(ROOT, "plugins")


class Registry:
    def __init__(self):
        self.loaded: list[str] = []

    def add_scanner(self, kind: str, scanner_module: str):
        from .target_detector import KIND_TO_SCANNER
        KIND_TO_SCANNER[kind] = scanner_module

    def add_mitre(self, prefix: str, technique: tuple):
        from attack_paths import mitre
        mitre.TECHNIQUE_MAP[prefix] = technique

    def add_validator(self, prefix: str, fn):
        from validation import validator
        validator.register(prefix, fn)

    def add_objective(self, prefix: str, objective: tuple):
        from attack_paths import graph
        graph.OBJECTIVES[prefix] = objective

    def add_capability(self, tool):
        from . import capabilities
        capabilities.REGISTRY.append(tool)


def load_plugins(directory: str | None = None) -> list[str]:
    """Import every plugins/*.py and call its register(reg). Returns loaded names."""
    directory = directory or PLUGINS_DIR
    reg = Registry()
    if not os.path.isdir(directory):
        return []
    for fname in sorted(os.listdir(directory)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(directory, fname)
        try:
            spec = importlib.util.spec_from_file_location(f"vulnscan_plugin_{fname[:-3]}", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)   # type: ignore
            if hasattr(mod, "register"):
                mod.register(reg)
                reg.loaded.append(fname)
        except Exception as e:  # a broken plugin must never break the engine
            print(f"[plugins] failed to load {fname}: {e}")
    return reg.loaded
