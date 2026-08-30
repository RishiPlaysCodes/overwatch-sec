"""
core — the platform engine for vulnscan.

This package holds the target-agnostic brain of the assessment platform:

  findings        unified Finding model (severity / confidence / status / MITRE)
  scope           in-scope / out-of-scope enforcement (bug-bounty grade)
  policy          safety levels + authorization gate (safe by default)
  target_detector target-type identification (plugin-friendly)
  capabilities    tool registry (what's installed, versions, risk, target types)
  coverage        measurable coverage tracking + honesty ("no 100% secure")
  orchestrator    builds and runs the assessment pipeline from profile + mode

The existing flat scanner_*.py modules are preserved and driven BY the
orchestrator — nothing that works was thrown away.
"""

__version__ = "2.0.0"
