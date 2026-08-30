"""
connectors — turn real tool exports into overwatch's input formats.

Bring-your-own-data: run authorized tools (BloodHound, ScoutSuite, Prowler) in
your environment, then feed their JSON output here. Connectors are pure,
offline parsers — they never call a live directory/cloud API themselves.

  bloodhound.to_identity(export)  -> identity graph  (for attack_paths.identity)
  scoutsuite.to_threat(report)    -> threat data     (for threat_detection)
  prowler.to_threat(findings)     -> threat data     (for threat_detection)

`detect_and_load(path)` sniffs the file and returns
    ("identity", data) | ("threat", data) | (None, None).
"""

from . import bloodhound, scoutsuite, prowler  # noqa: F401


def detect_and_load(path: str):
    """Sniff a JSON export and convert it to the right overwatch input format."""
    import json
    try:
        with open(path, "r", errors="ignore") as fh:
            raw = json.load(fh)
    except Exception:
        return None, None

    # BloodHound exports: {"data":[...], "meta":{"type":"users"|...}} or a list of nodes/edges
    if bloodhound.looks_like(raw):
        return "identity", bloodhound.to_identity(raw)
    # Prowler v3/v4 JSON: list of {"status","check_id","severity",...} -> findings
    if prowler.looks_like(raw):
        return "findings", prowler.to_findings(raw)
    # ScoutSuite: {"services": {...}, "account_id": ...} style -> threat telemetry
    if scoutsuite.looks_like(raw):
        return "threat", scoutsuite.to_threat(raw)
    return None, None
