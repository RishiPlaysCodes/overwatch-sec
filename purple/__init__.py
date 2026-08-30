"""
purple — detection verification (purple-team mode).

Answers the defensive question: "when we run authorized test activity, do our
controls SEE it?" For each executed validation/technique we know the expected
telemetry + MITRE technique; we compare that against an optional SIEM/EDR/IDS
export to determine whether a detection fired, and surface detection GAPS with
recommended rules.

This is read-only correlation — it never disables controls or generates attacks
beyond the already-authorized validation the engine performed.
"""
