"""
threat_detection — classify security signals and (from authorized data) surface
indicators of compromise.

Strict epistemics (spec §8): we clearly separate VULNERABILITY, MISCONFIGURATION,
THREAT_INDICATOR, and ACTIVE_COMPROMISE_INDICATOR. A weak signal is NEVER
reported as "system compromised" — active-compromise conclusions require strong,
corroborated evidence and are always phrased as indicators to investigate.
"""
