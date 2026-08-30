"""
validation — safe, policy-gated confirmation of findings.

Upgrades a finding's validation state (detected -> validated / not_exploitable)
and its confidence, using ONLY non-destructive, safe checks. There is no
exploitation here: validators re-observe deterministic evidence (a header is
really absent, an input is really reflected, a listing is really served). Any
check that cannot be performed safely leaves the finding as
"detected — manual validation required".
"""
