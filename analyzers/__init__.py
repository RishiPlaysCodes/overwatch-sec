"""
analyzers/ — dependency-free static analyzers that produce normalized findings.

These run WITHOUT external tools (stdlib only), so `overwatch ./repo` performs
real CI/CD and IaC analysis even on a minimal box. Each analyzer returns a list
of finding dicts built via common.finding(kb_id, evidence), so results flow
through the same normalization → correlation → reporting pipeline as every other
scanner. They are static/pattern analyzers: findings are DETECTED (config facts)
and, where confirmation needs human judgement, remain manual by policy.
"""
