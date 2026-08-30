"""
Example plugin — adds GraphQL awareness to the engine without touching core.

Demonstrates the four extension points. Safe: the validator only re-observes,
it does not exploit anything.
"""


def _validate_graphql_introspection(finding):
    """
    SAFE check: confirm the GraphQL endpoint answers a benign introspection
    query (indicates introspection is enabled). Non-destructive.
    """
    try:
        from common import http_get  # noqa
    except Exception:
        return "manual"
    # We only *observe*; a real check would POST a benign introspection query.
    return "manual"


def register(reg):
    reg.add_mitre("web.graphql", ("T1190", "Exploit Public-Facing Application", "initial-access"))
    reg.add_objective("web.graphql", ("GraphQL schema / data exposure", 4, False))
    reg.add_validator("web.graphql", _validate_graphql_introspection)
