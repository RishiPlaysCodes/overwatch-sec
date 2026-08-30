# plugins/

Drop-in extensibility. Any `plugins/*.py` that defines `register(reg)` is loaded
at startup and can extend the engine without modifying core code.

```python
# plugins/my_plugin.py
def register(reg):
    # map a new finding type to MITRE ATT&CK
    reg.add_mitre("web.graphql", ("T1190", "Exploit Public-Facing Application", "initial-access"))

    # teach the attack-path engine what a finding grants
    reg.add_objective("web.graphql", ("GraphQL data exposure", 4, False))

    # register a safe, non-destructive validator (must NOT exploit)
    def validate_graphql(finding):
        return "manual"   # "validated" | "not_exploitable" | "manual" | "skipped"
    reg.add_validator("web.graphql", validate_graphql)

    # register a new target kind -> scanner module
    # reg.add_scanner("iot", "scanner_iot")

    # register a new orchestrated tool
    # from core.capabilities import Tool
    # reg.add_capability(Tool("mytool", ("web",), "safe_active"))
```

Rules:
- Validators must be **non-destructive** (re-observe facts, never exploit).
- A broken plugin is caught and skipped; it never crashes the engine.
- Load them with `vulnscan.py --plugins` (or they load automatically when present).
