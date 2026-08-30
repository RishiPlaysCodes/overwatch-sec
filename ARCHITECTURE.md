# Architecture

vulnscan is a modular, plugin-friendly security-assessment platform. A thin CLI
drives a **core engine** that detects the target, enforces policy + scope, runs
the appropriate scanner pipeline, normalizes results into a unified model,
correlates attack paths, and produces industry-grade reports.

```
                         ┌──────────────┐
   vulnscan.py (CLI) ───▶│ core.config  │  profiles/*.yaml, policies/*.yaml
                         └──────┬───────┘
                                ▼
        ┌───────────────  core.orchestrator  ───────────────┐
        │  target_detector → scope → policy → capabilities   │
        │        │              │       │          │         │
        │        ▼              ▼       ▼          ▼         │
        │   pick pipeline   in/out   safety     choose       │
        │                   scope    levels     tools        │
        └───────────────────────┬───────────────────────────┘
                                 ▼
                 legacy scanners (preserved, driven by engine)
       scanner_recon / web / network / mobile / cloud / container / code
                                 │  (emit legacy dict findings)
                                 ▼
                     core.findings.Finding  (normalize + epistemics)
                                 │
              ┌──────────────────┼───────────────────┐
              ▼                  ▼                    ▼
   attack_paths.mitre    attack_paths.correlation   core.coverage
   (ATT&CK mapping)      (chains + risk score)       (measurable coverage)
                                 │
                                 ▼
                 reporting  →  md / json / csv / html  +  compare (baseline/retest)
```

## Packages

| Package | Responsibility |
|---|---|
| `core.findings` | Unified `Finding` (severity, **confidence**, **validation state**, status, CWE/OWASP/CVE/CVSS/KEV/ATT&CK); `from_legacy` lifts old scanner dicts; fingerprint/dedupe/sort. |
| `core.scope` | Bug-bounty-grade scope: domains, `*.wildcards`, IP/CIDR, exclusions, URL prefixes. Never auto-expands. |
| `core.policy` | Safety levels `passive→safe_active→validation→intrusive→destructive`, **safe by default**, authorization gate, secret redaction, hard clamp. |
| `core.target_detector` | Identifies target kind (web/api/recon/network/mobile/cloud/container/kubernetes/code) → scanner. |
| `core.capabilities` | Tool registry: which tools serve which kinds, risk level, modes, install state, version. |
| `core.coverage` | Measurable coverage: stages ran/skipped/errored + reasons, tools, ATT&CK count. Never claims "100% secure". |
| `core.orchestrator` | Builds and runs the pipeline; enforces scope + policy; normalizes; correlates. |
| `core.config` | Loads profiles/policies (PyYAML if present, else built-in loader; safe fallbacks). |
| `attack_paths.mitre` | Finding→ATT&CK technique + tactic mapping (metadata-driven, extensible). |
| `attack_paths.correlation` | Chains findings per asset along the kill-chain; risk-scores paths. |
| `reporting.report` | `md` / `json` / `csv` / `html` dashboard + `security_score` + embedded Mermaid attack graph. |
| `reporting.compare` | Baseline/retest diff (new/fixed/persistent, risk delta). |
| `attack_paths.graph` | **Real node/edge graph** (entry/asset/finding/objective); enumerates Internet→crown-jewel paths with **multi-asset lateral** chaining; risk scoring + Mermaid export. |
| `validation.validator` | **Safe, policy-gated** confirmation (DETECTED→VALIDATED / NOT_EXPLOITABLE); non-destructive re-observation only, never exploitation. |
| `validation.confidence` | Confidence/validation-state transitions. |
| `core.triage` | **Persistent triage** store (fingerprint→status) applied across scans; mutes false-positives/fixed. |
| `core.plugins` | **Plugin loader**: `plugins/*.py` register scanners / MITRE maps / validators / objectives / tools without touching core. |
| `scanner_api` | Dedicated **OWASP API Security** checks (no-auth, CORS, verbs, GraphQL introspection, exposed docs). |
| `scanner_kubernetes` | Static **K8s manifest audit** (privileged, hostPath, wildcard RBAC, hostNetwork, missing NetworkPolicy) + tool hooks. |
| `attack_paths.identity` | **AD/cloud identity attack paths** from an authorized export (BloodHound-style); principal→crown-jewel privesc/lateral chains → MITRE. |
| `threat_detection.detector` | Classify signals (vuln/misconfig/**threat_indicator**/**active_compromise**); IOC matching from authorized host/cloud exports. Strict epistemics. |
| `reporting.pdf` | PDF output: best-effort html→pdf, else a dependency-free built-in text PDF. |

## Design decisions

- **Preserve what works.** The existing flat `scanner_*.py` modules are *driven
  by* the orchestrator rather than rewritten. New target kinds are added by
  registering a scanner + capability entries — no core changes.
- **Safe by default.** Nothing intrusive/destructive runs unless a policy
  explicitly and legitimately enables it; destructive requires a `lab`
  authorization. There is no auto-exploitation, post-exploitation, or DoS.
- **Epistemic honesty.** Findings carry confidence + validation state; coverage
  is measurable and always disclaims exhaustiveness.
- **No hard 3rd-party deps.** Runs on stdlib; PyYAML and external security tools
  are optional and gracefully skipped.

## Extending

- **New scanner / target kind:** add `scanner_x.py` with `scan(target, outdir, skip)`,
  register it in `target_detector.KIND_TO_SCANNER` and add `capabilities.Tool`s.
- **New attack technique mapping:** add an entry to `attack_paths.mitre.TECHNIQUE_MAP`.
- **New finding type:** add to `knowledgebase.KB` (id → cwe/owasp/description/attack/patch).
- **New profile/policy:** drop a YAML into `profiles/` / `policies/`.
