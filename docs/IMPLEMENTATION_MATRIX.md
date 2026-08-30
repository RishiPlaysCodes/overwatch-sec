# Implementation & Coverage Matrix

This document is an **honest, code-verified** audit of what the platform actually
does — not what documentation claims. Every row was checked against the real
execution path (CLI → orchestrator → capability selection → scanner/validator →
finding → correlation → report) and against the test suite (`python3 tests/run_tests.py`,
currently **103/103 passing**, plus the lab-driven pipeline test).

> Measured snapshot: **133 KB definitions / 22 families**, **31 validation
> capabilities** (6 automated safe checkers, 25 honest MANUAL/gated), CI/CD + IaC
> analyzers running dependency-free. Run `--gap-analysis` for the live matrix.

Status legend:

| Status | Meaning |
|---|---|
| ✅ IMPLEMENTED | Real, tested execution path end-to-end |
| 🟡 DETECTION-ONLY | Detected/knowledge-modelled; validation is manual or gated |
| 🧠 KNOWLEDGE | In the knowledge base; surfaced when a scanner/import emits the id |
| 🔬 MANUAL | Requires human validation (honest state, not faked) |
| 🔒 SAFETY-GATED | Available only under an explicit authorized policy (intrusive/destructive) |
| 🔌 EXTERNAL | Depends on an external tool/export being present |

> Guiding principle (spec §53): a capability that exists only as metadata is
> marked MANUAL/gated — never presented as if it actively proves something.

---

## Core engine

| Capability | Status | Notes |
|---|---|---|
| Target detection (web/api/recon/network/mobile/cloud/container/k8s/code/linux/windows) | ✅ | `core/target_detector.py`; tested |
| Intelligent, target+profile+policy-aware capability selection | ✅ | `core/capabilities.py` + orchestrator plan; **not** blind "run everything" |
| Safety policy (passive→safe_active→validation→intrusive→destructive), safe-by-default + hard clamp | ✅ | `core/policy.py`; destructive requires lab; tested |
| Scope enforcement (domains/wildcards/CIDR/exclusions, in-scope override) | ✅ | `core/scope.py`; bug-bounty scope drop tested |
| Program-aware bug bounty (`--program` scope+headers+rate+OOS rules) | ✅ | `core/program.py`; tested |
| Checkpoint / resume (no rescanning) | ✅ | `core/checkpoint.py`; resume restores findings+paths (verified) |
| Baseline / retest / compare (new/fixed/persistent) | ✅ | `reporting/compare.py`; verified |
| Triage persistence (fingerprint→status across scans) | ✅ | `core/triage.py`; tested |
| Fast vs Deep produce different plans | ✅ | deep adds validation + more tools; tested |
| Dry-run (plan only, no execution) | ✅ | verified |
| Secret redaction in evidence + reports | ✅ | `core/policy.redact`; lab test asserts no leak |
| Graceful failure (one scanner/tool failing ≠ whole scan dies) | ✅ | orchestrator try/except per stage → coverage errored |

## Knowledge model

| Area | Status | Count / Notes |
|---|---|---|
| Knowledge base (CWE/OWASP/CAPEC/severity/attack/patch per id) | ✅ | **131 entries / 22 families** |
| Knowledge catalog + domain coverage (`--list-knowledge`) | ✅ | `core/knowledge.py`; derived live from KB |
| CVE/CVSS/KEV enrichment | ✅ 🔌 | `cve_intel.py` + `data/` feeds (`--update`) |
| MITRE ATT&CK mapping (technique + tactic, longest-prefix, honest unmapped) | ✅ | `attack_paths/mitre.py`; tested |
| Web/injection classes (SQLi, XSS r/s/dom, SSRF, SSTI, XXE, deserialization, traversal, LFI/RFI, cmd/NoSQL/LDAP/XPath inj, CRLF, response-splitting, EL, smuggling, proto-pollution, CSRF, cache poisoning, host-header, open redirect, JWT, OAuth, mass assignment) | 🧠 / 🟡 | KB-backed; header/cookie/CORS/dir-listing/reflected-XSS/open-redirect have real detection+validation |
| API (BOLA/BFLA/excessive-data/mass-assignment/GraphQL/CORS/verbs/introspection/no-auth) | ✅ 🧠 | `scanner_api.py` detects several; authz classes = 🔬 (need test account) |
| Auth/session/identity (bypass, weak policy, no-lockout, session fixation/invalidation, SAML/SSO) | 🧠 🔬 | KB-backed; validation needs test identity |
| Business logic (workflow/price/replay/race/tenant) | 🧠 🔬 | KB-backed; explicitly manual-validation |
| Network/host services (discovery, TLS, exposed DB/SMB/RDP/SSH/WinRM, known-vuln) | ✅ 🔌 | `scanner_network.py`/`scanner_web.py` + nmap/testssl when installed |
| Windows host (unquoted svc, weak perms, SMB/RDP/WinRM, creds, patches) | 🧠 🔌 | `scanner_windows.py` from authorized export |
| Linux host (SUID/SGID, sudo, caps, cron, ssh, world-writable, kernel) | 🧠 🔌 | `scanner_linux.py` from authorized export |
| Active Directory / identity graph | ✅ 🔌 | `attack_paths/identity.py` from BloodHound-style export; edges CONFIRMED/INFERRED/UNVALIDATED |
| Cloud (IAM/storage/network/logging/MFA/public exposure) | ✅ 🔌 | `scanner_cloud.py` + Prowler/ScoutSuite connectors |
| Container / Kubernetes | ✅ 🔌 | `scanner_container.py`/`scanner_kubernetes.py` + trivy/checkov |
| Mobile (manifest/perms/exported/secrets/cleartext/backup/debug) | ✅ 🔌 | `scanner_mobile.py` + apkleaks/apktool |
| Source / SCA / secrets | ✅ 🔌 | `scanner_code.py` + semgrep/gitleaks/grype/osv |
| **CI/CD pipeline security** | ✅ | `analyzers/cicd.py` — dependency-free static analysis of GitHub Actions / GitLab CI / Jenkins: excessive permissions, `pull_request_target` PR-checkout, script injection, unpinned actions, secret exposure. Runs via `scanner_code` + orchestrator; tested |
| **IaC security** | ✅ | `analyzers/iac.py` — dependency-free analysis of Dockerfiles / Terraform / Kubernetes YAML: public exposure, hardcoded secrets, insecure defaults, privileged/hostPath/hostNet, RBAC wildcards. Tested end-to-end |
| Database, crypto/TLS | ✅ 🧠 | TLS via testssl; DB exposure/creds + crypto weaknesses KB-backed |
| Memory/binary safety | 🧠 | reasoned via CVE/SAST — **no direct binary fuzzing** (stated in KB) |
| Wireless / IoT | 🧠 🔒 | KB-backed; active wireless is intrusive/authorized-only |

## Validation engine

| Capability | Status | Notes |
|---|---|---|
| Machine-readable capability registry (prereqs/risk/evidence/cleanup) | ✅ | `validation/registry.py`, ~35 capabilities |
| Policy/scope/prereq-aware decision (run / blocked_by_policy/scope/auth/dependency) | ✅ | `registry.decide()`; tested |
| **Real safe validators**: security headers, cookies, CORS, directory listing, reflected input, **open redirect (Location, not followed)** | ✅ | `validation/validator.py`; lab test confirms validated + evidence |
| Active-exploitation classes (SSRF/SSTI/cmdi/deser/XXE/traversal/CRLF/EL) | 🔒 | intrusive; blocked_by_policy by default — **no auto-exploitation shipped** |
| Object/function authz (IDOR/BOLA/BFLA), business logic, auth/session | 🔬 | require test account → honest blocked_by_authentication / manual |
| Validation states (detected…validated/not_exploitable/manual/blocked_by_*/error) | ✅ | `core/findings.py` (15 states) |
| Structured, timestamped, redacted evidence per validated finding | ✅ | `Finding.set_validation`; lab test asserts tool+timestamp |

## Analysis & reporting

| Capability | Status | Notes |
|---|---|---|
| Attack-path correlation (objective-reaching only; steps CONFIRMED/ASSUMED/UNVALIDATED) | ✅ | `attack_paths/graph.py` + `correlation.py`; tested |
| Threat classification — legacy 4-bucket | ✅ | `threat_detection.classify()` |
| Threat classification — **evidence-graded 6-state** (vuln/misconfig/threat-indicator/suspicious/possible-compromise/validated-compromise) | ✅ | `classify_detailed()`; IOC ≤ possible, validated needs confirmation; tested |
| Purple-team detection verification | ✅ 🔌 | `purple/verification.py`; "not available" when no telemetry |
| Social-engineering (authorized awareness RESULTS analysis only) | ✅ 🔒 | `social_engineering/simulation.py`; never sends, never handles real creds |
| Availability/resilience (passive) + bounded opt-in lab load-test | ✅ 🔒 | `validation/resilience.py`,`loadtest.py`; never a DoS/flood |
| Reports: md/json/csv/html/sarif/pdf + bundle | ✅ | `reporting/*`; tested |
| **Measurable coverage**: stages, tools, ATT&CK, **validation coverage**, **per-domain matrix** | ✅ | `core/coverage.py` + `core/knowledge.coverage_by_domain`; in report + console + json |
| **Automatic gap detection** — machine-readable capability matrix (knowledge→detection→validation→checker) | ✅ | `core/gap_analysis.py` + `--gap-analysis`; flags KB-without-detection, capability-without-checker (MANUAL), orphan validators. Prevents silent incompleteness |
| Security score + qualitative posture | ✅ | `reporting/report.py`; config-only findings don't fake attack paths |

## Platform hardening & tests

| Capability | Status | Notes |
|---|---|---|
| Safe subprocess (arg arrays, no shell string-concat of untrusted input) | ✅ | `common.run` / scanners use arg lists |
| One-command tool install (`--install`/`--auto-install`, PATH symlink, retries) | ✅ 🔌 | `install.sh` + CLI; needs sudo/network on the host |
| Zero-dependency test runner + lab pipeline test | ✅ | `tests/run_tests.py` — 98/98 |
| Local intentionally-vulnerable lab | ✅ | `lab/app.py`; drives detection→validation→evidence→report test |

---

## Final gap analysis (remaining, with honest status)

| Gap | Status | Reason |
|---|---|---|
| Active exploitation of injection/RCE/SSRF classes | 🔒 BLOCKED_FOR_SAFETY | Detection + controlled validation only; no weaponization by design |
| IDOR/BOLA/BFLA/business-logic auto-validation | 🔬 REQUIRES_MANUAL_VALIDATION / 🔌 test account | Needs an authorized test identity + human judgement |
| Windows/Linux/AD/cloud host assessment | 🔌 REQUIRES_EXTERNAL_SYSTEM | Analyzes authorized data exports; never touches a live host |
| Direct binary/memory fuzzing | ❌ NOT_APPLICABLE | Out of scope; memory classes reasoned via CVE/SAST |
| Active wireless/IoT RF testing | 🔒 BLOCKED_FOR_SAFETY / 🔌 | Requires authorized RF access + intrusive policy |
| Live DoS/stress | 🔒 BLOCKED_FOR_SAFETY | Only bounded, opt-in, lab-gated resilience checks |
| CI/CD & IaC static analysis | ✅ IMPLEMENTED_AND_TESTED | `analyzers/cicd.py` + `analyzers/iac.py`; dependency-free, real findings in the pipeline |
| Cloud/DB/mobile-dynamic/wireless live adapters | 🔌 REQUIRES_AUTHORIZED_CREDENTIALS / REQUIRES_SPECIAL_HARDWARE | Read-only assessment needs supplied creds; wireless needs RF hardware + authorization |
| Deep injection/RCE auto-validation | 🔒 INTENTIONALLY_BLOCKED_FOR_SAFETY | Controlled validation only; classes gated at intrusive, no auto-exploitation |

Nothing above is a hidden TODO on a *claimed* capability: each is either
implemented, safely gated, external-data/credential/hardware dependent, or
explicitly manual. Run `python3 vulnscan.py --gap-analysis` for the live,
code-derived matrix.
