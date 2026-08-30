# 🛡️ vulnscan — Universal Security Assessment Platform

**A modular, profile-driven, authorized security-assessment & adversary-emulation
platform.** You give it a target and the authorized context; it fingerprints the
target, selects the applicable checks, runs them, safely validates what it can,
correlates attack paths, maps MITRE ATT&CK, measures its own coverage, and writes
professional reports — all **scope- and policy-enforced, safe by default**.

```bash
python3 vulnscan.py example.com --profile bugbounty --mode deep --scope scope.txt
```

> ⚠️ **Authorized use only.** Assess only systems/apps/accounts you own or are
> explicitly permitted to test. The tool asks you to type `I AM AUTHORIZED`
> before it starts (`--yes` to skip on owned assets / in CI).
> **Safe by default:** detection, recon & controlled validation only — no
> auto-exploitation, no post-exploitation, no DoS/flooding. It never claims
> "100% secure".

---

## 📑 Table of contents

1. [Install (one command)](#1-install-one-command)
2. [Quick start](#2-quick-start)
3. [The mental model (how it works)](#3-the-mental-model-how-it-works)
4. [Profiles](#4-profiles)
5. [Modes: fast vs deep](#5-modes-fast-vs-deep)
6. [Target types (auto-detected)](#6-target-types-auto-detected)
7. [What it covers (by domain)](#7-what-it-covers-by-domain)
8. [Safety, scope & policy](#8-safety-scope--policy)
9. [Validation & evidence (incl. OAST safe-proof)](#9-validation--evidence)
10. [Measurable coverage & the capability matrix](#10-measurable-coverage--the-capability-matrix)
11. [Reports](#11-reports)
12. [Bug-bounty workflow](#12-bug-bounty-workflow)
13. [Authenticated / credentialed scans](#13-authenticated--credentialed-scans)
14. [Host / cloud / identity from authorized exports](#14-host--cloud--identity-from-authorized-exports)
15. [Baseline, retest, resume & triage](#15-baseline-retest-resume--triage)
16. [CI/CD gating](#16-cicd-gating)
17. [Self-updating vulnerability feeds](#17-self-updating-vulnerability-feeds)
18. [Complete command reference](#18-complete-command-reference)
19. [Project layout](#19-project-layout)
20. [Extending the platform](#20-extending-the-platform)
21. [Testing & the local lab](#21-testing--the-local-lab)
22. [Docs & FAQ](#22-docs--faq)

---

## 1. Install (one command)

Core runs on **Python 3.9+ stdlib only** — it works immediately, and skips any
external tool that isn't installed (reporting exactly what was skipped and why).

```bash
git clone https://github.com/RishiPlaysCodes/script-test-case.git
cd script-test-case
python3 vulnscan.py --version          # works right away (stdlib only)
```

Install all the external scanners it can orchestrate (Kali/Debian/Ubuntu/WSL):

```bash
python3 vulnscan.py --install          # one shot: apt → go → curl/pip/pipx, then exits
# or only some groups:
python3 vulnscan.py --install recon web network code
```

The installer is reliable and idempotent: apt first, then `go install` (with
retries + a `GOPROXY=direct` fallback), then curl/pip/pipx fallbacks. It
**symlinks Go tools into `/usr/local/bin`** so they're on `PATH` immediately (no
"installed but not found", no new-terminal dance). Anything it still can't
install is printed at the end with the exact command to finish it. PEP-668
("externally-managed-environment") is handled automatically (`--break-system-packages`
/ `pipx`).

Prefer to let a scan grab its target's tools automatically, just before running?

```bash
python3 vulnscan.py https://your-site.com --auto-install
```

Then pull fresh vulnerability data (optional but recommended):

```bash
python3 feeds/update_feeds.py          # CISA KEV + NVD into data/ (offline-safe after)
```

---

## 2. Quick start

```bash
# interactive — asks what to scan (device → target → mode)
python3 vulnscan.py

# website / API
python3 vulnscan.py https://your-site.com
python3 vulnscan.py https://api.your-site.com --profile web --mode deep

# bug-bounty recon over a whole attack surface, confined to scope
printf 'example.com\napi.example.com\n' > scope.txt
python3 vulnscan.py example.com --profile bugbounty --mode deep --scope scope.txt

# network / host / subnet
python3 vulnscan.py 192.168.1.10
python3 vulnscan.py 10.0.0.0/24 --profile network --yes

# source repo (SCA + secrets + SAST + CI/CD + IaC)
python3 vulnscan.py ./my-project

# container image / Kubernetes manifests / Terraform
python3 vulnscan.py nginx:1.21
python3 vulnscan.py ./k8s-manifests
python3 vulnscan.py ./terraform

# mobile app
python3 vulnscan.py ./app.apk
```

Explore the platform without scanning anything:

```bash
python3 vulnscan.py --dry-run https://your-site.com --profile bugbounty --mode deep
python3 vulnscan.py --list-profiles          # available profiles
python3 vulnscan.py --list-tools             # external tools + install status
python3 vulnscan.py --list-capabilities      # validation capabilities (risk + prerequisites)
python3 vulnscan.py --list-knowledge         # knowledge catalog + per-domain coverage
python3 vulnscan.py --capability-matrix      # what it CAN and CANNOT do, with reasons
python3 vulnscan.py --gap-analysis           # code-derived knowledge→detection→validation gaps
```

---

## 3. The mental model (how it works)

```
TARGET + authorized context + PROFILE + MODE
        │
        ▼
 target detection ─► fingerprint ─► attack surface
        │
        ▼
 capability selection  (target + profile + scope + policy + prerequisites + risk)
        │
        ├──────────────► DETECTION  (scanners / analyzers)
        │                     │
        └──────────────► VALIDATION (safe, policy-gated re-observation / OAST proof)
                              │
                              ▼
        unified Finding  (severity · confidence · validation state · CWE/OWASP/CAPEC/CVE/KEV · evidence)
                              │
                              ▼
        attack-path correlation ─► MITRE ATT&CK ─► threat classification ─► risk score
                              │
                              ▼
        measurable coverage ─► professional report (md/json/csv/html/sarif/pdf)
```

It does **not** blindly run every tool against every target. It builds a plan:
each capability records *why it was selected, skipped, or blocked, and which
prerequisite is missing*. See it with `--dry-run`.

---

## 4. Profiles

A **profile** sets the intent, default risk posture, scope rules, and which
capabilities apply. Pick with `--profile`.

| Profile | For | Notes |
|---|---|---|
| `bugbounty` | Bug-bounty within program scope | scope-first; deep adds *safe* validation |
| `redteam` | Authorized adversary emulation | validates; intrusive still needs explicit policy |
| `enterprise` | Broad internal assessment | deep adds safe validation |
| `purple` | Detection verification | correlates telemetry (needs `--telemetry`) |
| `web` / `api` | Web app / API | scoped-pentest behaviour |
| `mobile` | APK / IPA | static analysis |
| `cloud` | Cloud / IaC | read-only posture |
| `network` | Network / host | service/version + known-vuln |
| `code` | Source repo | SCA + secrets + SAST + CI/CD + IaC |

`--list-profiles` shows them live. Profiles map to a **policy** (safety levels);
you can override with a policy file via `--policy` (see [§8](#8-safety-scope--policy)).

---

## 5. Modes: fast vs deep

| | **fast** (default) | **deep** (`--mode deep` or `--deep`) |
|---|---|---|
| Goal | quick, low-noise, high-confidence | thorough, correlated |
| Discovery | common checks, known-vuln | full enumeration + fingerprinting + crawl |
| Validation | minimal safe checks | safe validation of applicable findings |
| Analysis | severity + basics | attack paths, threat analysis, full coverage |

Deep **never** bypasses scope or safety policy — it only does *more of what is
authorized*.

---

## 6. Target types (auto-detected)

| Target looks like | Detected kind | Scanner |
|---|---|---|
| `aws` / `azure` / `gcp` | cloud (live) | scanner_cloud |
| `*.apk` / `*.ipa` / `*.xapk` | mobile | scanner_mobile |
| dir with `*.tf` / `*.template` | cloud (IaC) | scanner_cloud (+ IaC analyzer) |
| dir with `deployment.yaml` / `kustomization.yaml` | kubernetes | scanner_kubernetes |
| dir with code / manifests | code | scanner_code (+ CI/CD + IaC analyzers) |
| IP / CIDR | network | scanner_network |
| `name:tag` / `repo/app:tag` / `@sha256:` | container | scanner_container |
| host-export JSON (SUID/services…) | linux / windows | scanner_linux / scanner_windows |
| apex domain (`example.com`) | recon | scanner_recon |
| deeper host / URL | web / api | scanner_web / scanner_api |

Override detection with `--type {recon,web,api,network,mobile,cloud,container,kubernetes,code,linux,windows}`.

---

## 7. What it covers (by domain)

Run `python3 vulnscan.py --capability-matrix` for the live, per-capability status.
Summary (133 knowledge definitions across 22 families):

- **Web** — headers, cookies, reflected/stored/DOM XSS, CSRF, SSRF, SSTI, XXE,
  deserialization, path traversal/LFI/RFI, SQL/NoSQL/LDAP/XPath/command injection,
  CRLF/response-splitting/log injection, request smuggling, prototype pollution,
  cache poisoning, host-header, open redirect, JWT, OAuth, mass assignment, file upload, TLS.
- **API** — BOLA/BFLA, broken auth, mass assignment, excessive data, GraphQL
  introspection/DoS, CORS, dangerous verbs, exposed docs, no-auth endpoints.
- **Network / host** — service/version discovery, exposed DB/SMB/RDP/SSH/WinRM,
  TLS, known-vulnerable services (nmap NSE), Exploit-DB correlation.
- **Windows / Linux** — local-privesc & hardening from an authorized host export
  (SUID/sudo/caps/cron, services/unquoted-paths/creds/patches).
- **Active Directory / identity** — privilege & lateral-movement paths from a
  BloodHound-style export; edges tagged CONFIRMED / INFERRED / UNVALIDATED.
- **Cloud** — IAM, storage, network, encryption, logging, MFA, public exposure
  (+ Prowler / ScoutSuite connectors).
- **Container / Kubernetes** — image CVEs & misconfig; privileged/hostPath/
  hostNetwork, wildcard RBAC.
- **Mobile** — manifest/permissions/exported components/secrets/cleartext/backup/debug.
- **Source / SCA** — dependency CVEs, committed secrets, insecure code patterns.
- **CI/CD** — GitHub Actions / GitLab CI / Jenkins: excessive permissions,
  `pull_request_target` PR-checkout, script injection, unpinned actions, secret exposure.
- **IaC** — Dockerfiles / Terraform / Kubernetes YAML: public exposure, hardcoded
  secrets, insecure defaults, privileged workloads.
- **Auth/session, business logic, database, crypto/TLS, supply chain, memory/binary
  (via CVE/SAST), wireless/IoT** — knowledge-modelled; validation is manual or
  gated (see the capability matrix for exact status).
- **Threat analysis** — evidence-graded classification (vuln → misconfig → threat
  indicator → suspicious → possible compromise → validated compromise).
- **Purple team** — technique → expected/observed telemetry → detected / not-detected
  / telemetry-unavailable.
- **Availability** — passive rate-limit / WAF-CDN signals; bounded opt-in lab load-test.

**CI/CD & IaC analyzers are dependency-free** (stdlib only) — scanning a repo
produces real findings even on a minimal box.

---

## 8. Safety, scope & policy

**Safety levels** (least → most impactful), enforced fail-closed:

```
passive → safe_active → validation → intrusive → destructive
```

- **Default policy = passive + safe_active only.** `validation` turns on for deep
  scans on validating profiles. `intrusive`/`destructive` **never** run unless an
  explicit, authorized policy enables them (`destructive` additionally requires a
  `lab` authorization). A hard clamp prevents a misparsed config from escalating.
- **Scope** confines every discovered asset. Provide a scope file with `--scope`
  (one entry per line: domains, `*.wildcards`, IPs, CIDRs, exclusions). Out-of-scope
  assets are never actively tested and are listed in the report.
- **Program config** (`--program program.yaml`) captures a full bug-bounty program:
  scope + required headers + rate limit + out-of-scope finding rules — the engine
  auto-respects all of it (see `programs/` for a template + a MATLAB example).
- **Policy file** (`--policy policy.yaml`) sets safety levels explicitly (see
  `policies/` — `bugbounty`, `redteam`, `purple`, `lab`).

Every active validation must pass: scope → authorization → profile → policy →
risk → prerequisites, in that order, before it runs.

---

## 9. Validation & evidence

Findings carry a **validation state**, not just a severity:

```
detected · likely · validated · not_validated · not_exploitable · false_positive
· manual_validation_required · blocked_by_policy · blocked_by_scope
· blocked_by_authentication · blocked_by_missing_dependency · error
```

- **Automated safe validators** (re-observe deterministic facts, never exploit):
  security headers, cookies, CORS, directory listing, reflected input, and
  **open redirect** (checks the `Location` header **without following the redirect**).
- **Controlled OAST safe-proof** (`validation/oast.py`) for blind classes such as
  **SSRF**: injects a benign unique marker pointing at an out-of-band collaborator
  *you* control; if the target calls back, the issue is **proven with evidence** —
  non-destructively. Runs only under an intrusive-authorized policy **with** a
  collaborator configured; otherwise it's honestly `manual_validation_required`,
  and it's `blocked_by_policy` under the safe default. It **never auto-exploits**.
- **Active-exploitation classes** (SSTI, command injection, deserialization, XXE,
  CRLF, EL) are gated at the `intrusive` level and are otherwise reported as
  detected/manual — the platform does not weaponize arbitrary targets.

Every validated finding records **structured, timestamped, redacted evidence**
(tool, test, reason, timestamp, and — for OAST — the callback). Operator secrets
(`--cookie/--token/--api-key/--header` values) are auto-redacted from all output.

---

## 10. Measurable coverage & the capability matrix

The platform is honest about what it did and didn't do.

```bash
python3 vulnscan.py --capability-matrix          # per-capability status + reason
python3 vulnscan.py --capability-matrix --json   # machine-readable
python3 vulnscan.py --gap-analysis               # KB→detection→validation→checker gaps
python3 vulnscan.py --list-knowledge             # families, counts, domain coverage
```

Every capability is classified with an exact status and a reason — **zero
unexplained gaps**:

```
IMPLEMENTED_AND_TESTED · IMPLEMENTED_PARTIALLY · MANUAL_VALIDATION_REQUIRED
REQUIRES_AUTHORIZED_CREDENTIALS · REQUIRES_EXTERNAL_TELEMETRY · REQUIRES_SPECIAL_HARDWARE
REQUIRES_TARGET_SPECIFIC_CONFIGURATION · EXTERNAL_TOOL_REQUIRED
BLOCKED_BY_SCOPE · BLOCKED_BY_POLICY · INTENTIONALLY_BLOCKED_FOR_SAFETY · NOT_APPLICABLE
```

Every report/console shows **validation coverage** (selected / executed /
validated / refuted / manual + the exact reason anything was *not* run) and a
**per-domain coverage matrix**. Never a fabricated percentage.

---

## 11. Reports

Everything lands in `report-<profile>-<target>-<timestamp>/` (or `--out DIR`).

```bash
python3 vulnscan.py https://your-site.com --formats md,json,csv,html,sarif,pdf
python3 vulnscan.py https://your-site.com --bundle    # executive + technical bundle
```

- **`report.md`** — executive summary (posture, score, KEV, attack paths),
  indicators, attack paths, validation status, per-domain coverage, then full
  findings (each: severity, confidence, validation, CWE/OWASP/CAPEC/CVE/CVSS/KEV/
  ATT&CK, evidence, *what it is*, *attack scenario*, *fix*).
- **`report.json`** — machine-readable; includes `summary`, `coverage_by_domain`,
  and the `capability_matrix`.
- **`report.csv`** — findings table. **`report.html`** — self-contained dashboard
  + interactive attack graph. **`report.sarif`** — GitHub Code Scanning.
  **`report.pdf`** — best-effort HTML→PDF, else a dependency-free text PDF.
- Raw tool outputs (`nmap.txt`, `nuclei.txt`, `trivy-fs.txt`, …).

---

## 12. Bug-bounty workflow

```bash
# 1) capture scope (domains / wildcards / IPs / exclusions), one per line
printf 'example.com\n*.example.com\n!admin.example.com\n' > scope.txt

# 2) fast pass — attack surface + known-vuln, strictly in scope
python3 vulnscan.py example.com --profile bugbounty --mode fast --scope scope.txt

# 3) deep pass — content discovery, crawl, safe validation, attack paths
python3 vulnscan.py example.com --profile bugbounty --mode deep --scope scope.txt
```

Or drive a whole program with one config (scope + required headers + rate limit +
out-of-scope finding rules):

```bash
python3 vulnscan.py example.com --program programs/your-program.yaml
```

The recon pipeline chains subdomain enum → HTTP probe → port scan → URL collection
→ content discovery → takeover checks → templated CVE scanning (nuclei) — each
tool auto-detected and skipped if missing, everything confined to scope.
**Detection only — no auto-exploitation** (which is exactly what program rules require).

---

## 13. Authenticated / credentialed scans

Supply credentials to test behind auth. Values are **redacted** from all output.

```bash
python3 vulnscan.py https://app.example.com --profile web --mode deep \
    --cookie "session=…" \
    --header "Authorization: Bearer …" \
    --token "…" --api-key "…"
```

Object/function-authorization classes (IDOR/BOLA/BFLA) require an explicitly
supplied **test identity** and are otherwise reported as `manual` /
`blocked_by_authentication` — the platform never obtains credentials itself and
never touches accounts you didn't provide.

---

## 14. Host / cloud / identity from authorized exports

These analyze data **you export** from systems you're authorized to inspect —
read-only, never touching a live host/cloud:

```bash
python3 vulnscan.py host.json --type linux           # Linux host audit (SUID/sudo/caps/…)
python3 vulnscan.py host.json --type windows          # Windows host audit
python3 vulnscan.py --identity-file ad.json <target>  # AD/cloud privilege-escalation paths
python3 vulnscan.py --threat-input export.json --ioc-file iocs.json <target>   # threat indicators
python3 vulnscan.py --telemetry siem.json --profile purple <target>            # detection verification
```

Connectors auto-convert common formats (BloodHound → identity graph, Prowler →
findings, ScoutSuite → threat telemetry).

---

## 15. Baseline, retest, resume & triage

```bash
python3 vulnscan.py <t> --baseline                 # save this run as the baseline
python3 vulnscan.py <t> --retest                   # diff vs saved baseline (new/fixed/persistent)
python3 vulnscan.py <t> --compare old/report.json  # diff vs a specific report
python3 vulnscan.py --resume SCAN-<id>             # rebuild from checkpoint, no rescanning

# persistent triage (mute false-positives/accepted-risk across scans)
python3 vulnscan.py <t> --triage-file triage.json
python3 vulnscan.py <t> --triage-file triage.json --mark "<FINGERPRINT>=false_positive:mitigated by WAF"
```

Deep scans checkpoint after each stage, so a crash/interruption can `--resume`
from where it stopped.

---

## 16. CI/CD gating

Fail a pipeline on risk thresholds (exit non-zero):

```bash
python3 vulnscan.py <t> --yes --formats sarif --fail-on high      # any ≥ high
python3 vulnscan.py <t> --yes --fail-on-kev                        # any actively-exploited (KEV)
python3 vulnscan.py <t> --yes --compare baseline.json --fail-on-new   # any new vs baseline
```

Emit SARIF (`--formats sarif`) for GitHub Code Scanning.

---

## 17. Self-updating vulnerability feeds

The *code* rarely changes; the **vulnerability data** does. `cve_intel.py` reads
`data/` first, so CVE enrichment (CVSS + CISA KEV) works **fully offline**.

```bash
python3 feeds/update_feeds.py            # refresh KEV + NVD (+ tool DBs if installed)
python3 vulnscan.py --update             # same, via the CLI
```

Keep it fresh automatically (works even when your machine is off):

- **GitHub Actions** — `.github/workflows/update-feeds.yml` refreshes daily in the cloud.
- **Local schedule** — `./deploy/install-scheduler.sh` (systemd timer) or `--cron`.

---

## 18. Complete command reference

Full details in [`docs/CLI.md`](docs/CLI.md). Most-used flags:

| Flag | Meaning |
|---|---|
| `--profile P` | assessment profile (see `--list-profiles`) |
| `--mode fast\|deep`, `--deep` | speed vs thoroughness |
| `--type KIND` | force target kind (override detection) |
| `--scope FILE` | scope file (in-scope assets) |
| `--program FILE` | bug-bounty program YAML (scope + headers + rate + OOS rules) |
| `--policy FILE` | safety-level policy YAML |
| `--out DIR` | output directory |
| `--formats md,json,csv,html,pdf,sarif` | report formats |
| `--bundle` | executive + technical report bundle |
| `--skip t1,t2` | skip specific tools |
| `--workers N`, `--timeout S` | concurrency / per-tool timeout |
| `--cookie/--header/--token/--api-key/--username` | authenticated scan (redacted) |
| `--aws-profile/--gcp-project/--azure-subscription` | cloud creds context |
| `--compare FILE`, `--baseline`, `--retest` | diff / baseline / retest |
| `--triage-file FILE`, `--mark SPEC` | persistent triage |
| `--resume ID` | resume a scan from checkpoint |
| `--fail-on SEV`, `--fail-on-kev`, `--fail-on-new` | CI gating |
| `--identity-file/--threat-input/--ioc-file/--telemetry/--se-input` | authorized exports |
| `--load-test` | bounded, opt-in, LAB-only resilience test (never a DoS) |
| `--no-plugins` | disable plugin loading |
| `--yes` | skip the authorization prompt (owned assets / CI) |
| `--dry-run` | show the plan, run nothing |
| **Info** | `--list-profiles` `--list-tools` `--list-capabilities` `--list-knowledge` `--gap-analysis` `--capability-matrix [--json]` |
| **Setup** | `--install [groups]` `--auto-install` `--update` `--version` |

---

## 19. Project layout

```
vulnscan.py            # CLI entry: detection, auth gate, dispatch, reporting
common.py              # shared helpers (safe subprocess, HTTP, finding builder)
knowledgebase.py       # every finding: CWE/OWASP/CAPEC + description/attack/patch
cve_intel.py           # NVD CVSS + CISA KEV enrichment (offline-safe)

core/                  # the engine
  orchestrator.py      #   builds + runs the pipeline; scope/policy; correlation
  target_detector.py   #   identify target kind → scanner
  capabilities.py      #   external-tool registry (kinds, risk, install state)
  policy.py            #   safety levels + authorization gate (safe by default)
  scope.py             #   scope model (domains/wildcards/CIDR/exclusions)
  program.py           #   bug-bounty program config
  findings.py          #   unified Finding model (confidence + validation state)
  knowledge.py         #   knowledge catalog + per-domain coverage
  coverage.py          #   measurable coverage (stages/tools/validation)
  gap_analysis.py      #   code-derived knowledge→detection→validation gaps
  capability_matrix.py #   structured capability matrix (status vocabulary)
  checkpoint.py        #   checkpoint / resume / baselines
  triage.py            #   persistent triage store

scanner_*.py           # per-kind scanners (recon/web/api/network/mobile/cloud/
                        # container/kubernetes/code/linux/windows)
analyzers/             # dependency-free CI/CD + IaC static analyzers
validation/            # registry, validators, confidence, resilience, loadtest, oast
attack_paths/          # graph, correlation, mitre, identity
threat_detection/      # indicator classification (+ 6-state), IOC analysis
purple/                # detection verification
social_engineering/    # authorized awareness-RESULTS analysis (never sends)
connectors/            # BloodHound / Prowler / ScoutSuite importers
reporting/             # md/json/csv/html/sarif/pdf + bundle + compare + graph
plugins/               # drop-in scanners/validators/objectives (no core changes)
profiles/ policies/ programs/   # YAML configs
lab/                   # intentionally-vulnerable local app for safe testing
tests/                 # zero-dependency test runner + suites + fixtures
data/                  # KEV/NVD feed cache (offline enrichment)
deploy/ feeds/         # feed updater + schedulers
docs/                  # CLI reference + implementation/capability matrix
```

---

## 20. Extending the platform

- **New finding class:** add an entry to `knowledgebase.py` (CWE/OWASP/CAPEC +
  description/attack/patch), then emit it from a scanner via
  `common.finding("<id>", "<evidence>")`. `--gap-analysis` will confirm it's wired.
- **New validator:** register a callable in `validation/validator.py` and declare
  a `ValidationCapability` in `validation/registry.py` (prerequisites, risk,
  evidence). Blind classes can use `validation/oast.py`.
- **New scanner / MITRE map / objective:** drop a `plugins/*.py` module — it's
  loaded automatically (disable with `--no-plugins`).
- **New target kind:** add a detector rule + a `scanner_<kind>.py` and register it
  in `core/target_detector.py`.

Design goal: capabilities expand by **adding**, without an architectural rewrite.

---

## 21. Testing & the local lab

```bash
python3 tests/run_tests.py         # zero-dependency runner (unit + integration + lab)
# or, if you have pytest:
pytest
```

The suite includes a **local intentionally-vulnerable lab** (`lab/app.py`) that
exercises the full pipeline: detection → validation → evidence → correlation →
report → secret-redaction. Try it live:

```bash
python3 lab/app.py                                   # serves http://127.0.0.1:8000
python3 vulnscan.py http://127.0.0.1:8000 --profile redteam --mode deep --yes
```

> Automated tests use only local fixtures/labs — never real-world targets.

---

## 22. Docs & FAQ

📚 [INSTALL](INSTALL.md) · [USAGE](USAGE.md) · [CLI reference](docs/CLI.md) ·
[ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) ·
[IMPLEMENTATION / CAPABILITY MATRIX](docs/IMPLEMENTATION_MATRIX.md)

**Does it exploit vulnerabilities?** No. It detects, and *safely validates* what
it can (re-observation + authorized OAST callbacks). Active exploitation is gated
and never automatic.

**Does it do DoS / stress testing?** No uncontrolled DoS. Only passive resilience
signals and a bounded, opt-in, lab-only load-test.

**Will it work without the external tools?** Yes — the core is stdlib-only and
skips missing tools, reporting exactly what was skipped. CI/CD + IaC analysis and
the built-in web checks need no external tools at all.

**Is CVE data required online?** No. `data/` is read first; scans complete offline
(CVSS/KEV simply omitted if never fetched).

**Why does it never say "100% secure"?** Because that's never true. It reports
measurable coverage and tells you which issues are *actively exploited in the wild*
(CISA KEV) so you fix those first.

---

> 🛡️ Built for authorized security work. Detection, recon & controlled validation
> only. Every scan enforces scope + policy and produces honest, evidence-based,
> measurable results. Authorized use only.
