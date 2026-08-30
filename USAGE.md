# Usage

> Authorized use only. Assess systems you own or are explicitly permitted to
> test. Safe by default — detection, recon and controlled validation only.

## One command

```bash
python3 vulnscan.py                      # interactive: pick profile → target → mode
python3 vulnscan.py example.com          # auto-detect kind + sensible profile
```

## Profiles & modes

```bash
python3 vulnscan.py example.com --profile bugbounty --mode fast --scope scope.txt
python3 vulnscan.py example.com --profile bugbounty --mode deep --scope scope.txt
python3 vulnscan.py 10.0.0.0/24 --profile redteam  --mode deep --yes
python3 vulnscan.py ./app.apk    --profile mobile
python3 vulnscan.py ./terraform  --profile cloud
python3 vulnscan.py ./repo       --profile code
python3 vulnscan.py nginx:1.21   --profile cloud   # container image
```

- **FAST** — quick, passive + safe-active checks; attack-surface + known-vuln.
- **DEEP** — thorough; adds crawling, more tools, and *safe* validation +
  attack-path correlation. (Intrusive/destructive still require an explicit,
  authorized policy — never automatic.)

## Scope (bug bounty)

`scope.txt` (one entry per line):
```
example.com
*.example.com
10.0.0.0/24
!admin.example.com      # exclusion
https://example.com/api/
```
```bash
python3 vulnscan.py example.com --profile bugbounty --scope scope.txt
```
Out-of-scope discovered assets are dropped and reported.

## Authentication (redacted from all output)

```bash
python3 vulnscan.py https://app.example.com --header "Authorization: Bearer T0KEN" \
        --cookie "session=..." --token T0KEN
python3 vulnscan.py aws --aws-profile prod
```
Secrets you pass are stripped from evidence, logs, and reports.

## Reports & baselines

```bash
python3 vulnscan.py example.com --formats md,json,csv,html --out ./run1
python3 vulnscan.py example.com --baseline                    # save baseline.json
python3 vulnscan.py example.com --compare ./run1/report.json  # retest diff
```

Reports include an **attack-path graph** (Mermaid) rendered in the HTML/Markdown
report — Internet → findings → 🎯 crown-jewel objectives, with multi-asset
lateral movement.

## Validation (safe, policy-gated)

In `deep` mode with a validating policy (`redteam`/`lab`/`authorized_pentest`),
findings are **safely re-checked** and upgraded from `detected` to `validated`
or `not_exploitable` — using non-destructive re-observation only (never
exploitation). In `fast`/bug-bounty defaults, findings are marked
`detected — manual validation required`.

## Triage (persist decisions across scans)

```bash
# record a decision (get FINGERPRINT from report.json)
python3 vulnscan.py example.com --triage-file triage.json --mark "<FP>=false_positive:mitigated by WAF"
# subsequent scans apply it (muted findings drop out of the score)
python3 vulnscan.py example.com --triage-file triage.json
```
Statuses: `open`, `validated`, `false_positive`, `accepted_risk`, `fixed`, `retest_required`.

## Identity & threat analysis (from authorized data exports)

These analyze data **you export** from systems you're authorized to inspect —
no live AD/cloud attacks, no host access.

```bash
# AD/cloud privilege-escalation + lateral paths from an identity graph export
python3 vulnscan.py corp.example --profile redteam --identity-file identity.json

# threat indicators from a host/cloud export (+ optional IOC feed)
python3 vulnscan.py host.example --threat-input host_export.json --ioc-file iocs.json
```

- `--identity-file` (JSON `nodes`/`edges`): traces principal → crown-jewel
  escalation paths (BloodHound-style), mapped to MITRE ATT&CK.
- `--threat-input` + `--ioc-file`: classifies signals as vulnerability /
  misconfiguration / **threat_indicator** / **active_compromise_indicator**.
  Active-compromise requires a strong IOC match; weak signals stay "indicator to
  investigate" (never a definitive breach claim).

## PDF & report formats

```bash
python3 vulnscan.py example.com --formats md,json,csv,html,pdf,sarif
```
- `pdf` uses `wkhtmltopdf`/`weasyprint` if installed (rich), else a built-in
  dependency-free text PDF so `report.pdf` always exists.
- `html` also emits **`attack-graph.html`** — an interactive Cytoscape.js graph
  (click nodes to drill down, filter by severity); the main report links to it.
- `sarif` emits `report.sarif` (SARIF 2.1.0) for GitHub Code Scanning / CI.

## CI gating

Fail a pipeline on risk thresholds (non-zero exit):
```bash
python3 vulnscan.py example.com --profile web --yes --formats sarif --fail-on high
python3 vulnscan.py example.com --yes --fail-on-kev                    # any actively-exploited CVE
python3 vulnscan.py example.com --yes --compare baseline.json --fail-on-new
```
Only **active** findings count (false-positive/fixed/accepted-risk are ignored).

## Live tool connectors (bring-your-own-data)

Feed raw output from authorized tools directly to `--identity-file` /
`--threat-input`; connectors auto-detect and convert it:
```bash
# BloodHound export -> identity attack paths
python3 vulnscan.py corp.example --profile redteam --identity-file bloodhound.json
# Prowler JSON -> cloud findings   |   ScoutSuite JSON -> threat telemetry
python3 vulnscan.py aws --threat-input prowler.json
python3 vulnscan.py aws --threat-input scoutsuite.json
```
Connectors are offline parsers — they never call a live directory/cloud API.

## Validation states & evidence

Every finding carries a validation state and structured, timestamped evidence:
`detected` · `likely` · `validated` · `not_validated` · `not_exploitable` ·
`manual_validation_required` · `blocked_by_policy` / `_scope` / `_authentication`
/ `_missing_dependency` · `error`. The **validation capability registry**
(`validation/registry.py`) decides, per finding + policy + context, whether a
safe re-check runs — and when it can't, the report says *why* (e.g. "blocked by
policy") instead of silently skipping. Safe re-checks (`safe_active`) run even in
fast mode; riskier `controlled_validation` checks need a validating policy
(deep / redteam / lab / purple).

The report includes a **Validation status** table, **Validated findings**,
**Unvalidated findings**, and **Tests not performed (blocked)** sections.

## Attack-path confidence

Each attack-path step is tagged **CONFIRMED** (independently validated),
**ASSUMED** (detected, plausible but unproven), or **UNVALIDATED** (checked or
blocked). Each path reports an overall confidence (CONFIRMED / PARTIAL / ASSUMED)
plus confirmed-step and unvalidated-assumption counts — so a report never
presents a hypothetical chain as a confirmed compromise.

## Purple team — detection verification

```bash
python3 vulnscan.py target --profile purple --mode deep --yes
python3 vulnscan.py target --profile purple --telemetry siem_export.json --yes
```
Maps executed test activity → expected telemetry / MITRE, correlates with your
SIEM/EDR/IDS export, and reports detection rate + gaps + recommended rules. With
no telemetry supplied, everything is reported as an unverified gap (honest).

## Resume / checkpointing

Progress is checkpointed to `~/.cache/vulnscan/scans/<scan-id>.json` (the CLI
prints the scan-id). Resume without rescanning:
```bash
python3 vulnscan.py --resume SCAN-YYYYMMDD-HHMMSS-xxxx
```

## Availability & resilience (safe, passive)

For web/API/recon targets the engine passively inspects response headers for
rate-limiting, WAF/CDN edge protection, and amplification surface. This is **not**
a DoS tool — there is no flooding or load generation.

## Plugins (extend without touching core)

Drop a `plugins/*.py` defining `register(reg)` (see `plugins/README.md`). Loaded
automatically; disable with `--no-plugins`. Add MITRE mappings, validators,
attack-path objectives, new target kinds, or tools.

## Inspect / control

```bash
python3 vulnscan.py --version
python3 vulnscan.py --list-profiles
python3 vulnscan.py --list-tools
python3 vulnscan.py --list-capabilities
python3 vulnscan.py example.com --dry-run       # show the plan, run nothing
python3 vulnscan.py --update                    # refresh CVE feeds (KEV/NVD)
python3 vulnscan.py example.com --workers 10 --timeout 30 --skip nuclei,sqlmap
```

## Local test lab (no real targets)

```bash
python3 lab/app.py                                   # insecure demo on :8000
python3 vulnscan.py http://127.0.0.1:8000 --profile web --yes
# or: cd lab && docker compose up -d   (Juice Shop :3000, DVWA :8080)
```
