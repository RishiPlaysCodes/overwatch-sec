# vulnscan — Complete CLI Reference

```
python3 vulnscan.py [target] [options]
```

`target` — URL / domain / IP / CIDR / app file / directory / image ref. Omit it
to launch the **interactive wizard** (asks device type → target → mode).

> Safe by default: detection, recon & controlled validation only. Authorized use
> only — you'll be asked to type `I AM AUTHORIZED` (use `--yes` on owned assets / CI).

---

## Information commands (run and exit)

| Command | What it prints |
|---|---|
| `--version` | version string |
| `--list-profiles` | available profiles |
| `--list-tools` | external tools per kind + install status |
| `--list-capabilities` | validation capabilities (id : risk : prerequisites) |
| `--list-knowledge` | knowledge catalog (families, counts) + per-domain coverage |
| `--gap-analysis` | code-derived matrix: KB→detection→validation→checker gaps |
| `--capability-matrix` | per-capability status (what it can/can't do) + reasons |
| `--capability-matrix --json` | same, machine-readable JSON |
| `--dry-run` | show the execution plan for a target; run nothing |

## Setup commands

| Command | What it does |
|---|---|
| `--install [groups…]` | install external scanners in one shot, then exit. Groups: `recon web network mobile cloud code container` (default: all) |
| `--auto-install` | before a scan, auto-install the target-kind's missing tools |
| `--update` / `--check-updates` | refresh CVE feeds (CISA KEV + NVD) into `data/` |

---

## Target & selection

| Flag | Default | Meaning |
|---|---|---|
| `--profile P` | inferred | `bugbounty`,`redteam`,`enterprise`,`purple`,`web`,`api`,`mobile`,`cloud`,`network`,`code` |
| `--mode {fast,deep}` | `fast` | quick vs thorough (deep adds safe validation + attack paths) |
| `--deep` | — | alias for `--mode deep` |
| `--type KIND` | auto | force kind: `recon web api network mobile cloud container kubernetes code linux windows` |
| `--scope FILE` | — | scope file (one entry/line: domains, `*.wildcards`, IPs, CIDRs, `!exclusions`) |
| `--program FILE` | — | bug-bounty program YAML: scope + required headers + rate limit + out-of-scope finding rules |
| `--policy FILE` | profile default | safety-level policy YAML (see `policies/`) |

## Execution & performance

| Flag | Default | Meaning |
|---|---|---|
| `--skip t1,t2` | — | comma list of tools to skip |
| `--workers N` | 8 | max concurrent workers |
| `--timeout S` | 30 | per-tool timeout (seconds) |
| `--no-plugins` | off | disable plugin loading |
| `--yes` | off | skip the authorization prompt (owned assets / CI) |

## Authentication (values are redacted from all output)

| Flag | Meaning |
|---|---|
| `--cookie "k=v"` | session cookie |
| `--header "Name: value"` | extra header (repeatable) |
| `--token T` / `--api-key K` | bearer token / API key |
| `--username U` | username context |
| `--aws-profile` / `--gcp-project` / `--azure-subscription` | cloud creds context |

## Output & reporting

| Flag | Default | Meaning |
|---|---|---|
| `--out DIR` | `report-<profile>-<target>-<ts>` | output directory |
| `--formats …` | `md,json,html` | any of `md,json,csv,html,pdf,sarif` |
| `--bundle` | off | professional bundle (executive + technical + artifacts + evidence) |

## Baseline / retest / triage / resume

| Flag | Meaning |
|---|---|
| `--baseline` | save this run as the retest baseline for the target |
| `--retest` | diff against the saved baseline (auto-located) |
| `--compare FILE` | diff against a specific `report.json` |
| `--triage-file FILE` | persistent triage store (fingerprint→status) applied across scans |
| `--mark "FP=STATUS[:note]"` | record a triage decision (needs `--triage-file`). Statuses: `open, validated, false_positive, accepted_risk, fixed, retest_required` |
| `--resume SCAN-ID` | rebuild from checkpoint without rescanning |

## CI gating (exit non-zero to fail a pipeline)

| Flag | Meaning |
|---|---|
| `--fail-on {critical,high,medium,low,info}` | fail if any active finding ≥ this severity |
| `--fail-on-kev` | fail if any actively-exploited (CISA KEV) finding is present |
| `--fail-on-new` | fail if new findings vs `--compare` baseline |

## Authorized data exports (read-only; never touches a live host)

| Flag | Meaning |
|---|---|
| `--identity-file FILE` | identity graph export (JSON / BloodHound) → AD/cloud privilege paths |
| `--threat-input FILE` | authorized host/cloud export (JSON) → threat-indicator detection |
| `--ioc-file FILE` | IOC feed (hashes/domains/IPs) used with `--threat-input` |
| `--telemetry FILE` | SIEM/EDR/IDS detections export → purple-team detection verification |
| `--se-input FILE` | authorized awareness-campaign RESULTS (analysis only; needs policy opt-in) |

## Availability (safe)

| Flag | Meaning |
|---|---|
| `--load-test` | bounded, opt-in, **LAB-only** resilience test (requires lab policy + `dos.enabled`; hard-capped, rate-limited, abortable — never a DoS/flood) |

---

## Examples

```bash
# interactive
python3 vulnscan.py

# website / API, deep, authenticated
python3 vulnscan.py https://app.example.com --profile web --mode deep \
    --cookie "session=…" --header "Authorization: Bearer …"

# bug bounty in scope
python3 vulnscan.py example.com --profile bugbounty --mode deep --scope scope.txt
python3 vulnscan.py example.com --program programs/your-program.yaml

# network / repo / container / cloud / mobile
python3 vulnscan.py 10.0.0.0/24 --profile network --yes
python3 vulnscan.py ./my-project                       # SCA + secrets + SAST + CI/CD + IaC
python3 vulnscan.py nginx:1.21
python3 vulnscan.py ./terraform
python3 vulnscan.py ./app.apk

# authorized exports
python3 vulnscan.py host.json --type linux
python3 vulnscan.py --identity-file ad.json example.com
python3 vulnscan.py --telemetry siem.json --profile purple example.com

# CI gating + SARIF
python3 vulnscan.py https://ci-target --yes --formats sarif --fail-on high --fail-on-kev

# baseline then retest
python3 vulnscan.py example.com --baseline
python3 vulnscan.py example.com --retest

# resume an interrupted deep scan
python3 vulnscan.py --resume SCAN-20260101-120000-abcdef01

# introspection
python3 vulnscan.py --capability-matrix
python3 vulnscan.py --dry-run example.com --profile redteam --mode deep
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | completed (or gate passed) |
| `2` | authorization not confirmed / bad arguments / nothing to do |
| non-zero (gating) | a `--fail-on*` threshold was hit |
| `130` | interrupted (Ctrl-C) |
