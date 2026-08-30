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
