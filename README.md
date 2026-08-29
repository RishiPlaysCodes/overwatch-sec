# vulnscan — Master Multi-Target Vulnerability Scanner

**One command. One target. Full report.** vulnscan auto-detects whether your
target is a **website**, a **mobile app**, or **cloud / IaC**, runs the right
suite of checks + industry tools, and produces a single report that for every
finding explains **what it is**, **how an attacker exploits it**, and **how to
fix it** — mapped to **OWASP Top 10** and **CWE / SANS Top 25**.

```bash
python3 vulnscan.py https://example.com     # website
python3 vulnscan.py ./app.apk               # mobile (APK / IPA)
python3 vulnscan.py ./terraform/            # cloud IaC (Terraform / CloudFormation)
python3 vulnscan.py aws                      # live cloud account (aws / azure / gcp)
```

> ⚠️ **Authorized use only.** Run ONLY against systems, apps, and cloud accounts
> you own or have explicit written permission to test. The tool asks you to
> confirm authorization before it starts (`--yes` to skip on owned assets/CI).
>
> 🚫 **No DoS/DDoS.** Denial-of-service / stress / flood testing is intentionally
> excluded — it is a destructive attack, not a vulnerability check. Everything
> here only **detects and reports**; nothing is exploited.

---

## What it covers

### 🌐 Web (OWASP Top 10 / CWE Top 25)
Built-in: security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer,
Permissions), cookie flags (Secure/HttpOnly/SameSite), reflected-input XSS
indicator, form + file-upload surface discovery, tech/version info-leak.
Tools (auto-detected): `nmap`, `whatweb`, `testssl.sh`, `nikto`, `nuclei`
(CVE templates), `sqlmap` (detection-only, safe).

### 📱 Mobile (OWASP Mobile Top 10 / MASVS)
Static analysis of `.apk` / `.ipa`: cleartext traffic, debuggable build,
allowBackup, exported components without permission, dangerous permissions,
iOS ATS exceptions, and hardcoded secrets / API keys (AWS, Google, Slack,
private keys, generic). Optional deep analysis via **MobSF** (`MOBSF_URL` +
`MOBSF_APIKEY`) and `apkleaks`.

### ☁️ Cloud & IaC (OWASP Cloud / CIS)
Built-in IaC checks (Terraform / CloudFormation): public storage buckets,
security groups open to `0.0.0.0/0` on sensitive ports, unencrypted stores,
wildcard IAM policies (`Action:*`/`Resource:*`), public IPs, disabled logging.
Tools (auto-detected): `checkov`, `trivy config`, `prowler` (AWS),
`scoutsuite` (multi-cloud).

---

## How the auto-adjust works

`vulnscan.py` inspects the target and picks a **profile**:

| Target looks like | Profile |
|---|---|
| `aws` / `azure` / `gcp` | cloud (live) |
| ends in `.apk` / `.ipa` / `.xapk` | mobile |
| a directory (with `.tf`/`.yaml`/…) | cloud (IaC) |
| a URL or hostname | web |

Force it with `--type {web,mobile,cloud}` if needed.

## Install

### Quick setup on Kali / Debian / Ubuntu (one command)

```bash
chmod +x install.sh
./install.sh                # install all groups (web + mobile + cloud)
./install.sh web            # only web tools
./install.sh web mobile     # pick groups
```

The installer handles Kali's PEP-668 (`--break-system-packages`) automatically,
updates nuclei templates, and skips anything it can't install (vulnscan just
skips missing tools at scan time).

### Manual install

Core needs only **Python 3.9+**. `requests` is optional (falls back to urllib):

```bash
pip install -r requirements.txt
```

Install whichever scanners you want — missing ones are skipped with a hint:

```bash
# Web
sudo apt install nmap nikto whatweb sqlmap
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
git clone --depth 1 https://github.com/drwetter/testssl.sh   # add to PATH

# Mobile
pip install apkleaks                 # + MobSF (docker) for deep analysis

# Cloud
pip install checkov prowler scoutsuite
# trivy: https://github.com/aquasecurity/trivy
```

## Usage

```bash
python3 vulnscan.py <target> [--type auto|web|mobile|cloud] [--out DIR] [--skip t1,t2] [--yes]
```

Examples:
```bash
python3 vulnscan.py https://your-site.com
python3 vulnscan.py ./release.apk --out mobile-report
python3 vulnscan.py ./infra/terraform --skip trivy
python3 vulnscan.py https://staging.internal --yes        # CI, owned asset
```

## Output

Everything lands in `report-<profile>-<target>-<timestamp>/`:
- **`report.md`** — findings sorted by severity, each with CWE + OWASP mapping,
  evidence, *What it is*, *Attack scenario*, and *Fix / patch*.
- **`report.json`** — machine-readable.
- Raw tool outputs (`nmap.txt`, `nuclei.txt`, `checkov.txt`, …).

## Project layout

```
vulnscan.py         # entry point: detection, auth gate, dispatch, reporting
common.py           # shared helpers (shell, HTTP, finding builder)
knowledgebase.py    # every finding: CWE/OWASP + description/attack/patch
scanner_web.py      # website checks + tool wrappers
scanner_mobile.py   # APK/IPA static analysis
scanner_cloud.py    # IaC + live-cloud checks/wrappers
```

Add coverage by adding an entry to `knowledgebase.py` and emitting it via
`common.finding("<id>", "<evidence>")` from the relevant scanner.

## Notes
- Findings are **indicators** — validate manually before acting/reporting.
- The tool never exploits, never performs DoS, and requires authorization.
