# vulnscan — Master Multi-Platform Vulnerability Scanner

**One command. One target. Full report.** vulnscan auto-detects your target and
runs the right suite of checks + industry tools across **six platforms** —
website, mobile app, cloud/IaC, network/host, source code, and container images.
Every finding is explained: **what it is**, **how an attacker exploits it**, and
**how to fix it** — mapped to **OWASP Top 10** and **CWE / SANS Top 25**, and
(for CVEs) enriched with **CVSS** and the **CISA KEV** actively-exploited flag.

## ⚡ Just one command (same on every device)

```bash
./run.sh
```

That's it. On the **first run** it auto-installs the tools and pulls fresh CVE
data; then it **asks what you want to scan** (website / network / mobile / code /
container / cloud) and does the rest. Every run after that just scans (fast).

Brand-new machine? One line does the whole thing (Kali / Ubuntu / Debian / macOS / WSL):
```bash
git clone https://github.com/RishiPlaysCodes/script-test-case.git && cd script-test-case && ./run.sh
```

Prefer to pass the target directly (it still auto-sets-up once, then auto-detects the type):
```bash
./run.sh https://example.com      # website
./run.sh 192.168.1.0/24           # network / host / CIDR
./run.sh ./app.apk                # mobile (APK / IPA)
./run.sh ./my-project             # source code (deps + secrets + SAST)
./run.sh nginx:1.21               # container image
./run.sh ./terraform/             # cloud IaC
./run.sh aws                      # live cloud account
```

`run.sh` extras: `--setup` (redo tool install), `--update` (refresh feeds now),
`--no-setup` (skip setup, just scan). Any `vulnscan.py` flag (`--yes`, `--type`,
`--skip`, `--out`) is passed straight through.

<details>
<summary>Advanced: call the Python scanner directly</summary>

```bash
python3 vulnscan.py               # asks what to scan (interactive)
python3 vulnscan.py https://example.com
python3 vulnscan.py ./app.apk
python3 vulnscan.py aws
```
</details>

> ⚠️ **Authorized use only.** Run ONLY against systems, apps, and accounts you
> own or have explicit written permission to test. The tool asks you to confirm
> authorization before it starts (`--yes` to skip on owned assets/CI).
>
> 🚫 **No DoS/DDoS.** Denial-of-service / stress / flood testing is intentionally
> excluded — it is a destructive attack, not a vulnerability check. vulnscan only
> **detects, explains, and prioritizes**; it never weaponizes or runs exploit code.

---

## Honest scope

No tool checks *literally every* vulnerability — new CVEs land daily. vulnscan
gets comprehensive by **orchestrating best-in-class engines per layer** and
enriching results from **continuously-updated feeds** (nuclei templates,
Trivy/Grype DBs, OSV, NVD, CISA KEV). It reports **indicators** to validate, and
tells you which issues are **actively exploited in the wild** so you patch those
first.

---

## 🐉 Kali Linux — full workflow (step by step)

Copy-paste in order. Most tools ship with Kali already; the installer grabs the rest.

**Step 1 — Get the code**
```bash
git clone https://github.com/RishiPlaysCodes/script-test-case.git
cd script-test-case
```

**Step 2 — Install everything (one command)**
```bash
chmod +x install.sh deploy/install-scheduler.sh feeds/update_feeds.py
./install.sh                     # web + mobile + cloud + code + network tools
# or pick groups:  ./install.sh web network code
```
If pip complains about "externally-managed-environment", the installer already
passes `--break-system-packages`; for manual pip use add that flag yourself.

**Step 3 — Pull fresh vulnerability data (CISA KEV + NVD)**
```bash
python3 feeds/update_feeds.py            # fills data/ so CVE enrichment is current
```

**Step 4 — Run a scan (pick your target type — it auto-detects)**
```bash
python3 vulnscan.py https://your-site.com        # website
python3 vulnscan.py 192.168.1.10                  # network / host
python3 vulnscan.py 192.168.1.0/24                # whole subnet
python3 vulnscan.py ./your-app.apk                # mobile app
python3 vulnscan.py ./source-code-folder          # code + dependencies + secrets
python3 vulnscan.py nginx:1.21                     # container image
python3 vulnscan.py ./terraform                    # cloud IaC
python3 vulnscan.py aws                            # live cloud account
```
It asks you to confirm authorization — type `I AM AUTHORIZED`. On your own
assets / in CI, add `--yes` to skip the prompt.

**Step 5 — Read the report**
```bash
ls report-*/                       # a timestamped folder per scan
xdg-open report-*/report.md        # or: cat report-*/report.md
```
Each finding shows: severity (incl. CRITICAL), CWE + OWASP, evidence, *what it
is*, *attack scenario*, and *fix / patch*. Actively-exploited (CISA KEV) issues
are flagged "patch first".

**Step 6 (optional) — Auto-refresh the CVE data on this machine**
```bash
./deploy/install-scheduler.sh          # systemd daily timer (or --cron)
```

**Handy flags**
```bash
--type web|mobile|cloud|network|code|container   # force the profile
--skip nuclei,sqlmap                              # skip specific tools
--out my-report                                   # custom output folder
--yes                                             # skip auth prompt (owned assets)
```

**One-liner quick start**
```bash
git clone https://github.com/RishiPlaysCodes/script-test-case.git && cd script-test-case && chmod +x install.sh && ./install.sh && python3 feeds/update_feeds.py && python3 vulnscan.py https://your-site.com
```

---

## What it covers

### 🌐 Web (OWASP Top 10 / CWE Top 25)
Built-in: security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer,
Permissions), cookie flags, reflected-input XSS indicator, form + file-upload
discovery, tech/version info-leak. Tools: `nmap`, `whatweb`, `testssl.sh`,
`nikto`, `nuclei` (CVE templates), `sqlmap` (detection-only, safe).

### 📱 Mobile (OWASP Mobile Top 10 / MASVS)
Static analysis of `.apk` / `.ipa`: cleartext traffic, debuggable, allowBackup,
exported components without permission, dangerous permissions, iOS ATS, and
hardcoded secrets/API keys. Optional deep analysis via **MobSF** + `apkleaks`.

### ☁️ Cloud & IaC (OWASP Cloud / CIS)
Built-in Terraform/CloudFormation checks: public buckets, security groups open
to `0.0.0.0/0`, unencrypted stores, wildcard IAM, public IPs, disabled logging.
Tools: `checkov`, `trivy config`, `prowler` (AWS), `scoutsuite` (multi-cloud).

### 🖧 Network / Host / Infra
Goes beyond web (what Nikto/web-only tools can't do): `nmap -sV` service/version
discovery, `nmap --script vuln` (NSE known-vuln checks, **dos category excluded**),
`searchsploit` Exploit-DB correlation, and an **OpenVAS / Greenbone (GVM)** hook
for deep authenticated NVT coverage. Discovered CVEs are KEV/CVSS-enriched.

### 💻 Source code + Dependencies (SCA) + Secrets
Point at a repo/dir: dependency CVEs via `osv-scanner`, `trivy fs`, `grype`,
`pip-audit`, `npm audit`; secrets via a built-in regex sweep + `gitleaks`;
insecure patterns via `semgrep` (SAST). CVEs are KEV/CVSS-enriched.

### 📦 Container images
Point at an image ref (`repo/app:tag`): OS + language package CVEs, secrets, and
misconfig via `trivy image` and `grype`. CVEs are KEV/CVSS-enriched.

### 🎯 CVE intelligence (`cve_intel.py`)
Every discovered CVE is enriched (offline-safe) with:
- **CISA KEV** — is it *actively exploited in the wild*? (top patch priority)
- **NVD** — CVSS base score + severity + summary

---

## How the auto-adjust works

| Target looks like | Profile |
|---|---|
| `aws` / `azure` / `gcp` | cloud (live) |
| ends in `.apk` / `.ipa` / `.xapk` | mobile |
| directory with `.tf`/`.template` | cloud (IaC) |
| directory with code / manifests | code (SCA + secrets) |
| IP address or CIDR | network |
| `name:tag` / `repo/app:tag` / `@sha256:` | container |
| URL or hostname | web |

Force it with `--type {web,mobile,cloud,network,code,container}`.

## Install

Core needs only **Python 3.9+**. `requests` is optional (falls back to urllib):

```bash
pip install -r requirements.txt
```

Install whichever engines you want — **missing ones are skipped with a hint**:

```bash
# Web
sudo apt install nmap nikto whatweb sqlmap nuclei testssl.sh

# Network / infra
sudo apt install nmap exploitdb        # searchsploit; + greenbone/gvm for OpenVAS

# Source code / SCA / secrets
pip install semgrep pip-audit
# osv-scanner, grype, gitleaks, trivy: see each project's releases

# Cloud
pip install checkov prowler scoutsuite   # + trivy

# Mobile
pip install apkleaks                      # + MobSF (docker) for deep analysis
```

> On Kali, `./install.sh` sets up the common tool groups in one shot.

## Usage

```bash
python3 vulnscan.py <target> [--type auto|web|mobile|cloud|network|code|container] \
                    [--out DIR] [--skip t1,t2] [--yes]
```

Examples:
```bash
python3 vulnscan.py https://your-site.com
python3 vulnscan.py ./release.apk --out mobile-report
python3 vulnscan.py 192.168.1.0/24 --type network
python3 vulnscan.py ./service --type code --skip semgrep
python3 vulnscan.py myrepo/api:latest
```

## Output

Everything lands in `report-<profile>-<target>-<timestamp>/`:
- **`report.md`** — findings sorted by severity (incl. `CRITICAL`), each with
  CWE + OWASP mapping, evidence, *What it is*, *Attack scenario*, *Fix / patch*,
  plus a **CISA KEV "patch first"** callout for actively-exploited CVEs.
- **`report.json`** — machine-readable.
- Raw tool outputs (`nmap-vuln.txt`, `trivy-fs.txt`, `nuclei.txt`, …).

## Project layout

```
vulnscan.py          # entry: detection, auth gate, dispatch, reporting
common.py            # shared helpers (shell, HTTP, finding builder)
knowledgebase.py     # every finding: CWE/OWASP + description/attack/patch
cve_intel.py         # NVD CVSS + CISA KEV enrichment (offline-safe)
scanner_web.py       # website checks + tool wrappers
scanner_mobile.py    # APK/IPA static analysis
scanner_cloud.py     # IaC + live-cloud checks/wrappers
scanner_network.py   # nmap NSE vuln + searchsploit + OpenVAS/GVM hook
scanner_code.py      # SCA + secrets + SAST for source trees
scanner_container.py # trivy/grype image CVE scanning
```

Add coverage by adding an entry to `knowledgebase.py` and emitting it via
`common.finding("<id>", "<evidence>")` from the relevant scanner.

## Staying current — self-updating feeds (no live session needed)

The *code* rarely changes; the **vulnerability data** does. A pipeline refreshes
that data on a schedule so vulnscan stays current on its own — **even when your
machine is off**.

`feeds/update_feeds.py` downloads public feed data into `data/`:
- `kev.json` — CISA Known Exploited Vulnerabilities (actively-exploited CVEs)
- `nvd_recent.json` — recently-modified NVD CVEs with CVSS
- and refreshes `nuclei` / `trivy` / `grype` local DBs if installed

`cve_intel.py` reads `data/` first, so enrichment works **fully offline**.

Two ways to schedule it (use either or both):

**1. GitHub Actions (runs in the cloud — works when your PC is off)**
`.github/workflows/update-feeds.yml` runs daily on GitHub's servers, refreshes
the feeds, and commits them back to the repo. Nothing to install; enable Actions
and (optionally) trigger it manually from the **Actions** tab. Adjust the `cron:`
for a shorter interval if you want it fresher.

**2. Local systemd timer / cron (runs when this machine is on)**
```bash
./deploy/install-scheduler.sh          # systemd user timer (daily), or:
./deploy/install-scheduler.sh --cron   # cron fallback
```
Run a refresh manually any time:
```bash
python3 feeds/update_feeds.py            # KEV + NVD (+ tool DBs)
python3 feeds/update_feeds.py --kev      # just the actively-exploited list
```

> Practical note: "real-time" here means *scheduled* (e.g. daily/hourly) — CISA
> KEV and NVD publish in batches, not continuously, so a daily refresh keeps you
> effectively current.

## Notes
- Findings are **indicators** — validate manually before acting/reporting.
- CVE enrichment is **offline-safe**: if feeds are unreachable, the scan still
  completes; CVSS/KEV fields are simply omitted.
- The tool never exploits, never performs DoS, and requires authorization.
