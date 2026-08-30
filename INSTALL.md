# Install

The platform core runs on **Python 3.9+ stdlib only**. External security tools
and PyYAML are optional — missing ones are skipped and reported in coverage.

## Quick

```bash
git clone https://github.com/RishiPlaysCodes/script-test-case.git
cd script-test-case
python3 vulnscan.py --version          # core works immediately (stdlib only)
```

## Recommended (Kali / Debian / Ubuntu / WSL / macOS)

```bash
chmod +x install.sh
./install.sh                           # installs tool groups; skips what it can't
python3 feeds/update_feeds.py          # pull fresh CISA KEV + NVD data
```

Optional Python extras:
```bash
pip install -r requirements.txt        # requests, and pyyaml/pytest (optional)
```

## Tool groups (install what you need)

| Group | Tools |
|---|---|
| recon | subfinder, httpx, naabu, dnsx, katana, gau, waybackurls, gowitness, amass, wafw00f |
| web   | nuclei, nikto, whatweb, testssl.sh, sqlmap, ffuf/feroxbuster |
| network | nmap, searchsploit |
| mobile | apkleaks, apktool, jadx (+ MobSF via Docker) |
| cloud | checkov, trivy, prowler, scoutsuite |
| code  | semgrep, gitleaks, grype, osv-scanner, pip-audit |

Check what's detected:
```bash
python3 vulnscan.py --list-tools
```

## Tests

```bash
pip install pytest && pytest            # full suite
# or, with no dependencies at all:
python3 tests/run_tests.py
```

## Self-updating feeds

- GitHub Actions (`.github/workflows/update-feeds.yml`) refreshes feeds daily in
  the cloud.
- Local schedule: `./deploy/install-scheduler.sh` (systemd timer or cron).
