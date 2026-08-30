# Install

The platform core runs on **Python 3.9+ stdlib only**. External security tools
and PyYAML are optional — missing ones are skipped and reported in coverage.

## Quick

```bash
git clone https://github.com/RishiPlaysCodes/script-test-case.git
cd script-test-case
python3 overwatch.py --version          # core works immediately (stdlib only)
```

## Recommended — install everything in one shot (Kali / Debian / Ubuntu / WSL)

```bash
python3 overwatch.py --install          # installs ALL external scanners, then exits
# equivalent to:  ./install.sh
python3 feeds/update_feeds.py          # pull fresh CISA KEV + NVD data
```

The installer is reliable and idempotent: it uses apt first, then `go install`
(with retries + a proxy fallback), then curl/pip/pipx fallbacks, and it
**symlinks Go-built binaries into `/usr/local/bin`** so they are on `PATH`
immediately — no "installed but shows as not installed" and no need to open a
new terminal. Anything it still can't install is listed at the end with the
exact command to finish it.

Install only specific groups:
```bash
python3 overwatch.py --install recon web      # or: ./install.sh recon web
```

Let overwatch install a target's tools automatically, right before scanning:
```bash
python3 overwatch.py https://your-site.com --auto-install
```

Manual equivalent:
```bash
chmod +x install.sh
./install.sh                           # installs all tool groups
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
python3 overwatch.py --list-tools
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
