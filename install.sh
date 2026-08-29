#!/usr/bin/env bash
#
# install.sh — one-command setup for vulnscan on Kali Linux / Debian / Ubuntu.
#
# Installs the external scanners vulnscan can orchestrate (web / mobile / cloud)
# plus the optional Python dependency. Anything that fails to install is skipped
# with a warning — vulnscan still runs and just skips missing tools at scan time.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh              # install everything (web + mobile + cloud)
#   ./install.sh web          # only web tools
#   ./install.sh web mobile   # web + mobile
#
set -uo pipefail

# ---- pretty output --------------------------------------------------------
if [ -t 1 ]; then
  R="\033[31m"; G="\033[32m"; Y="\033[33m"; B="\033[34m"; C="\033[36m"; Z="\033[0m"; BOLD="\033[1m"
else
  R=""; G=""; Y=""; B=""; C=""; Z=""; BOLD=""
fi
info()  { echo -e "${B}[*]${Z} $*"; }
ok()    { echo -e "${G}[+]${Z} $*"; }
warn()  { echo -e "${Y}[!]${Z} $*"; }
err()   { echo -e "${R}[x]${Z} $*"; }
title() { echo -e "\n${C}======================================================================${Z}\n${C}== $*${Z}\n${C}======================================================================${Z}"; }

# ---- sudo helper ----------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    warn "not root and sudo not found — apt installs may fail"
  fi
fi

# ---- which groups to install ---------------------------------------------
GROUPS=("$@")
if [ ${#GROUPS[@]} -eq 0 ]; then GROUPS=(web mobile cloud); fi
want() { for g in "${GROUPS[@]}"; do [ "$g" = "$1" ] && return 0; done; return 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# pip flag for Kali's externally-managed environment (PEP 668)
PIP_FLAG=""
if pip install --help 2>/dev/null | grep -q "break-system-packages"; then
  PIP_FLAG="--break-system-packages"
fi
pip_install() {
  if have pip3; then pip3 install $PIP_FLAG "$@";
  elif have pip; then pip install $PIP_FLAG "$@";
  else warn "pip not found — skipping: $*"; fi
}
apt_install() {
  $SUDO apt-get install -y "$@" 2>/dev/null && ok "installed: $*" || warn "could not apt-install: $*"
}

# ---------------------------------------------------------------------------
title "vulnscan setup — groups: ${GROUPS[*]}"

if have apt-get; then
  info "updating apt package index…"
  $SUDO apt-get update -y >/dev/null 2>&1 && ok "apt index updated" || warn "apt update failed (continuing)"
else
  warn "apt-get not found — this script targets Kali/Debian/Ubuntu. Install tools manually."
fi

# ---- core python dep ------------------------------------------------------
title "Python dependencies"
if [ -f requirements.txt ]; then
  pip_install -r requirements.txt && ok "python deps installed" || warn "python deps may be incomplete"
else
  pip_install requests
fi

# ---- WEB ------------------------------------------------------------------
if want web; then
  title "Web tools (nmap, nikto, sqlmap, whatweb, nuclei, testssl)"
  apt_install nmap nikto sqlmap whatweb
  apt_install nuclei || {
    if have go; then
      info "installing nuclei via go…"
      go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && ok "nuclei installed (add \$HOME/go/bin to PATH)"
    else
      warn "nuclei not installed (no apt package + no go)"
    fi
  }
  if have nuclei; then info "updating nuclei templates…"; nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates updated"; fi
  apt_install testssl.sh
fi

# ---- MOBILE ---------------------------------------------------------------
if want mobile; then
  title "Mobile tools (apkleaks, apktool, jadx)"
  pip_install apkleaks && ok "apkleaks installed" || warn "apkleaks failed"
  apt_install apktool jadx
  info "Tip: for deep mobile analysis run MobSF via Docker and set MOBSF_URL + MOBSF_APIKEY"
fi

# ---- CLOUD ----------------------------------------------------------------
if want cloud; then
  title "Cloud tools (checkov, prowler, scoutsuite, trivy)"
  pip_install checkov prowler scoutsuite && ok "cloud python tools installed" || warn "some cloud python tools failed"
  apt_install trivy || {
    warn "trivy not in apt — install from https://github.com/aquasecurity/trivy/releases"
  }
fi

# ---- summary --------------------------------------------------------------
title "Verification"
check() { if have "$1"; then ok "$1 ✓"; else warn "$1 — not installed (vulnscan will skip it)"; fi; }
want web    && for t in nmap nikto sqlmap whatweb nuclei testssl.sh; do check "$t"; done
want mobile && for t in apkleaks apktool jadx; do check "$t"; done
want cloud  && for t in checkov prowler scout trivy; do check "$t"; done

echo
ok "Setup complete. Run a scan, e.g.:"
echo -e "   ${BOLD}python3 vulnscan.py https://your-site.com${Z}"
echo -e "   ${BOLD}python3 vulnscan.py ./app.apk${Z}"
echo -e "   ${BOLD}python3 vulnscan.py ./terraform/${Z}"
warn "Authorized targets only."
