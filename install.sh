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
#   ./install.sh                 # install everything (recon web network mobile cloud code)
#   ./install.sh recon           # only bug-bounty recon tools
#   ./install.sh recon web       # pick groups
#
# Groups: recon | web | network | mobile | cloud | code | container
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
if [ ${#GROUPS[@]} -eq 0 ]; then GROUPS=(recon web network mobile cloud code); fi
want() { for g in "${GROUPS[@]}"; do [ "$g" = "$1" ] && return 0; done; return 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# make freshly go-installed binaries visible to this script AND to future shells
export GOBIN="$HOME/go/bin"
mkdir -p "$GOBIN"
case ":$PATH:" in *":$GOBIN:"*) : ;; *) export PATH="$PATH:$GOBIN" ;; esac

# ensure Go exists (needed for many recon tools) ----------------------------
ensure_go() {
  if have go; then return 0; fi
  info "Go not found — installing (needed for recon tools)…"
  $SUDO apt-get install -y golang-go >/dev/null 2>&1
  have go && ok "Go installed" || warn "could not install Go — Go-based tools will be skipped"
}

# go install helper (many recon tools are Go binaries) ----------------------
go_install() {
  # $1 = binary name to check, $2 = go module path
  if have "$1"; then ok "$1 already present"; return 0; fi
  if ! have go; then
    warn "$1 skipped — Go not available"; return 1
  fi
  info "go install $2 … (first build can take a minute)"
  if GOBIN="$GOBIN" go install "$2" >/dev/null 2>&1 && have "$1"; then
    ok "$1 installed -> $GOBIN/$1"
  else
    warn "go install failed for $1 (network/proxy?) — vulnscan will skip it"
  fi
}

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
  apt_install nmap nikto sqlmap whatweb testssl.sh
  if ! have nuclei; then
    apt_install nuclei
    if ! have nuclei; then ensure_go; go_install nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"; fi
  fi
  if have nuclei; then info "updating nuclei templates…"; nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates updated"; fi
fi

# ---- RECON (bug bounty) ---------------------------------------------------
if want recon; then
  title "Recon tools (subfinder, httpx, naabu, dnsx, katana, nuclei, ffuf, gau, gowitness, amass, wafw00f)"
  # Kali often packages some of these; try apt first, then go install.
  apt_install amass wafw00f ffuf assetfinder seclists
  ensure_go
  # ProjectDiscovery + friends via go
  go_install subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  go_install httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  go_install naabu       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  go_install dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  go_install katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
  go_install nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  go_install gau         "github.com/lc/gau/v2/cmd/gau@latest"
  go_install waybackurls "github.com/tomnomnom/waybackurls@latest"
  go_install gowitness   "github.com/sensepost/gowitness@latest"
  if have nuclei; then info "updating nuclei templates…"; nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates updated"; fi
  info "Tip: install 'seclists' for content-discovery wordlists (used in --deep)."
fi

# ---- NETWORK --------------------------------------------------------------
if want network; then
  title "Network tools (nmap, searchsploit/exploitdb)"
  apt_install nmap exploitdb
  info "Tip: install Greenbone/OpenVAS (gvm) separately for deep authenticated NVT scans."
fi

# ---- CODE / SCA -----------------------------------------------------------
if want code; then
  title "Code / SCA tools (semgrep, pip-audit, gitleaks, grype, osv-scanner, trivy)"
  pip_install semgrep pip-audit && ok "python SCA tools installed" || warn "some python SCA tools failed"
  apt_install gitleaks
  ensure_go
  go_install osv-scanner "github.com/google/osv-scanner/cmd/osv-scanner@latest"
  if ! have grype; then
    info "installing grype…"
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | $SUDO sh -s -- -b /usr/local/bin >/dev/null 2>&1 \
      && ok "grype installed" || warn "grype install failed (see github.com/anchore/grype)"
  fi
  apt_install trivy || warn "trivy not in apt — see github.com/aquasecurity/trivy/releases"
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
want recon   && for t in subfinder httpx naabu dnsx katana nuclei ffuf gau gowitness amass wafw00f; do check "$t"; done
want web     && for t in nmap nikto sqlmap whatweb nuclei testssl.sh; do check "$t"; done
want network && for t in nmap searchsploit; do check "$t"; done
want mobile  && for t in apkleaks apktool jadx; do check "$t"; done
want cloud   && for t in checkov prowler scout trivy; do check "$t"; done
want code    && for t in semgrep pip-audit gitleaks grype osv-scanner trivy; do check "$t"; done

# persist ~/go/bin on PATH so tools are found in future shells (idempotent)
if [ -d "$GOBIN" ] && ls "$GOBIN" >/dev/null 2>&1; then
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    if ! grep -q 'go/bin' "$rc" 2>/dev/null; then
      echo 'export PATH="$PATH:$HOME/go/bin"' >> "$rc"
      ok "added \$HOME/go/bin to $(basename "$rc")"
    fi
  done
  echo; warn "Go tools were installed to $GOBIN."
  echo -e "   Open a NEW terminal, or run:  ${BOLD}export PATH=\"\$PATH:\$HOME/go/bin\"${Z}"
fi

echo
ok "Setup complete. Run a scan, e.g.:"
echo -e "   ${BOLD}python3 vulnscan.py --type recon example.com${Z}   ${C}# bug-bounty recon${Z}"
echo -e "   ${BOLD}python3 vulnscan.py https://your-site.com${Z}"
echo -e "   ${BOLD}python3 vulnscan.py ./app.apk${Z}"
warn "Authorized / in-scope targets only. Detection & recon — no auto-exploitation."
