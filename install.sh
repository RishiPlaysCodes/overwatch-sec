#!/usr/bin/env bash
#
# install.sh — one-command setup for vulnscan on Kali Linux / Debian / Ubuntu.
#
# Installs EVERY external scanner vulnscan can orchestrate (recon/web/network/
# mobile/cloud/code/container) plus Python deps, in one shot. It is designed to
# be reliable and idempotent:
#   * apt first, then `go install`, then curl/pip/pipx fallbacks
#   * go-built binaries are SYMLINKED into /usr/local/bin so they are on PATH
#     immediately (fixes the "installed but shows as not installed" problem)
#   * flaky `go install` is retried, incl. a GOPROXY=direct fallback
#   * at the end it prints EXACTLY which tools are still missing and the precise
#     command to finish each one — nothing silently disappears.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh                 # install EVERYTHING (recommended)
#   ./install.sh recon web       # only chosen groups
#
# Groups: recon | web | network | mobile | cloud | code | container | all
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

# remediation notes collected for anything still missing at the end
declare -A FIXME

# ---- sudo helper ----------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    warn "not root and sudo not found — apt/system installs may fail (run as root or install sudo)"
  fi
fi

# ---- which groups to install ---------------------------------------------
GROUPS=("$@")
if [ ${#GROUPS[@]} -eq 0 ]; then GROUPS=(recon web network mobile cloud code container); fi
for g in "${GROUPS[@]}"; do
  if [ "$g" = "all" ]; then GROUPS=(recon web network mobile cloud code container); break; fi
done
want() { for g in "${GROUPS[@]}"; do [ "$g" = "$1" ] && return 0; done; return 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---- Go env: make builds resilient + binaries globally visible ------------
export GOBIN="$HOME/go/bin"
export GOPATH="${GOPATH:-$HOME/go}"
export GO111MODULE=on
export GOFLAGS="${GOFLAGS:-}"
mkdir -p "$GOBIN"
case ":$PATH:" in *":$GOBIN:"*) : ;; *) export PATH="$PATH:$GOBIN" ;; esac

# symlink a freshly-built go binary into /usr/local/bin so it's on PATH now,
# in THIS shell and every future one — no "open a new terminal" dance.
publish_bin() {
  local name="$1"
  if [ -x "$GOBIN/$name" ]; then
    if [ -w /usr/local/bin ] || [ -n "$SUDO" ]; then
      $SUDO ln -sf "$GOBIN/$name" "/usr/local/bin/$name" 2>/dev/null && return 0
    fi
  fi
  return 1
}

ensure_go() {
  if have go; then return 0; fi
  info "Go not found — installing (needed for several recon/web tools)…"
  $SUDO apt-get install -y golang-go >/dev/null 2>&1
  have go && ok "Go $(go version 2>/dev/null | awk '{print $3}') installed" \
          || warn "could not install Go — Go-based tools will be skipped"
}

# go install with retry + proxy fallback, then publish to /usr/local/bin
go_install() {
  # $1 = binary name, $2 = go module path
  local name="$1" mod="$2"
  if have "$name"; then ok "$name already present"; return 0; fi
  if ! have go; then
    warn "$name skipped — Go not available"
    FIXME[$name]="install Go (apt-get install golang-go), then: go install $mod"
    return 1
  fi
  info "building $name  (go install $mod — first build can take a minute)…"
  local attempt
  for attempt in 1 2 3; do
    local proxy="https://proxy.golang.org,direct"
    [ "$attempt" -eq 3 ] && proxy="direct"     # last try: bypass module proxy
    if GOBIN="$GOBIN" GOPROXY="$proxy" go install "$mod" >/dev/null 2>&1 && [ -x "$GOBIN/$name" ]; then
      publish_bin "$name" >/dev/null 2>&1
      have "$name" && { ok "$name installed -> $(command -v "$name")"; return 0; }
    fi
    [ "$attempt" -lt 3 ] && warn "$name build attempt $attempt failed — retrying…"
  done
  warn "go install failed for $name (network/proxy?)"
  FIXME[$name]="retry: GOPROXY=direct go install $mod   (then it's in ~/go/bin)"
  return 1
}

# pip / pipx (Kali is PEP668 externally-managed) ----------------------------
PIP_FLAG=""
if pip3 install --help 2>/dev/null | grep -q "break-system-packages"; then
  PIP_FLAG="--break-system-packages"
fi
pip_install() {
  # try pipx first for CLI apps (isolated, PEP668-safe), then pip
  local pkg
  for pkg in "$@"; do
    if have pipx; then
      pipx install "$pkg" >/dev/null 2>&1 && { ok "pipx: $pkg"; continue; }
    fi
    if have pip3;  then pip3 install $PIP_FLAG "$pkg" >/dev/null 2>&1 && { ok "pip: $pkg"; continue; }; fi
    if have pip;   then pip  install $PIP_FLAG "$pkg" >/dev/null 2>&1 && { ok "pip: $pkg"; continue; }; fi
    warn "could not pip-install: $pkg"
    FIXME[$pkg]="pip3 install $PIP_FLAG $pkg   (or: pipx install $pkg)"
  done
}
apt_install() {
  # install each package independently so one bad name doesn't sink the rest
  local pkg
  for pkg in "$@"; do
    if $SUDO apt-get install -y "$pkg" >/dev/null 2>&1; then ok "apt: $pkg"; else
      warn "apt could not install: $pkg"
    fi
  done
}

# ---------------------------------------------------------------------------
title "vulnscan setup — groups: ${GROUPS[*]}"

if have apt-get; then
  info "updating apt package index…"
  $SUDO apt-get update -y >/dev/null 2>&1 && ok "apt index updated" || warn "apt update failed (continuing)"
else
  warn "apt-get not found — this script targets Kali/Debian/Ubuntu."
  warn "On other distros install the tools with your package manager; vulnscan still runs and skips missing ones."
fi

# ensure pipx is available (best PEP668-safe way to install python CLIs)
if ! have pipx && have apt-get; then apt_install pipx; have pipx && pipx ensurepath >/dev/null 2>&1 || true; fi

# ---- core python dep ------------------------------------------------------
title "Python dependencies"
if [ -f requirements.txt ]; then
  if have pip3; then pip3 install $PIP_FLAG -r requirements.txt >/dev/null 2>&1 && ok "python deps installed" || warn "python deps may be incomplete"; fi
else
  pip_install requests
fi

# ---- WEB ------------------------------------------------------------------
if want web; then
  title "Web tools (nmap, nikto, sqlmap, whatweb, nuclei, testssl.sh)"
  apt_install nmap nikto sqlmap whatweb testssl.sh
  if ! have nuclei; then
    apt_install nuclei
    if ! have nuclei; then ensure_go; go_install nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"; fi
  fi
  have nuclei && { info "updating nuclei templates…"; nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates updated"; }
fi

# ---- RECON (bug bounty) ---------------------------------------------------
if want recon; then
  title "Recon tools (subfinder, httpx, naabu, dnsx, katana, nuclei, ffuf, gau, gowitness, amass, wafw00f)"
  apt_install amass wafw00f ffuf assetfinder seclists
  ensure_go
  go_install subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  go_install httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  go_install naabu       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  go_install dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  go_install katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
  go_install nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  go_install gau         "github.com/lc/gau/v2/cmd/gau@latest"
  go_install waybackurls "github.com/tomnomnom/waybackurls@latest"
  go_install gowitness   "github.com/sensepost/gowitness@latest"
  have nuclei && { info "updating nuclei templates…"; nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates updated"; }
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
  pip_install semgrep pip-audit
  apt_install gitleaks
  ensure_go
  go_install osv-scanner "github.com/google/osv-scanner/cmd/osv-scanner@latest"
  if ! have grype; then
    info "installing grype…"
    if curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | $SUDO sh -s -- -b /usr/local/bin >/dev/null 2>&1 && have grype; then
      ok "grype installed"
    else
      warn "grype install failed"
      FIXME[grype]="curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    fi
  fi
  if ! have trivy; then
    apt_install trivy
    have trivy || FIXME[trivy]="see https://github.com/aquasecurity/trivy/releases (deb/rpm), or: brew install trivy"
  fi
fi

# ---- CONTAINER ------------------------------------------------------------
if want container; then
  title "Container tools (trivy, grype)"
  if ! have trivy; then apt_install trivy; have trivy || FIXME[trivy]="see https://github.com/aquasecurity/trivy/releases"; fi
  if ! have grype; then
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | $SUDO sh -s -- -b /usr/local/bin >/dev/null 2>&1 && have grype && ok "grype installed" \
      || FIXME[grype]="curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin"
  fi
fi

# ---- MOBILE ---------------------------------------------------------------
if want mobile; then
  title "Mobile tools (apkleaks, apktool, jadx)"
  pip_install apkleaks
  apt_install apktool jadx
  info "Tip: for deep mobile analysis run MobSF via Docker and set MOBSF_URL + MOBSF_APIKEY"
fi

# ---- CLOUD ----------------------------------------------------------------
if want cloud; then
  title "Cloud tools (checkov, prowler, scoutsuite, trivy)"
  pip_install checkov prowler scoutsuite
  if ! have trivy; then apt_install trivy; have trivy || FIXME[trivy]="see https://github.com/aquasecurity/trivy/releases"; fi
fi

# persist ~/go/bin on PATH so tools are found in future shells (idempotent) --
if [ -d "$GOBIN" ]; then
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [ -f "$rc" ] || continue
    grep -q 'go/bin' "$rc" 2>/dev/null || echo 'export PATH="$PATH:$HOME/go/bin"' >> "$rc"
  done
fi

# ---- summary --------------------------------------------------------------
title "Verification"
MISSING=()
check() { if have "$1"; then ok "$1 ✓"; else warn "$1 — not installed"; MISSING+=("$1"); fi; }
want recon     && for t in subfinder httpx naabu dnsx katana nuclei ffuf gau gowitness amass wafw00f; do check "$t"; done
want web       && for t in nmap nikto sqlmap whatweb nuclei testssl.sh; do check "$t"; done
want network   && for t in nmap searchsploit; do check "$t"; done
want mobile    && for t in apkleaks apktool jadx; do check "$t"; done
want cloud     && for t in checkov prowler scout trivy; do check "$t"; done
want container && for t in trivy grype; do check "$t"; done
want code      && for t in semgrep pip-audit gitleaks grype osv-scanner trivy; do check "$t"; done

echo
if [ ${#MISSING[@]} -eq 0 ]; then
  ok "All requested tools are installed and on PATH. 🎉"
else
  warn "Still missing: ${MISSING[*]}"
  echo -e "${C}Finish these manually (copy-paste):${Z}"
  for t in "${MISSING[@]}"; do
    if [ -n "${FIXME[$t]:-}" ]; then
      echo -e "   ${BOLD}$t${Z}: ${FIXME[$t]}"
    else
      echo -e "   ${BOLD}$t${Z}: sudo apt-get install -y $t"
    fi
  done
  echo -e "${C}Then re-run:${Z} ${BOLD}./install.sh ${GROUPS[*]}${Z}   (already-installed tools are skipped)"
fi

echo
ok "Setup complete. vulnscan runs regardless — it uses whatever is installed and clearly reports the rest."
echo -e "   ${BOLD}python3 vulnscan.py --list-tools${Z}                 ${C}# see tool availability${Z}"
echo -e "   ${BOLD}python3 vulnscan.py --type recon example.com${Z}     ${C}# bug-bounty recon${Z}"
echo -e "   ${BOLD}python3 vulnscan.py https://your-site.com${Z}"
warn "Authorized / in-scope targets only. Detection & recon — no auto-exploitation."
