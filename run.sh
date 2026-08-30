#!/usr/bin/env bash
#
# run.sh — THE single command. Same on every device (Kali/Ubuntu/Debian/macOS/WSL).
#
#   ./run.sh                      # first run sets up, then asks what to scan
#   ./run.sh https://example.com  # scan directly (still auto-sets-up once)
#   ./run.sh 192.168.1.0/24
#   ./run.sh ./app.apk
#
# Options:
#   ./run.sh --setup     force re-run tool setup
#   ./run.sh --update    refresh CVE feeds now
#   ./run.sh --no-setup  skip setup/feeds entirely (just scan)
#   ...any vulnscan.py flags are passed through (e.g. --yes --type web)
#
# What it does on FIRST run (once, tracked by a .setup-done marker):
#   1) installs tools via install.sh (best-effort; missing tools are skipped)
#   2) pulls fresh CVE feeds (CISA KEV + NVD)
# After that it just runs the scanner (fast).
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
MARK="$DIR/.setup-done"

# ---- colors ----
if [ -t 1 ]; then G="\033[32m"; Y="\033[33m"; C="\033[36m"; Z="\033[0m"; B="\033[1m"; else G=""; Y=""; C=""; Z=""; B=""; fi
say()  { echo -e "${C}[run]${Z} $*"; }
ok()   { echo -e "${G}[ok]${Z} $*"; }
warn() { echo -e "${Y}[!]${Z} $*"; }

# ---- pick a python ----
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  warn "Python 3 not found. Install it first (e.g. 'sudo apt install python3')."
  exit 1
fi

# ---- parse our own control flags; pass the rest to vulnscan.py ----
DO_SETUP="auto"; DO_UPDATE="auto"; ARGS=()
for a in "$@"; do
  case "$a" in
    --setup)    DO_SETUP="force" ;;
    --no-setup) DO_SETUP="skip"; DO_UPDATE="skip" ;;
    --update)   DO_UPDATE="force" ;;
    *)          ARGS+=("$a") ;;
  esac
done

# ---- first-run setup (once) ----
if [ "$DO_SETUP" = "force" ] || { [ "$DO_SETUP" = "auto" ] && [ ! -f "$MARK" ]; }; then
  say "First-time setup — installing tools (missing ones are skipped)…"
  if [ -f "$DIR/install.sh" ]; then
    chmod +x "$DIR/install.sh" 2>/dev/null || true
    bash "$DIR/install.sh" || warn "some tools didn't install — scanner will skip them"
  fi
  # make sure the optional python dep is present
  "$PY" -c "import requests" 2>/dev/null || "$PY" -m pip install requests --break-system-packages >/dev/null 2>&1 || true
  date > "$MARK"
  ok "setup complete (won't run again; use --setup to redo)"
fi

# ---- refresh CVE feeds ----
if [ "$DO_UPDATE" = "force" ] || { [ "$DO_UPDATE" = "auto" ] && [ -f "$DIR/feeds/update_feeds.py" ]; }; then
  say "Refreshing CVE feeds (CISA KEV + NVD)…"
  "$PY" "$DIR/feeds/update_feeds.py" --nvd-days 7 --no-tools >/dev/null 2>&1 \
    && ok "feeds updated" || warn "feed refresh skipped (offline?) — scan continues"
fi

# ---- run the scanner (interactive if no target) ----
say "Launching scanner…"
exec "$PY" "$DIR/vulnscan.py" "${ARGS[@]}"
