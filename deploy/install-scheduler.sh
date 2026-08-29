#!/usr/bin/env bash
#
# install-scheduler.sh — set up automatic local feed refresh for vulnscan.
#
# Chooses systemd timers if available (preferred), else falls back to cron.
# This keeps CVE feeds fresh whenever THIS machine is on. (For refresh even when
# the machine is off, use the GitHub Actions workflow instead — it runs in the
# cloud on a schedule.)
#
# Usage:
#   ./deploy/install-scheduler.sh            # daily refresh
#   ./deploy/install-scheduler.sh --cron     # force cron instead of systemd
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$(command -v python3 || true)"
[ -z "$PY" ] && { echo "python3 not found"; exit 1; }

USE_CRON=0
[ "${1:-}" = "--cron" ] && USE_CRON=1

echo "[*] repo: $REPO_DIR"

install_systemd_user() {
  local unit_dir="$HOME/.config/systemd/user"
  mkdir -p "$unit_dir"
  cat > "$unit_dir/vulnscan-feeds.service" <<EOF
[Unit]
Description=Refresh vulnscan CVE feeds
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$REPO_DIR
ExecStart=$PY $REPO_DIR/feeds/update_feeds.py --nvd-days 7
Nice=10
EOF
  cat > "$unit_dir/vulnscan-feeds.timer" <<EOF
[Unit]
Description=Run vulnscan feed refresh daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now vulnscan-feeds.timer
  echo "[+] systemd user timer installed. Check: systemctl --user list-timers | grep vulnscan"
  echo "    (run 'loginctl enable-linger $USER' so it runs while you're logged out)"
}

install_cron() {
  local line="17 5 * * * cd $REPO_DIR && $PY feeds/update_feeds.py --nvd-days 7 >> $REPO_DIR/feeds.log 2>&1"
  # Idempotent: remove any old vulnscan cron line, then add.
  ( crontab -l 2>/dev/null | grep -v 'feeds/update_feeds.py' ; echo "$line" ) | crontab -
  echo "[+] cron installed (daily 05:17). Check: crontab -l | grep update_feeds"
}

if [ "$USE_CRON" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  install_systemd_user
else
  install_cron
fi

echo "[*] Running one refresh now…"
cd "$REPO_DIR" && "$PY" feeds/update_feeds.py --nvd-days 7 || echo "[!] initial refresh had errors (will retry on schedule)"
echo "[+] Done."
