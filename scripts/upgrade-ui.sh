#!/usr/bin/env bash
# Upgrade only the local web UI; preserve /etc/amnezia, /var/lib/awg31-panel, keys and peers.
set -Eeuo pipefail
umask 077
say() { printf '[AWG31 UI] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run as root: sudo bash scripts/upgrade-ui.sh'
# Since v0.2 web UI depends on the multi-instance root controller, update together.
if [[ -f "$(dirname -- "${BASH_SOURCE[0]}")/upgrade-core.sh" ]]; then
  exec bash "$(dirname -- "${BASH_SOURCE[0]}")/upgrade-core.sh"
fi
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_WEB="$DIR/src/web.py"
SOURCE_LINK="$DIR/src/amnezialink.py"
SOURCE_CSS="$DIR/src/panel.css"
SOURCE_JS="$DIR/src/panel.js"
DEST=/opt/awg31-panel
SERVICE=awg31-panel.service
[[ -f "$SOURCE_WEB" && -f "$SOURCE_LINK" && -f "$SOURCE_CSS" && -f "$SOURCE_JS" ]] || die 'Project files src/web.py, src/panel.css, src/panel.js not found'
[[ -f "$DEST/web.py" && -d "$DEST/.venv" ]] || die 'Existing AWG31 panel not found'
[[ -f /etc/awg31-panel/auth.json ]] || die 'Missing auth.json; do not continue'
id awgpanel >/dev/null 2>&1 || die 'System user awgpanel not found'
systemctl cat "$SERVICE" >/dev/null || die 'systemd service awg31-panel.service not found'
"$DEST/.venv/bin/python3" -m py_compile "$SOURCE_WEB" "$SOURCE_LINK"

BACKUP_DIR="$(mktemp -d /var/backups/awg31-panel-ui.XXXXXXXX)"
chmod 700 "$BACKUP_DIR"
cp -p -- "$DEST/web.py" "$BACKUP_DIR/web.py"
if [[ -e "$DEST/amnezialink.py" ]]; then cp -p -- "$DEST/amnezialink.py" "$BACKUP_DIR/amnezialink.py"; fi
HAD_CSS=0
HAD_JS=0
if [[ -e "$DEST/panel.css" ]]; then
  cp -p -- "$DEST/panel.css" "$BACKUP_DIR/panel.css"
  HAD_CSS=1
fi
if [[ -e "$DEST/panel.js" ]]; then
  cp -p -- "$DEST/panel.js" "$BACKUP_DIR/panel.js"
  HAD_JS=1
fi
restore() {
  say "Restoring old files from $BACKUP_DIR"
  cp -p -- "$BACKUP_DIR/web.py" "$DEST/web.py"
  if [[ -f "$BACKUP_DIR/amnezialink.py" ]]; then cp -p -- "$BACKUP_DIR/amnezialink.py" "$DEST/amnezialink.py"; else rm -f -- "$DEST/amnezialink.py"; fi
  if [[ $HAD_CSS == 1 ]]; then
    cp -p -- "$BACKUP_DIR/panel.css" "$DEST/panel.css"
  else
    rm -f -- "$DEST/panel.css"
  fi
  if [[ $HAD_JS == 1 ]]; then
    cp -p -- "$BACKUP_DIR/panel.js" "$DEST/panel.js"
  else
    rm -f -- "$DEST/panel.js"
  fi
  systemctl restart "$SERVICE" || true
}
COMPLETED=0
trap 'if [[ $COMPLETED -eq 0 ]]; then say "Upgrade failed; rolling back"; restore; fi' EXIT

say 'Installing bilingual RU/EN graphite interface files'
install -o root -g root -m 644 "$SOURCE_LINK" "$DEST/amnezialink.py"
install -o root -g root -m 644 "$SOURCE_WEB" "$DEST/web.py"
install -o root -g root -m 644 "$SOURCE_CSS" "$DEST/panel.css"
install -o root -g root -m 644 "$SOURCE_JS" "$DEST/panel.js"
# Retain previously working venv permissions: do not change executables or sudoers.
PORT="${PANEL_PORT:-}"
if [[ -z "$PORT" ]]; then
  PORT="$(systemctl cat "$SERVICE" | sed -nE 's/.*--port ([0-9]+).*/\1/p' | tail -n1)"
fi
[[ "$PORT" =~ ^[0-9]+$ ]] || die 'Could not detect panel port, set PANEL_PORT=8080'
systemctl restart "$SERVICE"
sleep 2
systemctl is-active --quiet "$SERVICE" || die 'Panel service is not active'
curl --noproxy '*' -4 -fsS --max-time 7 "http://127.0.0.1:$PORT/health" >/dev/null || die 'Panel health check failed'
curl --noproxy '*' -4 -fsS --max-time 7 "http://127.0.0.1:$PORT/assets/panel.css" | grep 'stats-grid' >/dev/null || die 'Panel CSS failed to load'
curl --noproxy '*' -4 -fsS --max-time 7 "http://127.0.0.1:$PORT/assets/panel.js" | grep 'traffic-chart' >/dev/null || die 'Panel JS failed to load' 
COMPLETED=1
trap - EXIT
say "Updated successfully on 127.0.0.1:$PORT. Backup: $BACKUP_DIR"
say 'VPN awg0, keys, peers, database and systemd configuration were not modified'
