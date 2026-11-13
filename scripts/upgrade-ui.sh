#!/usr/bin/env bash
# Update only FastAPI presentation assets on a previously installed AWG31 panel.
# No AWG interface, DKMS, iptables or VPN configuration changes.
set -Eeuo pipefail
umask 077
say(){ printf '[AWG31 UI] %s\n' "$*"; }
die(){ printf '[AWG31 UI ERROR] %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run as root: sudo bash scripts/upgrade-ui.sh'
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
APP=/opt/awg31-panel
[[ -f "$APP/web.py" && -x "$APP/.venv/bin/python3" ]] || die 'AWG31 panel is not installed'
[[ -f /etc/systemd/system/awg31-panel.service ]] || die 'Panel systemd service is missing'
# The UI needs a controller with backup scheduling; otherwise run the full upgrade.
[[ -f /usr/local/sbin/awg31mgr ]] && grep -Fq "backup-policy-set" /usr/local/sbin/awg31mgr && \
[[ -f /etc/systemd/system/awg31-backup.service ]] || die "Run sudo bash scripts/upgrade-core.sh first: the installed controller is older than this UI"
for asset in web.py quicinitial.py md3.css panel.js; do
  [[ -f "$ROOT/src/$asset" ]] || die "Missing required file $asset"
done
"$APP/.venv/bin/python3" -m py_compile "$ROOT/src/web.py" || die 'Python compile check failed'
command -v systemctl >/dev/null || die 'systemctl is missing'
command -v curl >/dev/null || die 'curl is missing'
port="$(systemctl cat awg31-panel.service | sed -nE 's/.*--port ([0-9]+).*/\1/p' | tail -n1)"
[[ "$port" =~ ^[0-9]+$ ]] || die 'Unable to detect localhost panel port'
backup="$(mktemp -d /var/backups/awg31-ui.XXXXXXXX)"
chmod 700 "$backup"
for asset in web.py quicinitial.py md3.css panel.js; do [[ ! -f "$APP/$asset" ]] || cp -p -- "$APP/$asset" "$backup/$asset"; done
finished=0
rollback(){
  if [[ "$finished" -eq 0 ]]; then
    say "Update failed; restoring previous UI from $backup"
    for asset in web.py quicinitial.py md3.css panel.js; do if [[ -f "$backup/$asset" ]]; then cp -p -- "$backup/$asset" "$APP/$asset"; else rm -f -- "$APP/$asset"; fi; done
    systemctl restart awg31-panel.service || true
  fi
}
trap rollback EXIT
for asset in web.py quicinitial.py md3.css panel.js; do
  install -o root -g root -m 644 "$ROOT/src/$asset" "$APP/$asset"
done
if compgen -G "$ROOT/src/fonts/*" >/dev/null; then
  install -d -o root -g root -m 755 "$APP/fonts"
  install -o root -g root -m 644 "$ROOT"/src/fonts/* "$APP/fonts/"
fi
say 'Restarting web panel (VPN interfaces remain untouched)'
systemctl restart awg31-panel.service
source "$ROOT/scripts/os-support.sh"
awg31_wait_panel "$port" || die 'Panel failed to start after the update'
finished=1
trap - EXIT
say "Success. UI backup: $backup"
say "Web panel only updated; VPN tunnel and keys unchanged"
