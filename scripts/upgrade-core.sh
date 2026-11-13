#!/usr/bin/env bash
# Upgrade controller and web together, preserving every running AWG interface.
set -Eeuo pipefail
umask 077
say() { printf '[AWG31 upgrade] %s\n' "$*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || die 'Run as root'
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
APP=/opt/awg31-panel
CTR=/usr/local/sbin/awg31ctl
MGR=/usr/local/sbin/awg31mgr
SUD=/etc/sudoers.d/awg31-panel
# Do not require awg0: it may have been deleted while other servers remain.
# The installed application and controller are checked below.
[[ -f "$APP/web.py" && -x "$APP/.venv/bin/python3" && -f "$CTR" ]] || die 'Existing panel/controller missing'
id awgpanel >/dev/null 2>&1 || die 'awgpanel user not found'
for f in web.py amnezialink.py quicinitial.py panel.css md3.css panel.js awg31ctl awg31mgr awg31admin.py; do
    [[ -f "$DIR/src/$f" ]] || die "Missing src/$f"
done
[[ -f "$DIR/scripts/sudoers.sh" ]] || die 'Missing scripts/sudoers.sh'
compgen -G "$DIR/src/fonts/*.woff2" >/dev/null || die 'Missing src/fonts/*.woff2'
"$APP/.venv/bin/python3" -m py_compile "$DIR/src/web.py" "$DIR/src/amnezialink.py" "$DIR/src/quicinitial.py"
python3 -m py_compile "$DIR/src/awg31ctl" "$DIR/src/awg31mgr" "$DIR/src/awg31admin.py"
backup="$(mktemp -d /var/backups/awg31-upgrade.XXXXXXXX)"
chmod 700 "$backup"
for spec in "$APP/web.py:web.py" "$APP/amnezialink.py:amnezialink.py" "$APP/quicinitial.py:quicinitial.py" "$APP/panel.css:panel.css" "$APP/md3.css:md3.css" "$APP/panel.js:panel.js" \
            "$CTR:awg31ctl" "$MGR:awg31mgr" "/usr/local/sbin/awg31admin.py:awg31admin.py" "$SUD:sudoers"; do
    src="${spec%%:*}"; dst="${spec#*:}"
    if [[ -f "$src" ]]; then cp -p -- "$src" "$backup/$dst"; fi
done
# Snapshot all existing SQLite databases and configs before code or schema migration.
# This is recovery material, not an automatic restore: the running VPS must not
# have its VPN DB overwritten during a failed web-only upgrade.
AWG31_PRE_UPGRADE_BACKUP="$backup" python3 - <<'PY_BACKUP'
import os, sqlite3, shutil
from pathlib import Path
root=Path(os.environ['AWG31_PRE_UPGRADE_BACKUP'])
base=Path('/var/lib/awg31-panel')
for source in [base/'state.sqlite3', *(base/'servers').glob('awg*.sqlite3')]:
    if not source.is_file(): continue
    dest=root/'databases'/source.name
    dest.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(source) as s,sqlite3.connect(dest) as d: s.backup(d)
    dest.chmod(0o600)
for source in Path('/etc/amnezia/amneziawg').glob('awg*.conf'):
    dest=root/'configs'/source.name
    dest.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(source,dest)
    dest.chmod(0o600)
PY_BACKUP
restore(){
    say "Rolling back application files from $backup"
    for spec in "$APP/web.py:web.py" "$APP/amnezialink.py:amnezialink.py" "$APP/quicinitial.py:quicinitial.py" "$APP/panel.css:panel.css" "$APP/md3.css:md3.css" "$APP/panel.js:panel.js" \
                "$CTR:awg31ctl" "$MGR:awg31mgr" "/usr/local/sbin/awg31admin.py:awg31admin.py" "$SUD:sudoers"; do
        dst="${spec%%:*}"; name="${spec#*:}"
        if [[ -e "$backup/$name" ]]; then cp -p -- "$backup/$name" "$dst";
        else rm -f -- "$dst"; fi
    done
    systemctl restart awg31-panel.service || true
}
completed=0
trap 'if [[ $completed -eq 0 ]]; then restore; fi' EXIT
say 'Updating root-only controller and multi-server manager'
install -o root -g root -m 755 "$DIR/src/awg31ctl" "$CTR"
install -o root -g root -m 755 "$DIR/src/awg31mgr" "$MGR"
install -o root -g root -m 644 "$DIR/src/awg31admin.py" /usr/local/sbin/awg31admin.py
install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
install -o root -g root -m 755 "$DIR/scripts/restore-backup.py" /usr/local/libexec/awg31/scripts/restore-backup.py
say 'Checking existing server inventory'
"$MGR" servers </dev/null
say 'Installing narrowly scoped sudo permission'
source "$DIR/scripts/sudoers.sh"
awg31_install_sudoers "$SUD" || die 'Cannot install sudoers allowlist'
visudo -c >/dev/null
say 'Updating web UI files'
install -o root -g root -m 644 "$DIR/src/amnezialink.py" "$APP/amnezialink.py"
install -o root -g root -m 644 "$DIR/src/quicinitial.py" "$APP/quicinitial.py"
install -o root -g root -m 644 "$DIR/src/web.py" "$APP/web.py"
install -o root -g root -m 644 "$DIR/src/panel.css" "$APP/panel.css"
install -o root -g root -m 644 "$DIR/src/md3.css" "$APP/md3.css"
install -o root -g root -m 644 "$DIR/src/panel.js" "$APP/panel.js"
if [[ -f "$DIR/VERSION" ]]; then install -o root -g root -m 644 "$DIR/VERSION" "$APP/VERSION"; fi
# Self-hosted UI fonts (no CDN); older installations do not have them yet.
install -d -o root -g root -m 755 "$APP/fonts"
install -o root -g root -m 644 "$DIR"/src/fonts/* "$APP/fonts/"
port="$(systemctl cat awg31-panel.service | sed -nE 's/.*--port ([0-9]+).*/\1/p' | tail -n1)"
[[ "$port" =~ ^[0-9]+$ ]] || die 'Cannot detect localhost panel port'
systemctl restart awg31-panel.service
source "$DIR/scripts/os-support.sh"
awg31_wait_panel "$port" || die 'Panel failed to start after the update'
runuser -u awgpanel -- sudo -n "$MGR" servers </dev/null >/dev/null || die 'Panel sudo permission failed'
completed=1
trap - EXIT
install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
install -o root -g root -m 755 "$DIR/scripts/setup-nginx.sh" /usr/local/libexec/awg31/scripts/setup-nginx.sh
install -o root -g root -m 644 "$DIR/scripts/os-support.sh" /usr/local/libexec/awg31/scripts/os-support.sh
install -o root -g root -m 755 "$DIR/scripts/awg31-menu" /usr/local/bin/awg31
# Limit growth of root-owned audit log without exposing credentials.
if command -v logrotate >/dev/null 2>&1; then
    install -o root -g root -m 644 "$DIR/scripts/awg31-audit.logrotate" /etc/logrotate.d/awg31-panel
fi
install -o root -g root -m 755 "$DIR/scripts/kernel-check.sh" /usr/local/libexec/awg31/scripts/kernel-check.sh
for unit in awg31-sampler.service awg31-sampler.timer awg31-kernel-check.service awg31-kernel-check.timer awg31-backup.service; do
    install -o root -g root -m 644 "$DIR/scripts/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now awg31-sampler.timer awg31-kernel-check.timer
say "Upgrade completed. Backup: $backup"
say 'VPN interface, private keys, client databases and routing rules were not changed'
