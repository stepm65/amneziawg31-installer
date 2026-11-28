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
for f in web.py amnezialink.py quicinitial.py awg31import.py awg31client.py awg31helper panel.css md3.css panel.js awg31ctl awg31mgr awg31admin.py awg31bot.py; do
    [[ -f "$DIR/src/$f" ]] || die "Missing src/$f"
done
[[ -f "$DIR/scripts/sudoers.sh" ]] || die 'Missing scripts/sudoers.sh'
compgen -G "$DIR/src/fonts/*.woff2" >/dev/null || die 'Missing src/fonts/*.woff2'
"$APP/.venv/bin/python3" -m py_compile "$DIR/src/web.py" "$DIR/src/amnezialink.py" "$DIR/src/quicinitial.py" "$DIR/src/awg31import.py"
python3 -m py_compile "$DIR/src/awg31ctl" "$DIR/src/awg31mgr" "$DIR/src/awg31admin.py" "$DIR/src/awg31helper" "$DIR/src/awg31client.py"
# A snapshot of the whole installed program (and, as recovery material, the
# databases and server configurations): a failed update returns to it at once,
# and `sudo awg31 rollback` returns to it later. The newest five are kept.
[[ -f "$DIR/scripts/awg31-snapshot.py" ]] || die 'Missing scripts/awg31-snapshot.py'
backup="$(python3 "$DIR/scripts/awg31-snapshot.py" create --reason upgrade --to "$(tr -d '[:space:]' < "$DIR/VERSION" 2>/dev/null || :)")" ||
    die 'Cannot take a snapshot of the installed version; nothing was changed'
say "Snapshot of the installed version: $backup"
restore(){
    say "Update failed: restoring the previous version from $backup"
    python3 "$DIR/scripts/awg31-snapshot.py" restore "$(basename -- "$backup")" --no-snapshot || say 'WARNING: automatic restore failed; see sudo awg31 rollback'
}
completed=0
trap 'if [[ $completed -eq 0 ]]; then restore; fi' EXIT
say 'Updating root-only controller and multi-server manager'
install -o root -g root -m 755 "$DIR/src/awg31ctl" "$CTR"
install -o root -g root -m 755 "$DIR/src/awg31mgr" "$MGR"
install -o root -g root -m 644 "$DIR/src/awg31admin.py" /usr/local/sbin/awg31admin.py
install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
install -o root -g root -m 755 "$DIR/src/awg31bot.py" /usr/local/libexec/awg31/telegram-probe.py
install -o root -g root -m 755 "$DIR/scripts/restore-backup.py" /usr/local/libexec/awg31/scripts/restore-backup.py
install -o root -g root -m 755 "$DIR/scripts/awg31-snapshot.py" /usr/local/libexec/awg31/scripts/awg31-snapshot.py
install -o root -g root -m 755 "$DIR/scripts/update-run.sh" /usr/local/libexec/awg31/scripts/update-run.sh
say 'Checking existing server inventory'
"$MGR" servers </dev/null
say 'Installing narrowly scoped sudo permission'
source "$DIR/scripts/sudoers.sh"
# Only our own file is validated: an unrelated broken file in sudoers.d must not block updates.
awg31_install_sudoers "$SUD" || die 'Cannot install sudoers allowlist'
say 'Updating web UI files'
install -o root -g root -m 644 "$DIR/src/amnezialink.py" "$APP/amnezialink.py"
install -o root -g root -m 644 "$DIR/src/quicinitial.py" "$APP/quicinitial.py"
install -o root -g root -m 644 "$DIR/src/awg31import.py" "$APP/awg31import.py"
install -o root -g root -m 644 "$DIR/src/awg31bot.py" "$APP"/awg31bot.py
install -o root -g root -m 644 "$DIR/src/awg31client.py" "$APP/awg31client.py"
install -o root -g root -m 644 "$DIR/src/web.py" "$APP/web.py"
install -o root -g root -m 644 "$DIR/src/panel.css" "$APP/panel.css"
install -o root -g root -m 644 "$DIR/src/md3.css" "$APP/md3.css"
install -o root -g root -m 644 "$DIR/src/panel.js" "$APP/panel.js"
if [[ -f "$DIR/VERSION" ]]; then install -o root -g root -m 644 "$DIR/VERSION" "$APP/VERSION"; fi
# Self-hosted UI fonts (no CDN); older installations do not have them yet.
install -d -o root -g root -m 755 "$APP/fonts"
install -o root -g root -m 644 "$DIR"/src/fonts/* "$APP/fonts/"
# Security fixes of FastAPI/Starlette and friends arrive only this way. A failure
# (for example PyPI unreachable) keeps the packages that already work.
install -o root -g root -m 644 "$DIR/src/requirements.txt" "$APP/requirements.txt"
say 'Refreshing Python packages within the supported version ranges'
if "$APP/.venv/bin/pip" install --disable-pip-version-check --quiet --upgrade -r "$APP/requirements.txt"; then
    "$APP/.venv/bin/pip" freeze --disable-pip-version-check > "$APP/installed-packages.txt" 2>/dev/null || :
    chgrp -R awgpanel "$APP/.venv" && chmod -R g+rX "$APP/.venv"
else
    say 'WARNING: Python packages were not refreshed; continuing with the installed ones'
fi
port="$(systemctl cat awg31-panel.service | sed -nE 's/.*--port ([0-9]+).*/\1/p' | tail -n1)"
[[ "$port" =~ ^[0-9]+$ ]] || die 'Cannot detect localhost panel port'
source "$DIR/scripts/os-support.sh"
say 'Kernel network settings for VPN routing (/etc/sysctl.d/96-awg31-network.conf)'
awg31_network_sysctl
say 'Updating the control helper'
awg31_install_helper "$DIR" || say 'WARNING: the control helper did not start; the panel keeps working through sudo'
systemctl restart awg31-panel.service
awg31_wait_panel "$port" || die 'Panel failed to start after the update'
runuser -u awgpanel -- sudo -n "$MGR" servers </dev/null >/dev/null || die 'Panel sudo permission failed'
completed=1
trap - EXIT
install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
install -o root -g root -m 755 "$DIR/scripts/setup-nginx.sh" /usr/local/libexec/awg31/scripts/setup-nginx.sh
if [[ -f /etc/nginx/conf.d/awg31-panel.conf ]] && command -v nginx >/dev/null 2>&1; then
    bash "$DIR/scripts/setup-nginx.sh" --add-subscription || say 'WARNING: the Nginx site was not extended for subscriptions'
fi
install -o root -g root -m 644 "$DIR/scripts/os-support.sh" /usr/local/libexec/awg31/scripts/os-support.sh
install -o root -g root -m 755 "$DIR/scripts/awg31-menu" /usr/local/bin/awg31
install -o root -g root -m 755 "$DIR/scripts/uninstall.sh" /usr/local/libexec/awg31/scripts/uninstall.sh
install -o root -g root -m 755 "$DIR/install.sh" /usr/local/libexec/awg31/install.sh
install -o root -g root -m 755 "$DIR/scripts/setup-telegram.sh" /usr/local/libexec/awg31/scripts/setup-telegram.sh
install -o root -g root -m 755 "$DIR/src/awg31bot.py" /usr/local/libexec/awg31/telegram-probe.py
install -o root -g root -m 644 "$DIR/scripts/sudoers.sh" /usr/local/libexec/awg31/scripts/sudoers.sh
install -o root -g root -m 644 "$DIR/scripts/awg31-bot.service" /usr/local/libexec/awg31/scripts/awg31-bot.service
# A configured Telegram bot follows the update: new code, unit and sudo rule.
if [[ -f /etc/awg31-bot/telegram.json ]] && id awgbot >/dev/null 2>&1; then
    chmod -R o+rX "$APP/.venv"
    install -o root -g root -m 644 "$DIR/scripts/awg31-bot.service" /etc/systemd/system/awg31-bot.service
    awg31_unit_compat /etc/systemd/system/awg31-bot.service
    if awg31_install_bot_sudoers; then
        systemctl daemon-reload
        systemctl enable awg31-bot.service >/dev/null 2>&1 || :
        systemctl restart awg31-bot.service || say 'WARNING: the Telegram bot did not restart (sudo awg31 telegram status)'
    else
        say 'WARNING: could not update the sudo rule of the Telegram bot'
    fi
fi
# Limit growth of root-owned audit log without exposing credentials.
if command -v logrotate >/dev/null 2>&1; then
    install -o root -g root -m 644 "$DIR/scripts/awg31-audit.logrotate" /etc/logrotate.d/awg31-panel
fi
install -o root -g root -m 755 "$DIR/scripts/kernel-check.sh" /usr/local/libexec/awg31/scripts/kernel-check.sh
for unit in awg31-sampler.service awg31-sampler.timer awg31-kernel-check.service awg31-kernel-check.timer awg31-backup.service; do
    install -o root -g root -m 644 "$DIR/scripts/$unit" "/etc/systemd/system/$unit"
done
awg31_unit_compat /etc/systemd/system/awg31-panel.service
systemctl daemon-reload
systemctl enable --now awg31-sampler.timer awg31-kernel-check.timer
say "Upgrade completed. Backup: $backup"
say 'VPN interface, private keys, client databases and routing rules were not changed'
