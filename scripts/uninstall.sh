#!/usr/bin/env bash
# Remove AmneziaWG 3.1 Console from this server.
#
#   sudo awg31 uninstall            remove the software, keep VPN data and backups
#   sudo awg31 uninstall --purge    also delete configurations, keys, databases, backups and logs
#
# The DKMS kernel module and the awg tools are left in place: other AmneziaWG
# setups may use them. The commands to remove them are printed at the end.
set -Euo pipefail
PURGE=0
ASSUME_YES="${AWG31_UNATTENDED:-0}"
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        --yes) ASSUME_YES=1 ;;
        *) echo "Usage: uninstall.sh [--purge] [--yes]" >&2; exit 2 ;;
    esac
done
[[ ${EUID} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
say(){ printf '[AWG31 uninstall] %s\n' "$*"; }

CONFIG_DIR=/etc/amnezia/amneziawg
interfaces=()
if [[ -d "$CONFIG_DIR" ]]; then
    for conf in "$CONFIG_DIR"/awg*.conf; do
        [[ -f "$conf" ]] || continue
        name="$(basename "$conf" .conf)"
        [[ "$name" =~ ^awg(0|[1-9][0-9]?)$ ]] && interfaces+=("$name")
    done
fi

echo 'This removes the web panel, the controller, services, timers and the sudo rule.'
echo "VPN servers found: ${interfaces[*]:-none}. They will be STOPPED; clients lose the connection."
if ((PURGE)); then
    echo 'PURGE: server and client keys, client databases, backups, logs and the panel password are DELETED.'
    word=PURGE
else
    echo 'Configurations, keys, databases and backups are KEPT (use --purge to delete them).'
    word=UNINSTALL
fi
if [[ "$ASSUME_YES" != 1 ]]; then
    read -r -p "Type $word to continue: " answer
    [[ "$answer" == "$word" ]] || { echo 'Cancelled; nothing was changed.'; exit 1; }
fi

if ((!PURGE)) && [[ -x /usr/local/sbin/awg31mgr ]]; then
    # Best effort: a last full archive next to the data that stays.
    if /usr/local/sbin/awg31mgr backup-create >/dev/null 2>&1; then
        say 'A final backup was created in /var/backups/awg31-panel/full'
    fi
fi

say 'Stopping services'
# One unit per call: with several names systemctl gives up on the first unit
# that does not exist (the backup timer is optional) and leaves the rest running.
for unit in awg31-panel.service awg31-sampler.timer awg31-kernel-check.timer awg31-backup.timer; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || :
done
for unit in awg31-panel.service awg31-sampler.service awg31-kernel-check.service awg31-backup.service; do
    systemctl stop "$unit" >/dev/null 2>&1 || :
done
for name in "${interfaces[@]}"; do
    # PostDown in the configuration removes this server's firewall rules and NAT.
    systemctl disable --now "awg-quick@$name.service" >/dev/null 2>&1 || :
done

say 'Removing program files'
rm -f /etc/systemd/system/awg31-panel.service /etc/systemd/system/awg31-sampler.service \
      /etc/systemd/system/awg31-sampler.timer /etc/systemd/system/awg31-kernel-check.service \
      /etc/systemd/system/awg31-kernel-check.timer /etc/systemd/system/awg31-backup.service \
      /etc/systemd/system/awg31-backup.timer
systemctl daemon-reload >/dev/null 2>&1 || :
systemctl reset-failed 'awg31-*' >/dev/null 2>&1 || :
rm -f /etc/sudoers.d/awg31-panel /etc/logrotate.d/awg31-panel /etc/sysctl.d/96-awg31-ipv4.conf
rm -f /usr/local/sbin/awg31ctl /usr/local/sbin/awg31mgr /usr/local/sbin/awg31admin.py /usr/local/bin/awg31
rm -rf /opt/awg31-panel /usr/local/libexec/awg31
if [[ -f /etc/nginx/conf.d/awg31-panel.conf ]]; then
    rm -f /etc/nginx/conf.d/awg31-panel.conf
    if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
        systemctl reload nginx >/dev/null 2>&1 || :
    fi
    say 'Removed the Nginx site of the panel (Nginx itself and certificates are untouched)'
fi
if id awgpanel >/dev/null 2>&1; then userdel awgpanel >/dev/null 2>&1 || :; fi

if ((PURGE)); then
    say 'Deleting VPN data'
    for name in "${interfaces[@]}"; do rm -f "$CONFIG_DIR/$name.conf"; done
    rmdir "$CONFIG_DIR" 2>/dev/null || :
    rm -rf /var/lib/awg31-panel /etc/awg31-panel /var/backups/awg31-panel /var/log/awg31-panel
    rm -rf /var/backups/awg31-upgrade.* /var/backups/awg31-ui.* 2>/dev/null || :
    rm -f /root/awg31-initial-password.txt
else
    say "Kept: $CONFIG_DIR, /var/lib/awg31-panel, /etc/awg31-panel, /var/backups/awg31-panel"
    say 'To install again on top of this data, remove it first with: uninstall --purge'
fi

cat <<'EOF'
[AWG31 uninstall] Done. Still installed, because other setups may need them:
  kernel module:  dkms remove amneziawg/1.0.0 --all && rm -rf /usr/src/amneziawg-1.0.0
  tools:          rm -f /usr/bin/awg /usr/bin/awg-quick /usr/lib/systemd/system/awg-quick@.service
IPv4 forwarding stays as it is now until reboot (sysctl net.ipv4.ip_forward).
EOF
