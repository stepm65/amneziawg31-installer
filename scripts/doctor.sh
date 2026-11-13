#!/usr/bin/env bash
set -uo pipefail
printf '%s\n' '== OS / kernel =='
cat /etc/os-release | grep -E '^(NAME|VERSION_ID)=' || true
uname -r
printf '%s\n' '== Secure Boot == '
if command -v mokutil >/dev/null 2>&1; then mokutil --sb-state 2>&1 || :; else echo 'mokutil not installed'; fi
printf '\n%s\n' '== DKMS / module =='
dkms status 2>&1 | grep -i amnezia || true
modinfo -F filename amneziawg 2>&1 || true
modinfo -F version amneziawg 2>&1 || true
lsmod | grep amnezia || true
printf '\n%s\n' '== IPv4 interface =='
ip -4 addr show dev awg0 2>&1 || true
printf '\n%s\n' '== Services =='
systemctl is-active awg-quick@awg0 awg31-panel 2>&1 || true
printf '\n%s\n' '== Full tunnel: IPv4 forwarding / NAT =='
sysctl net.ipv4.ip_forward 2>&1 || true
printf '%s\n' 'Forward rules related to awg0:'
iptables -w -S FORWARD 2>&1 | grep -F awg0 || true
printf '%s\n' 'MASQUERADE rules (inspect subnet/uplink):'
iptables -w -t nat -S POSTROUTING 2>&1 | grep MASQUERADE || true
printf '\n%s\n' '== Firewall =='
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --state || true
    echo 'Rocky/firewalld: check forwarding policy and masquerade for selected AWG interface'
fi
printf '\n%s\n' '== Firewall reminder =='
printf '%s\n' 'Check VPN UDP port in provider firewall and local UFW/nftables manually.'
printf '\n%s\n' '== Logs (no private keys) =='
journalctl -u awg-quick@awg0 -n 12 --no-pager 2>&1 || true
journalctl -u awg31-panel -n 12 --no-pager 2>&1 || true
