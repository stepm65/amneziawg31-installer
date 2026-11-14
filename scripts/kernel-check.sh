#!/usr/bin/env bash
# Verification after boot and several times a day:
#   1. the module exists for the running kernel;
#   2. the module exists for a newer installed kernel that is not running yet.
#      A kernel update normally rebuilds it through DKMS. If that did not
#      happen, one rebuild is attempted here, and the outcome is written to
#      /var/lib/awg31-panel/next-kernel so the panel and the Telegram bot can
#      warn BEFORE the reboot that would leave the VPN down.
set -uo pipefail
STATE="${AWG31_NEXT_KERNEL:-/var/lib/awg31-panel/next-kernel}"
MODULES="${AWG31_MODULES_DIR:-/lib/modules}"
kernel="$(uname -r)"
has_module(){ modinfo -k "$1" -F version amneziawg >/dev/null 2>&1; }

newest=''
for dir in "$MODULES"/*/; do
    [[ -f "$dir/modules.dep" || -d "$dir/kernel" ]] || continue
    version="$(basename "$dir")"
    newest="$(printf '%s\n%s\n' "$newest" "$version" | sort -V | tail -n1)"
done
state=''
if [[ -n "$newest" && "$newest" != "$kernel" && "$(printf '%s\n%s\n' "$kernel" "$newest" | sort -V | tail -n1)" == "$newest" ]]; then
    echo "[AWG31] A newer kernel is installed and will run after the next reboot: $newest"
    if ! has_module "$newest" && command -v dkms >/dev/null; then
        echo "[AWG31] No amneziawg module for $newest yet; asking DKMS to build it"
        dkms install -m amneziawg -v 1.0.0 -k "$newest" >/dev/null 2>&1 || :
    fi
    if has_module "$newest"; then
        state="ok $newest"
    else
        state="missing $newest"
        echo "[AWG31 ERROR] amneziawg module is NOT built for kernel $newest: after a reboot the VPN will not start." >&2
        echo '[AWG31] Before rebooting run the installer again (sudo awg31 update): it rebuilds the module.' >&2
    fi
fi
if [[ -d "$(dirname "$STATE")" ]]; then
    printf '%s\n' "$state" >"$STATE.tmp" && chmod 644 "$STATE.tmp" && mv -f "$STATE.tmp" "$STATE"
fi

echo "[AWG31] Checking kernel $kernel"
if ! has_module "$kernel"; then
    echo "[AWG31 ERROR] amneziawg module missing for current kernel: $kernel" >&2
    echo '[AWG31] Check dkms status, headers, Secure Boot signing, then reboot if required.' >&2
    exit 1
fi
if ! lsmod | grep -q '^amneziawg '; then
    echo '[AWG31 WARNING] module is available but not currently loaded.' >&2
fi
if command -v dkms >/dev/null; then
    dkms status -m amneziawg
fi
if command -v mokutil >/dev/null && mokutil --sb-state 2>/dev/null | grep -qi 'enabled'; then
    echo '[AWG31] Secure Boot enabled; module must be signed by an enrolled key.'
fi
[[ "$state" != missing* ]]
