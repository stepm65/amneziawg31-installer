#!/usr/bin/env bash
# Read-only boot/periodic verification after kernel upgrades.
set -euo pipefail
kernel="$(uname -r)"
echo "[AWG31] Checking kernel $kernel"
if ! modinfo -k "$kernel" -F version amneziawg >/dev/null 2>&1; then
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
