#!/usr/bin/env bash
# Installs pinned upstream AWG 3.1 kernel module/tools; does NOT configure a VPN.
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_COMMIT=4569c4c67f3a57414969260cafbbd04694fbaae0
TOOLS_TAG=v3.1.20260812
EXPECTED_VERSION=3.1.20260812
PATCH_FILE="$ROOT/patches/ubuntu-26.04-udp-tunnel-pr265.patch"
say(){ printf '[AWG31/prepare] %s\n' "$*"; }
die(){ printf '[AWG31/prepare ERROR] %s\n' "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || die 'Run as root'
. /etc/os-release
source "$ROOT/scripts/os-support.sh"
awg31_detect_os
[[ -f "$PATCH_FILE" ]] || die 'Kernel compatibility patch is missing'

say "Installing build tools and dependencies on $AWG31_DISTRO $AWG31_OS_VERSION (IPv4 only)"
awg31_install_packages
secure_boot="$(awg31_secure_boot)"
say "Secure Boot: $secure_boot (not changed by installer)"

current_module="$(cat /sys/module/amneziawg/version 2>/dev/null || true)"
if [[ -n "$current_module" && "$current_module" != "$EXPECTED_VERSION" ]]; then
    die "Loaded AmneziaWG has incompatible version $current_module; refuse to replace it"
fi

build_module=1
if dkms status -m amneziawg -v 1.0.0 2>/dev/null | grep -F "$(uname -r)" | grep -q 'installed'; then
    say "DKMS module is already installed for $(uname -r); preserving it"
    build_module=0
fi
if [[ "$build_module" == 1 ]]; then
    if [[ -e /usr/src/amneziawg-1.0.0 ]]; then
        die '/usr/src/amneziawg-1.0.0 already exists but DKMS is not installed for this kernel; manual review required'
    fi
    work="$(mktemp -d /tmp/awg31-kmod.XXXXXXXX)"
    trap 'rm -rf -- "${work:-}"' EXIT
    say 'Cloning pinned official kernel module source'
    git clone -q https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git "$work/module"
    git -C "$work/module" checkout -q --detach "$KERNEL_COMMIT"
    [[ "$(git -C "$work/module" rev-parse HEAD)" == "$KERNEL_COMMIT" ]] || die 'Unexpected kernel source commit'
    if [[ "$AWG31_DISTRO:$AWG31_OS_VERSION" == 'ubuntu:26.04' ]]; then
        say 'Applying Ubuntu 26.04 UDP tunnel patch (upstream PR #265)'
        git -C "$work/module" apply --check "$PATCH_FILE" || die 'Compatibility patch does not apply; inspect sources'
        git -C "$work/module" apply "$PATCH_FILE"
    else
        say 'Using pinned upstream module without the Ubuntu 26.04-specific patch'
    fi
    say 'Copying source to DKMS and building for current kernel'
    make -C "$work/module/src" dkms-install
    dkms add -m amneziawg -v 1.0.0
    dkms build -m amneziawg -v 1.0.0 -k "$(uname -r)"
    dkms install -m amneziawg -v 1.0.0 -k "$(uname -r)"
    trap - EXIT
    rm -rf -- "$work"
fi

if ! modprobe amneziawg; then
    if [[ "$secure_boot" == enabled ]]; then
        cert=''
        for candidate in /var/lib/dkms/mok.pub /var/lib/shim-signed/mok/MOK.der; do
            if [[ -f "$candidate" ]]; then cert="$candidate"; break; fi
        done
        if [[ -n "$cert" ]] && ! mokutil --test-key "$cert" >/dev/null 2>&1; then
            if ! mokutil --list-new 2>/dev/null | grep -qE 'key|Owner|Fingerprint'; then
                say "Requesting MOK enrollment for $cert (requires console after reboot)"
                mokutil --import "$cert" || :
            fi
        fi
        cat >&2 <<'MSG'
The DKMS build is installed but Secure Boot rejected the module.
1. Check: mokutil --list-new
2. Reboot using the provider/hypervisor CONSOLE (not SSH).
3. In MOK Manager choose Enroll MOK, confirm, reboot.
4. Run the SAME Quick Start command again. Existing DKMS is reused.
No VPN configuration was created at this step.
MSG
    else
        printf 'Secure Boot status: %s. MOK enrollment is not requested by the installer.\n' "$secure_boot" >&2
    fi
    die 'Cannot load kernel module; inspect dmesg, DKMS and MOK enrollment'
fi
[[ "$(cat /sys/module/amneziawg/version)" == "$EXPECTED_VERSION" ]] || die 'Kernel module is not 3.1.20260812'
say "Kernel module $EXPECTED_VERSION loaded successfully"

if command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1 &&
   awg --version 2>/dev/null | grep -Fq "$TOOLS_TAG"; then
    say 'Compatible awg and awg-quick tools already installed; preserving them'
else
    if command -v awg >/dev/null 2>&1; then
        die 'Different AWG tools version detected; refuse to overwrite automatically'
    fi
    work="$(mktemp -d /tmp/awg31-tools.XXXXXXXX)"
    trap 'rm -rf -- "${work:-}"' EXIT
    say 'Cloning pinned official AWG 3.1 tools'
    git clone -q --depth 1 --branch "$TOOLS_TAG" \
      https://github.com/amnezia-vpn/amneziawg-tools.git "$work/tools"
    make -C "$work/tools/src" -j2
    make -C "$work/tools/src" install WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes
    systemctl daemon-reload
    trap - EXIT
    rm -rf -- "$work"
fi
awg --version | grep -Fq "$TOOLS_TAG" || die 'AWG tool version check failed'
command -v awg-quick >/dev/null || die 'awg-quick not installed'
say 'Upstream AWG 3.1 kernel module and tools ready'
