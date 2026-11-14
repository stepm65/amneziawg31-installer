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
kernel="$(uname -r)"
dkms_clean() {
    dkms remove amneziawg/1.0.0 --all >/dev/null 2>&1 || :
    rm -rf /usr/src/amneziawg-1.0.0 /var/lib/dkms/amneziawg
}
dkms_build() {
    # Returns 1 when the module does not compile for the running kernel.
    if dkms build -m amneziawg -v 1.0.0 -k "$kernel" && dkms install -m amneziawg -v 1.0.0 -k "$kernel"; then
        return 0
    fi
    echo '[AWG31/prepare] Last lines of the build log:' >&2
    tail -n 25 /var/lib/dkms/amneziawg/1.0.0/build/make.log >&2 2>/dev/null || :
    return 1
}
# Build from the pinned source; with_patch=1 adds the upstream compatibility
# patch for kernels whose UDP tunnel API changed (7.0 and distro backports).
build_from_source() {
    local with_patch="$1"
    rm -rf -- "$work/module"
    git clone -q https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git "$work/module"
    git -C "$work/module" checkout -q --detach "$KERNEL_COMMIT"
    [[ "$(git -C "$work/module" rev-parse HEAD)" == "$KERNEL_COMMIT" ]] || die 'Unexpected kernel source commit'
    # RHEL-family kernels (Rocky 9.8+) backport timer_container_of() and drop
    # from_timer(); the module's compat header must not redefine it there.
    # The guard changes nothing on kernels that do not have the macro.
    sed -i 's/^#define timer_container_of from_timer$/#ifndef timer_container_of\n#define timer_container_of from_timer\n#endif/' \
        "$work/module/src/compat/compat.h"
    grep -q '^#ifndef timer_container_of$' "$work/module/src/compat/compat.h" || die 'Unexpected compat.h in the pinned module source'
    if [[ "$with_patch" == 1 ]]; then
        say 'Applying the UDP tunnel compatibility patch (upstream PR #265)'
        git -C "$work/module" apply --check "$PATCH_FILE" || die 'Compatibility patch does not apply; inspect sources'
        git -C "$work/module" apply "$PATCH_FILE"
    fi
    say "Copying source to DKMS and building for kernel $kernel"
    make -C "$work/module/src" dkms-install
    dkms add -m amneziawg -v 1.0.0
    dkms_build
}
if [[ "$build_module" == 1 ]]; then
    if [[ -e /usr/src/amneziawg-1.0.0 ]] && dkms status -m amneziawg -v 1.0.0 2>/dev/null | grep -q .; then
        # The source is registered but not built for this kernel: the usual
        # situation after a kernel update. Build it for the running kernel.
        say "DKMS source is present; building the module for the new kernel $kernel"
        if ! dkms_build; then
            say 'The registered source does not build for this kernel; starting from the pinned source again'
            dkms_clean
        else
            build_module=0
        fi
    elif [[ -e /usr/src/amneziawg-1.0.0 ]]; then
        say 'Removing an unregistered source tree left by an earlier failed attempt'
        dkms_clean
    fi
fi
if [[ "$build_module" == 1 ]]; then
    work="$(mktemp -d /tmp/awg31-kmod.XXXXXXXX)"
    trap 'rm -rf -- "${work:-}"' EXIT
    say 'Cloning pinned official kernel module source'
    # Kernels from 7.0 on need the patch; older ones are tried without it first,
    # because distributions backport the API change without changing the version.
    kernel_major="${kernel%%.*}"
    first_try=0
    if [[ "$AWG31_DISTRO:$AWG31_OS_VERSION" == 'ubuntu:26.04' ]] || { [[ "$kernel_major" =~ ^[0-9]+$ ]] && ((kernel_major >= 7)); }; then
        first_try=1
    fi
    if ! build_from_source "$first_try"; then
        dkms_clean
        other=$((1 - first_try))
        say "Build failed; retrying $([[ $other == 1 ]] && echo with || echo without) the compatibility patch"
        if ! build_from_source "$other"; then
            dkms_clean       # leave nothing behind, so the next run starts clean
            die "The AmneziaWG module does not build for kernel $kernel. See the build log lines above."
        fi
    fi
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
