#!/usr/bin/env bash
# Shared OS and package-management support for AWG Console.
# No network or disk changes occur when this file is sourced.
awg31_die() { printf '[AWG31 ERROR] %s\n' "$*" >&2; exit 1; }
awg31_detect_os() {
  [[ -r /etc/os-release ]] || awg31_die 'Cannot read /etc/os-release'
  . /etc/os-release
  AWG31_DISTRO="${ID:-}"
  AWG31_OS_VERSION="${VERSION_ID:-}"
  AWG31_OS_FAMILY=''
  case "$AWG31_DISTRO:$AWG31_OS_VERSION" in
    ubuntu:24.04|ubuntu:26.04) AWG31_OS_FAMILY=deb ;;
    rocky:9.*|rocky:10.*|rocky:9|rocky:10) AWG31_OS_FAMILY=rpm ;;
    *) awg31_die "Unsupported OS: ${PRETTY_NAME:-$AWG31_DISTRO $AWG31_OS_VERSION}. Tested target families: Ubuntu 24.04/26.04, Rocky Linux 9/10. Rocky 8 requires separate validation." ;;
  esac
  export AWG31_DISTRO AWG31_OS_VERSION AWG31_OS_FAMILY
  case "$(uname -m)" in x86_64|aarch64) ;; *) awg31_die 'Supported CPUs: x86_64, aarch64' ;; esac
}
awg31_secure_boot() {
  local result
  if ! command -v mokutil >/dev/null 2>&1; then printf 'unknown\n'; return 0; fi
  result="$(mokutil --sb-state 2>&1 || :)"
  case "$result" in
    *'SecureBoot enabled'*) printf 'enabled\n' ;;
    *'SecureBoot disabled'*) printf 'disabled\n' ;;
    *) printf 'unknown\n' ;;
  esac
}
awg31_rocky_repos() {
  [[ "$AWG31_OS_FAMILY" == rpm ]] || return 0
  # CRB is required by EPEL dependency chains. Do not suppress repo failures.
  dnf -y install dnf-plugins-core
  dnf config-manager --set-enabled crb
  dnf -y install epel-release
  dnf -y makecache
}
awg31_install_packages() {
  [[ -d "/lib/modules/$(uname -r)/build" || -d "/usr/src/kernels/$(uname -r)" ]] || :
  if [[ "$AWG31_OS_FAMILY" == deb ]]; then
    apt-get -o Acquire::ForceIPv4=true update
    DEBIAN_FRONTEND=readline apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends \
      git curl ca-certificates build-essential make gcc dkms mokutil \
      "linux-headers-$(uname -r)" python3 python3-venv python3-pip \
      iproute2 iptables sudo gnupg
    # The line above covers only the running kernel. The meta package of the same
    # flavour (generic, virtual, aws, azure...) brings headers for every future
    # kernel, so DKMS can rebuild the module after an update. Best effort.
    local flavour
    flavour="$(uname -r)"; flavour="${flavour##*-}"
    if apt-cache show "linux-headers-$flavour" >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends \
        "linux-headers-$flavour" || echo "[AWG31 WARNING] linux-headers-$flavour not installed: after a kernel update install matching headers yourself" >&2
    fi
  else
    awg31_rocky_repos
    # Exact running-kernel package is essential: upgrading kernel-devel alone can
    # leave DKMS compiling for a different kernel without user noticing.
    dnf -y install "kernel-devel-$(uname -r)" || awg31_die 'Matching kernel-devel unavailable: update kernel packages, reboot, then retry'
    dnf -y install git curl ca-certificates gcc make dkms mokutil \
      python3 python3-pip iproute iproute-tc iptables sudo gnupg2 tar
  fi
  [[ -d "/lib/modules/$(uname -r)/build" ]] || awg31_die "Missing build tree for running kernel $(uname -r). Reboot after installing the matching kernel-devel package."
  python3 -c 'import venv, ensurepip' || awg31_die 'Python venv/ensurepip unavailable on this OS image'
}

# Wait until the panel answers on localhost. `systemctl start` returns as soon
# as the process is spawned, while uvicorn needs a moment to import the
# application and bind the port; an immediate request is refused.
# Usage: awg31_wait_panel PORT [SECONDS]; returns 1 on timeout or a failed unit.
awg31_wait_panel() {
  local port="$1" deadline=$((SECONDS + ${2:-45}))
  while ((SECONDS < deadline)); do
    if curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
      return 0
    fi
    # A crashed unit will not recover by waiting: stop early and show why.
    if systemctl is-failed --quiet awg31-panel.service 2>/dev/null; then break; fi
    sleep 1
  done
  printf '[AWG31 ERROR] Panel does not answer on 127.0.0.1:%s. Last service log lines:\n' "$port" >&2
  journalctl -u awg31-panel.service -n 25 --no-pager >&2 2>/dev/null || :
  return 1
}

# systemd older than 254 (Rocky Linux 9, Ubuntu 22.04, Debian 12) turns on
# "no new privileges" for a non-root service that uses RestrictAddressFamilies,
# and sudo then refuses to run. The panel and the bot cannot work without sudo,
# so on those systems the unit goes without that one restriction.
awg31_unit_compat() {
    local unit="$1" version
    version="$(systemctl --version 2>/dev/null | awk 'NR==1 {print $2}')"
    [[ "$version" =~ ^[0-9]+$ ]] || version=0
    if (( version < 254 )) && [[ -f "$unit" ]]; then
        sed -i '/^RestrictAddressFamilies=/d' "$unit"
    fi
}

