#!/usr/bin/env bash
# One-command bootstrap. Designed for `curl -fsSL URL | sudo bash`, or local `sudo bash bootstrap.sh`.
set -Eeuo pipefail
umask 077
REPO=stepm65/amneziawg31-installer
RELEASE_TAG="${AWG31_RELEASE_TAG:-main}"
ASSET="amneziawg31-ubuntu-installer-${RELEASE_TAG}.tar.gz"
say(){ printf '\n[AWG31 Quick Start] %s\n' "$*"; }
die(){ printf '[AWG31 Quick Start ERROR] %s\n' "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || die 'Run as root: curl -fsSL ... | sudo bash, or sudo bash bootstrap.sh'
case "${1:---install}" in --install|--upgrade|--doctor) MODE="${1:---install}" ;; *) die 'Allowed: --install, --upgrade, --doctor' ;; esac
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in ubuntu:24.04|ubuntu:26.04|rocky:9|rocky:9.*|rocky:10|rocky:10.*) ;; *) die 'Supported: Ubuntu 24.04/26.04, Rocky Linux 9/10';; esac
[[ -t 0 || -r /dev/tty ]] || die 'An interactive TTY is required'

# When launched via `curl ... | bash`, BASH_SOURCE[0] is unset under `set -u`.
# Never treat the arbitrary caller's cwd as our project directory.
SCRIPT_DIR=''
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fi
WORK=""
cleanup(){ [[ -z "$WORK" ]] || rm -rf -- "$WORK"; }
trap cleanup EXIT
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/install.sh" && -f "$SCRIPT_DIR/src/awg31ctl" && -f "$SCRIPT_DIR/scripts/prepare-awg31.sh" ]]; then
    PROJECT="$SCRIPT_DIR"
    say 'Using local project directory'
else
    WORK="$(mktemp -d /tmp/awg31-quickstart.XXXXXXXX)"
    cd "$WORK"
    if [[ "$RELEASE_TAG" == main ]]; then
        # Before a GitHub Release exists, install from main's current tree.
        # This is rolling and not checksum-pinned; users may choose a pinned
        # release tag later. Github over TLS is the source of trust here.
        if ! command -v git >/dev/null 2>&1; then
            say 'Installing git for first-time Quick Start'
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update && apt-get install -y git ca-certificates
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y git ca-certificates
            else
                die 'Install git manually to use the main branch'
            fi
        fi
        say "Cloning $REPO main (rolling branch, not release-pinned)"
        git clone --quiet --depth 1 --branch main "https://github.com/$REPO.git" project || die 'Public GitHub repository not found'
        PROJECT="$WORK/project"
        say "Checked out commit $(git -C "$PROJECT" rev-parse --short=12 HEAD)"
    else
        command -v curl >/dev/null || die 'curl is missing'
        command -v sha256sum >/dev/null || die 'sha256sum is missing'
        command -v tar >/dev/null || die 'tar is missing'
        [[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-test)?$ ]] || die 'Invalid AWG31_RELEASE_TAG'
        URL="https://github.com/$REPO/releases/download/$RELEASE_TAG"
        say "Downloading release $RELEASE_TAG and SHA256 from GitHub"
        curl --fail --location --silent --show-error --retry 2 --connect-timeout 8 --max-time 120 \
            "$URL/$ASSET" -o "$ASSET" || die 'Release not found'
        curl --fail --location --silent --show-error --retry 2 --connect-timeout 8 --max-time 30 \
            "$URL/$ASSET.sha256" -o "$ASSET.sha256" || die 'SHA256 verification file is missing'
        [[ "$(wc -l < "$ASSET.sha256")" == 1 ]] || die 'Malformed checksum file'
        grep -Eq "^[0-9a-f]{64}  ${ASSET//./\.}$" "$ASSET.sha256" || die 'Unexpected checksum format'
        sha256sum --check --status "$ASSET.sha256" || die 'Release checksum mismatch; aborting'
        mkdir project
        tar -xzf "$ASSET" -C project --strip-components=1 --no-same-owner --no-same-permissions
        PROJECT="$WORK/project"
    fi
    [[ -f "$PROJECT/install.sh" && -f "$PROJECT/src/awg31ctl" && -f "$PROJECT/scripts/prepare-awg31.sh" ]] || die 'Invalid project layout'

fi

if [[ "$MODE" == --doctor ]]; then
    bash "$PROJECT/scripts/doctor.sh"
    exit 0
fi
if [[ "$MODE" == --upgrade ]]; then
    [[ -f /var/lib/awg31-panel/state.sqlite3 ]] || die 'No existing AWG31 installation for upgrade'
    say 'Upgrading panel + controller only; VPN configurations are preserved'
    bash "$PROJECT/scripts/upgrade-core.sh"
    if [[ -f "$PROJECT/scripts/awg31-menu" ]]; then
        install -o root -g root -m 755 "$PROJECT/scripts/awg31-menu" /usr/local/bin/awg31
    fi
    exit 0
fi

if [[ -f /var/lib/awg31-panel/state.sqlite3 || -e /etc/amnezia/amneziawg/awg0.conf ]]; then
    die 'An AWG31 server already exists. Use --upgrade instead. Nothing was overwritten.'
fi
say 'Preparing AmneziaWG 3.1 kernel module and tools (no PPA, no Docker)'
bash "$PROJECT/scripts/prepare-awg31.sh" </dev/tty || die 'Prerequisites not ready. If Secure Boot requested MOK enrollment, enroll it and run Quick Start again.'
say 'Starting interactive VPN & web panel setup'
bash "$PROJECT/install.sh" </dev/tty
if [[ -f "$PROJECT/scripts/awg31-menu" ]]; then
    install -o root -g root -m 755 "$PROJECT/scripts/awg31-menu" /usr/local/bin/awg31
fi
say 'Installation finished. Use sudo awg31 to manage services.'
