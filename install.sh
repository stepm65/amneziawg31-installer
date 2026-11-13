#!/usr/bin/env bash
# AmneziaWG 3.1 Console — one-command installer and updater.
#
#   bash <(curl -Ls https://raw.githubusercontent.com/stepm65/amneziawg31-installer/main/install.sh)
#   bash <(curl -Ls .../install.sh) v0.9.6        a specific release
#   bash <(curl -Ls .../install.sh) dev-latest    rolling build from main
#   bash <(curl -Ls .../install.sh) --upgrade     update panel + controller only
#   bash <(curl -Ls .../install.sh) --doctor      read-only diagnostics
#   bash <(curl -Ls .../install.sh) --uninstall [--purge]
#
# Unattended installation (no questions): set AWG31_UNATTENDED=1 and, when the
# defaults do not fit, AWG31_SUBNET, AWG31_PORT, AWG31_MTU, AWG31_ENDPOINT,
# AWG31_DNS, AWG31_MODE, AWG31_UPLINK, AWG31_PANEL_PORT, AWG31_FIRST_CLIENT,
# AWG31_PASSWORD_FILE, AWG31_OPEN_FIREWALL=no.
#
# Run it as root. Release archives are verified against the SHA256 sum
# published next to them; a mismatch aborts before anything is unpacked.
set -Eeuo pipefail
umask 077
REPO=stepm65/amneziawg31-installer
RAW="https://raw.githubusercontent.com/$REPO/main/install.sh"
say(){ printf '\n[AWG31] %s\n' "$*"; }
die(){ printf '[AWG31 ERROR] %s\n' "$*" >&2; exit 1; }
usage(){
    cat <<EOF
AmneziaWG 3.1 Console installer

  bash <(curl -Ls $RAW)              install the latest release
  bash <(curl -Ls $RAW) v0.9.6       install a specific release
  bash <(curl -Ls $RAW) dev-latest   install the rolling build from main
  ... --upgrade [VERSION]            update panel and controller, VPN untouched
  ... --doctor                       read-only diagnostics
  ... --uninstall [--purge]          remove the console (and, with --purge, all VPN data)
  ... --allow-downgrade              let --upgrade install an older version
  AWG31_UNATTENDED=1 ...             install without questions (see the README)
EOF
}

MODE=install
TARGET="${AWG31_VERSION:-}"
UNATTENDED="${AWG31_UNATTENDED:-0}"
ALLOW_DOWNGRADE=0
PURGE=0
for arg in "$@"; do
    case "$arg" in
        --install) MODE=install ;;
        --upgrade|--update) MODE=upgrade ;;
        --doctor) MODE=doctor ;;
        --uninstall) MODE=uninstall ;;
        --purge) PURGE=1 ;;
        --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
        -h|--help) usage; exit 0 ;;
        dev-latest) TARGET=dev-latest ;;
        v[0-9]*) TARGET="$arg" ;;
        *) usage >&2; die "Unknown argument: $arg" ;;
    esac
done
if [[ -n "$TARGET" && "$TARGET" != dev-latest && ! "$TARGET" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    die "Invalid version '$TARGET': use a release tag such as v0.9.6, or dev-latest"
fi

if [[ ${EUID} -ne 0 ]]; then
    cat >&2 <<EOF
[AWG31 ERROR] Root is required. Become root first, then repeat the command:

  sudo -i
  bash <(curl -Ls $RAW)${*:+ $*}

or, without a root shell:

  curl -Ls $RAW | sudo bash${*:+ -s -- $*}
EOF
    exit 1
fi
[[ -r /etc/os-release ]] || die 'Cannot read /etc/os-release'
# os-release defines NAME, VERSION, ID...: keep our own variables distinct (TARGET).
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:24.04|ubuntu:26.04|rocky:9|rocky:9.*|rocky:10|rocky:10.*) ;;
    *) die 'Supported: Ubuntu 24.04/26.04, Rocky Linux 9/10' ;;
esac
# The wizard asks questions on the terminal; everything else runs without one.
if [[ "$UNATTENDED" == 1 ]]; then
    TTY=/dev/null
else
    TTY=/dev/tty
    if [[ "$MODE" == install ]] && ! { : <"$TTY"; } 2>/dev/null; then
        die 'No terminal to ask questions on. Run from an interactive shell, or set AWG31_UNATTENDED=1.'
    fi
fi

# `bash <(curl ...)` and `curl ... | bash` have no project directory: BASH_SOURCE
# is /dev/fd/N or empty. Never treat the caller's working directory as ours.
SCRIPT_DIR=''
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fi
valid_project(){
    [[ -f "$1/scripts/setup-wizard.sh" && -f "$1/src/awg31ctl" && -f "$1/src/web.py" && -f "$1/scripts/uninstall.sh" &&
       -f "$1/scripts/prepare-awg31.sh" && -f "$1/scripts/upgrade-core.sh" && -f "$1/VERSION" ]]
}

WORK=''
cleanup(){ [[ -z "$WORK" ]] || rm -rf -- "$WORK"; }
trap cleanup EXIT

fetch(){  # url output max-seconds
    curl --fail --location --silent --show-error --retry 2 --connect-timeout 8 --max-time "$3" "$1" -o "$2"
}

latest_release(){
    # Prints the newest release tag, or nothing when none is published.
    local body tag=''
    body="$(curl --fail --silent --location --connect-timeout 8 --max-time 20 \
              -H 'Accept: application/vnd.github+json' \
              "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || :)"
    tag="$(printf '%s\n' "$body" | sed -nE 's/^[[:space:]]*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
    if [[ -z "$tag" ]]; then
        # API rate limit or outage: the web redirect names the tag as well.
        tag="$(curl --silent --head --connect-timeout 8 --max-time 20 -o /dev/null -w '%{redirect_url}' \
                 "https://github.com/$REPO/releases/latest" 2>/dev/null | sed -nE 's#.*/releases/tag/([^/?]+).*#\1#p' || :)"
    fi
    if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then printf '%s\n' "$tag"; fi
}

download_project(){
    local tag="$1" asset url
    for tool in curl tar sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
    done
    WORK="$(mktemp -d /tmp/awg31-install.XXXXXXXX)"
    mkdir "$WORK/project"
    if [[ "$tag" == dev-latest ]]; then
        say "Downloading the rolling build from main (not a release, no checksum pinning)"
        fetch "https://github.com/$REPO/archive/refs/heads/main.tar.gz" "$WORK/main.tar.gz" 180 ||
            die 'Cannot download the main branch from GitHub'
        tar -xzf "$WORK/main.tar.gz" -C "$WORK/project" --strip-components=1 --no-same-owner --no-same-permissions
    else
        asset="awg31-console-$tag.tar.gz"
        url="https://github.com/$REPO/releases/download/$tag"
        say "Downloading release $tag and its SHA256 sum"
        fetch "$url/$asset" "$WORK/$asset" 180 || die "Release $tag not found"
        fetch "$url/$asset.sha256" "$WORK/$asset.sha256" 30 || die "SHA256 file for $tag is missing; refusing to install"
        [[ "$(wc -l < "$WORK/$asset.sha256")" -le 1 ]] || die 'Malformed checksum file'
        grep -Eq "^[0-9a-f]{64}  ${asset//./\\.}\$" "$WORK/$asset.sha256" || die 'Unexpected checksum format'
        (cd "$WORK" && sha256sum --check --status "$asset.sha256") || die 'SHA256 mismatch: the archive is damaged or was replaced. Nothing was installed.'
        say "SHA256 verified: $(cut -c1-16 "$WORK/$asset.sha256")…"
        tar -xzf "$WORK/$asset" -C "$WORK/project" --strip-components=1 --no-same-owner --no-same-permissions
    fi
    PROJECT="$WORK/project"
    valid_project "$PROJECT" || die 'Downloaded archive has an unexpected layout'
}

if [[ -z "$TARGET" && -n "$SCRIPT_DIR" ]] && valid_project "$SCRIPT_DIR"; then
    PROJECT="$SCRIPT_DIR"
    say "Using the local project directory ($(cat "$PROJECT/VERSION"))"
else
    if [[ -z "$TARGET" ]]; then
        TARGET="$(latest_release)"
        if [[ -z "$TARGET" ]]; then
            say 'No published release found; falling back to the rolling build (dev-latest)'
            TARGET=dev-latest
        fi
    fi
    download_project "$TARGET"
    say "Version to install: $(cat "$PROJECT/VERSION")${TARGET:+ ($TARGET)}"
fi

install_menu(){
    if [[ -f "$PROJECT/scripts/awg31-menu" ]]; then
        install -o root -g root -m 755 "$PROJECT/scripts/awg31-menu" /usr/local/bin/awg31
    fi
    # `awg31 update` runs this verified copy instead of fetching a script from main.
    install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
    install -o root -g root -m 755 "$PROJECT/install.sh" /usr/local/libexec/awg31/install.sh
    install -o root -g root -m 755 "$PROJECT/scripts/uninstall.sh" /usr/local/libexec/awg31/scripts/uninstall.sh
}

if [[ "$MODE" == doctor ]]; then
    bash "$PROJECT/scripts/doctor.sh"
    exit 0
fi

if [[ "$MODE" == uninstall ]]; then
    args=()
    if ((PURGE)); then args+=(--purge); fi
    if [[ "$UNATTENDED" == 1 ]]; then args+=(--yes); fi
    if [[ "$UNATTENDED" == 1 ]]; then
        bash "$PROJECT/scripts/uninstall.sh" "${args[@]}"
    else
        bash "$PROJECT/scripts/uninstall.sh" "${args[@]}" <"$TTY"
    fi
    exit $?
fi

# Three states, judged by what a finished installation always leaves behind:
#   complete     the service unit, the credentials and the code are all present
#   interrupted  VPN data exists, but the panel was never finished
#   fresh        neither; stray program files from a failed first attempt do not count
panel_installed=0
if [[ -f /etc/systemd/system/awg31-panel.service && -f /etc/awg31-panel/auth.json &&
      -f /opt/awg31-panel/web.py && -f /usr/local/sbin/awg31ctl ]]; then
    panel_installed=1
fi
vpn_data=0
if [[ -f /var/lib/awg31-panel/state.sqlite3 || -e /etc/amnezia/amneziawg/awg0.conf || -d /var/lib/awg31-panel/servers ]]; then
    vpn_data=1
fi

if [[ "$MODE" == install && $panel_installed -eq 1 ]]; then
    say 'AmneziaWG 3.1 Console is already installed here: switching to update mode'
    MODE=upgrade
fi

if [[ "$MODE" == upgrade ]]; then
    [[ $panel_installed -eq 1 ]] || die 'Nothing to update: the console is not (fully) installed. Run the installer without --upgrade.'
    current="$(tr -d '[:space:]' < /opt/awg31-panel/VERSION 2>/dev/null || :)"
    wanted="$(tr -d '[:space:]' < "$PROJECT/VERSION")"
    if [[ -n "$current" && "$current" != "$wanted" && $ALLOW_DOWNGRADE -eq 0 ]] &&
       [[ "$(printf '%s\n%s\n' "$current" "$wanted" | sort -V | head -n1)" == "$wanted" ]]; then
        die "Installed version $current is newer than $wanted. Older code may not understand the current databases. Add --allow-downgrade to do it anyway."
    fi
    say "Updating panel and controller${current:+ from $current} to $wanted; VPN interfaces, keys and clients are not touched"
    bash "$PROJECT/scripts/upgrade-core.sh"
    install_menu
    say "Update finished: $wanted. Menu: sudo awg31"
    exit 0
fi

if [[ $vpn_data -eq 1 ]]; then
    cat >&2 <<EOF
[AWG31 ERROR] VPN data exists here, but the panel is not installed (an interrupted
installation, or an uninstall that kept the data). Nothing was overwritten.
  Start over, deleting that data:   run this installer with  --uninstall --purge
  Finish an interrupted setup:      see "Interrupted installation" in the README
EOF
    exit 1
fi
if [[ -e /opt/awg31-panel || -e /usr/local/sbin/awg31ctl ]]; then
    say 'Found program files from an unfinished earlier attempt (no VPN data): installing over them'
fi
say 'Preparing the AmneziaWG 3.1 kernel module and tools (no PPA, no Docker)'
bash "$PROJECT/scripts/prepare-awg31.sh" <"$TTY" ||
    die 'Prerequisites are not ready. If Secure Boot asked for MOK enrolment, enrol the key and run the same command again.'
if [[ "$UNATTENDED" == 1 ]]; then
    say 'Starting the unattended VPN and web panel setup'
else
    say 'Starting the interactive VPN and web panel setup'
fi
AWG31_UNATTENDED="$UNATTENDED" bash "$PROJECT/scripts/setup-wizard.sh" <"$TTY"
install_menu
