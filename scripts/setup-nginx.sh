#!/usr/bin/env bash
# Optional HTTPS reverse proxy for the local-only AWG31 web panel.
# Can also be run after initial installation: sudo bash scripts/setup-nginx.sh --interactive
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/os-support.sh"
proxy_log() { printf '[AWG31/Nginx] %s\n' "$*"; }
proxy_die() { printf '[AWG31/Nginx ERROR] %s\n' "$*" >&2; exit 1; }
proxy_ask() { local var="$1" prompt="$2" fallback="$3" reply; read -r -p "$prompt [$fallback]: " reply </dev/tty; printf -v "$var" '%s' "${reply:-$fallback}"; }
proxy_ask_yes() { local prompt="$1" ans; read -r -p "$prompt [y/N]: " ans </dev/tty; [[ "${ans,,}" == 'y' || "${ans,,}" == 'yes' || "$ans" == 'д' ]]; }

# Host strings are inserted as Nginx config tokens and certificate SANs.
# Reject metacharacters, IPv6, schemes, paths and wildcard hostnames.
proxy_validate_host() {
    python3 - "$1" <<'PY'
import ipaddress,re,sys
v=sys.argv[1]
try:
    ip=ipaddress.ip_address(v)
    if ip.version != 4: raise ValueError('IPv4 only')
except ValueError:
    if (not v or len(v)>253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',v) or
        any(not 1 <= len(s) <= 63 or s.startswith('-') or s.endswith('-') for s in v.split('.'))):
        sys.exit('Invalid hostname; use DNS name or IPv4 address, without scheme/port/path')
PY
}
proxy_validate_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)) || proxy_die "Invalid TCP port: $1"
}
proxy_validate_certificate() {
    local cert="$1" key="$2" cert_public key_public
    [[ "$cert" = /* && "$key" = /* && -f "$cert" && -f "$key" ]] || proxy_die 'Certificate and key must be existing absolute file paths'
    openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null || proxy_die 'Certificate invalid or expires in less than 24 hours'
    openssl pkey -in "$key" -passin pass: -noout >/dev/null 2>&1 || proxy_die 'Private key cannot be read without a password'
    cert_public="$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)"
    key_public="$(openssl pkey -in "$key" -passin pass: -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
    [[ "$cert_public" == "$key_public" ]] || proxy_die 'Certificate and private key do not match'
}
# Comma- or space-separated IPv4 addresses/CIDRs allowed to open the panel.
proxy_validate_allow() {
    python3 - "$1" <<'PY'
import ipaddress,re,sys
for item in filter(None, re.split(r'[,\s]+', sys.argv[1])):
    try:
        if ipaddress.ip_network(item, strict=False).version != 4: raise ValueError
    except ValueError:
        sys.exit(f'Invalid IPv4 address or CIDR in the allow list: {item[:40]}')
PY
}
proxy_render_config() {
    local domain="$1" https_port="$2" panel_port="$3" cert="$4" key="$5" allow="${6:-}" access='' item
    for item in ${allow//,/ }; do access+="    allow ${item};"$'\n'; done
    # The installer's own health check connects from this host.
    if [[ -n "$access" ]]; then access="    allow 127.0.0.1;"$'\n'"${access}    deny all;"$'\n'; fi
    # Inputs must be validated before calling this function when writing config.
    cat <<EOF
# AWG31 managed virtual host. Do not store certificates or keys in this file.
# TLS listener is IPv4-only; the panel backend stays on 127.0.0.1.
# Sign-in attempts are limited per address before they reach the panel.
limit_req_zone \$binary_remote_addr zone=awg31_login:10m rate=10r/m;
server {
    listen ${https_port} ssl;
    server_name ${domain};

    ssl_certificate ${cert};
    ssl_certificate_key ${key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    server_tokens off;
    client_max_body_size 1m;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Strict-Transport-Security "max-age=31536000" always;
${access}
    location = /login {
        limit_req zone=awg31_login burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:${panel_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        proxy_pass http://127.0.0.1:${panel_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 30s;
        proxy_buffering off;
    }
}
EOF
}
proxy_self_signed_cert() {
    local host="$1" dir="$2" cert="$3" key="$4" san
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then san="IP:$host"; else san="DNS:$host"; fi
    [[ -d "$dir/certs" && -d "$dir/private" ]] || proxy_die "Standard TLS directories not found in $dir"
    [[ ! -e "$cert" && ! -e "$key" ]] || proxy_die "Certificate files already exist: $cert / $key (not overwritten)"
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
        -subj "/CN=$host" -addext "subjectAltName=$san" \
        -keyout "$key" -out "$cert" >/dev/null 2>&1 || proxy_die 'Self-signed certificate generation failed'
    chmod 600 "$key"
    chmod 644 "$cert"
    proxy_validate_certificate "$cert" "$key"
}
proxy_firewall_offer() {
    local port="$1" answer
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        if proxy_ask_yes "Open TCP/$port in firewalld for external panel access?"; then
            if firewall-cmd --permanent --add-port="$port/tcp" >/dev/null && firewall-cmd --reload >/dev/null; then
                proxy_log "firewalld: opened TCP/$port; verify active zone policy and upstream firewall"
            else
                proxy_log "WARNING: firewall-cmd failed to open TCP/$port; configure it manually"
            fi
        else
            proxy_log "TCP/$port not opened in firewalld"
        fi
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        if proxy_ask_yes "Open TCP/$port with UFW for external panel access?"; then
            ufw allow "$port/tcp" || proxy_log "WARNING: UFW did not open TCP/$port"
        else
            proxy_log "TCP/$port not opened in UFW"
        fi
    fi
}
proxy_interactive() {
    local answer
    proxy_ask answer 'Reverse proxy: 0 = no Nginx, 1 = self-signed TLS, 2 = existing certificate/key' '0'
    case "$answer" in
        0) AWG31_PROXY_MODE=none ;;
        1) AWG31_PROXY_MODE=self-signed ;;
        2) AWG31_PROXY_MODE=existing ;;
        *) proxy_die 'Enter 0, 1 or 2' ;;
    esac
    if [[ "$AWG31_PROXY_MODE" != none ]]; then
        proxy_ask AWG31_PROXY_HOST 'Domain or IPv4 for Nginx HTTPS (without https://)' 'vpn.example.net'
        proxy_ask AWG31_PROXY_HTTPS_PORT 'Public HTTPS TCP port' '443'
        proxy_ask AWG31_PANEL_PORT 'Local panel TCP port' '8080'
        proxy_ask AWG31_PROXY_ALLOW 'IPv4 addresses/CIDRs allowed to open the panel, comma-separated (all = everyone)' 'all'
        [[ "$AWG31_PROXY_ALLOW" != all ]] || AWG31_PROXY_ALLOW=''
        if [[ "$AWG31_PROXY_MODE" == existing ]]; then
            proxy_ask AWG31_PROXY_CERT 'Absolute path to certificate/fullchain PEM' '/etc/letsencrypt/live/vpn.example.net/fullchain.pem'
            proxy_ask AWG31_PROXY_KEY 'Absolute path to unencrypted private key PEM' '/etc/letsencrypt/live/vpn.example.net/privkey.pem'
        fi
        if [[ "$(getenforce 2>/dev/null || :)" == Enforcing ]] && command -v getsebool >/dev/null 2>&1 &&
           getsebool httpd_can_network_connect 2>/dev/null | grep -q -- '--> off'; then
            proxy_log 'SELinux Enforcing: Nginx requires httpd_can_network_connect=on for localhost proxying.'
            proxy_ask_yes 'Allow this SELinux boolean change?' || proxy_die 'Nginx reverse proxy not configured without SELinux permission'
            AWG31_PROXY_SELINUX_ACK=yes
        fi
    fi
}
proxy_main() {
    local mode host https_port panel_port cert key cert_dir conf occupied site_created=0 generated=0 changed_ipv6_vendor=0
    local selinux_changed=0
    if [[ "${1:-}" == --interactive ]]; then proxy_interactive; elif [[ $# -ne 0 ]]; then proxy_die 'Usage: sudo bash scripts/setup-nginx.sh [--interactive]'; fi
    mode="${AWG31_PROXY_MODE:-none}"
    case "$mode" in none|self-signed|existing) ;; *) proxy_die 'Invalid Nginx mode';; esac
    if [[ "$mode" == none ]]; then proxy_log 'No reverse proxy selected: panel remains bound to 127.0.0.1'; return 0; fi
    [[ $EUID -eq 0 ]] || proxy_die 'Run as root'
    awg31_detect_os
    host="${AWG31_PROXY_HOST:-}"
    https_port="${AWG31_PROXY_HTTPS_PORT:-443}"
    panel_port="${AWG31_PANEL_PORT:-8080}"
    proxy_validate_host "$host"
    proxy_validate_port "$https_port"
    proxy_validate_port "$panel_port"
    [[ "$https_port" != "$panel_port" ]] || proxy_die 'HTTPS port must differ from panel localhost port'
    proxy_validate_allow "${AWG31_PROXY_ALLOW:-}"
    # Use standard TLS certificate directories to retain SELinux labels on Rocky.
    if [[ "$AWG31_OS_FAMILY" == rpm ]]; then
        cert_dir=/etc/pki/tls
        cert="$cert_dir/certs/awg31-selfsigned.crt"
        key="$cert_dir/private/awg31-selfsigned.key"
    else
        cert_dir=/etc/ssl
        cert="$cert_dir/certs/awg31-selfsigned.crt"
        key="$cert_dir/private/awg31-selfsigned.key"
    fi
    if [[ "$mode" == existing ]]; then
        cert="${AWG31_PROXY_CERT:-}"
        key="${AWG31_PROXY_KEY:-}"
        [[ "$cert" =~ ^/[A-Za-z0-9._/@+:-]+$ && "$key" =~ ^/[A-Za-z0-9._/@+:-]+$ ]] || proxy_die 'Certificate path contains unsupported characters'
        [[ -f "$cert" && -f "$key" ]] || proxy_die 'Certificate/key files not found'
        if ! command -v openssl >/dev/null 2>&1; then
            if [[ "$AWG31_OS_FAMILY" == deb ]]; then
                DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::ForceIPv4=true install -y openssl
            else
                dnf -y install openssl
            fi
        fi
        proxy_validate_certificate "$cert" "$key"
    fi
    conf=/etc/nginx/conf.d/awg31-panel.conf
    [[ ! -e "$conf" ]] || proxy_die "Nginx config already exists: $conf (no overwrite). Edit it manually or back it up first."
    # Up-front collision check: an existing nginx may share 443 with a new named vhost.
    occupied="$(ss -H -ltnp "sport = :$https_port" 2>/dev/null || :)"
    if [[ -n "$occupied" ]] && ! grep -q 'nginx' <<<"$occupied"; then
        proxy_die "TCP/$https_port is occupied by another service; Nginx config not installed"
    fi
    if [[ "$(getenforce 2>/dev/null || :)" == Enforcing ]]; then
        # SELinux does not ordinarily allow Nginx to bind arbitrary TCP ports.
        # Require the default port rather than changing security policy implicitly.
        [[ "$https_port" == 443 ]] || proxy_die 'With SELinux Enforcing use HTTPS port 443; custom port requires manual semanage port labeling'
        if command -v getsebool >/dev/null 2>&1 && getsebool httpd_can_network_connect 2>/dev/null | grep -q -- '--> off'; then
            [[ "${AWG31_PROXY_SELINUX_ACK:-}" == yes ]] || proxy_die 'SELinux blocks proxy-to-localhost; allow httpd_can_network_connect explicitly first'
        fi
    fi
    command -v curl >/dev/null || proxy_die 'curl is required to check panel health'
    curl --noproxy '*' -4fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:$panel_port/health" >/dev/null || proxy_die "Panel not healthy on 127.0.0.1:$panel_port"
    proxy_cleanup_on_error() {
        local exit_code=$?
        if ((exit_code != 0)); then
            if ((site_created)); then
                rm -f -- "$conf"
                if systemctl is-active --quiet nginx 2>/dev/null; then nginx -t && systemctl reload nginx || :; fi
            fi
            if ((generated)); then rm -f -- "$cert" "$key"; fi
            if ((selinux_changed)); then setsebool -P httpd_can_network_connect off || :; fi
            # Vendor files may have been adjusted only on a fresh install with
            # IPv6 unavailable; restore exact backups on a failed setup.
            if ((changed_ipv6_vendor)); then
                for vendor_conf in /etc/nginx/sites-available/default /etc/nginx/nginx.conf; do
                    if [[ -f "${vendor_conf}.awg31-before-ipv6" ]]; then
                        cp -p -- "${vendor_conf}.awg31-before-ipv6" "$vendor_conf" || :
                    fi
                done
            fi
            proxy_log 'Nginx setup failed; AWG VPN and web panel remain installed. Newly added site config rolled back.'
        fi
        return "$exit_code"
    }
    trap proxy_cleanup_on_error EXIT
    if command -v nginx >/dev/null 2>&1; then
        nginx -t || proxy_die 'Existing nginx configuration is invalid; nothing modified'
    else
        proxy_log "Installing nginx and openssl with $AWG31_OS_FAMILY package manager"
        if [[ "$AWG31_OS_FAMILY" == deb ]]; then
            DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends nginx openssl
        else
            dnf -y install nginx openssl
        fi
        if [[ ! -e /proc/net/if_inet6 ]]; then
            # IPv6 kernel unavailable: newly installed vendor default may bind [::]:80.
            # Back up and comment out only exactly matching default listener lines.
            for vendor_conf in /etc/nginx/sites-available/default /etc/nginx/nginx.conf; do
                [[ -f "$vendor_conf" ]] || continue
                if grep -Eq '^[[:space:]]*listen[[:space:]]+\[::\]:80([^;]*);[[:space:]]*$' "$vendor_conf"; then
                    [[ ! -e "${vendor_conf}.awg31-before-ipv6" ]] || proxy_die "Backup path already exists: ${vendor_conf}.awg31-before-ipv6"
                    cp -p -- "$vendor_conf" "${vendor_conf}.awg31-before-ipv6"
                    changed_ipv6_vendor=1
                    sed -Ei '/^[[:space:]]*listen[[:space:]]+\[::\]:80([^;]*);[[:space:]]*$/s@^@# AWG31 IPv4-only vendor listener: @' "$vendor_conf"
                    proxy_log "Disabled vendor IPv6 :80 listener in $vendor_conf (backup retained)"
                fi
            done
        fi
    fi
    command -v openssl >/dev/null || proxy_die 'OpenSSL not installed'
    [[ -d /etc/nginx/conf.d ]] || proxy_die 'Missing /etc/nginx/conf.d'
    grep -Eq '^[[:space:]]*include[[:space:]]+/etc/nginx/conf\.d/\*\.conf[[:space:]]*;' /etc/nginx/nginx.conf ||
        proxy_die 'nginx.conf does not include conf.d/*.conf; refusing to edit existing nginx.conf'
    nginx -t || proxy_die 'Nginx configuration invalid before changes'
    if [[ "$mode" == self-signed ]]; then
        [[ ! -e "$cert" && ! -e "$key" ]] || proxy_die 'Self-signed files already exist; not overwriting them'
        generated=1  # remove partial key/cert on OpenSSL failure
        proxy_self_signed_cert "$host" "$cert_dir" "$cert" "$key"
    fi
    # Keep config private during installation; nginx master is root.
    proxy_render_config "$host" "$https_port" "$panel_port" "$cert" "$key" "${AWG31_PROXY_ALLOW:-}" >"$conf"
    chmod 644 "$conf"
    site_created=1
    nginx -t
    if [[ "$(getenforce 2>/dev/null || :)" == Enforcing ]] && command -v getsebool >/dev/null 2>&1 &&
       getsebool httpd_can_network_connect 2>/dev/null | grep -q -- '--> off'; then
        setsebool -P httpd_can_network_connect on
        selinux_changed=1
    fi
    systemctl enable nginx >/dev/null
    if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl start nginx; fi
    # Resolve locally so the test does not depend on external DNS/firewalls.
    if ! curl --noproxy '*' -kfsS --connect-timeout 3 --max-time 8 \
          --resolve "$host:$https_port:127.0.0.1" "https://$host:$https_port/health" >/dev/null; then
        proxy_die 'HTTPS proxy health check failed; inspect nginx logs / SELinux before retrying'
    fi
    # Firewall changes require explicit confirmation when run interactively. The
    # installer also defers firewall decisions to this step after proxy works.
    if [[ "${AWG31_PROXY_SKIP_FIREWALL_PROMPT:-no}" != yes ]]; then proxy_firewall_offer "$https_port"; fi
    proxy_log "Nginx configured: https://$host:$https_port -> http://127.0.0.1:$panel_port"
    if [[ "$mode" == self-signed ]]; then
        proxy_log 'Self-signed certificate: browser WILL warn until it is explicitly trusted; replace for production.'
    fi
    trap - EXIT
}
# Allow tests to import pure validation/rendering functions without side effects.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then proxy_main "$@"; fi
