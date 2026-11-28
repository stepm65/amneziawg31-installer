#!/usr/bin/env bash
# Interactive setup wizard for Ubuntu 24.04/26.04 and Rocky Linux 9/10.
# Started by install.sh after the kernel module and tools are ready.
set -Eeuo pipefail
umask 077
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
UI=text                      # whiptail when there is a terminal and whiptail (see below)
on_error() {
    if [[ "$UI" == whiptail ]] && declare -F ui_failed >/dev/null && [[ -n "${WIZ_GAUGE_PID:-}" ]]; then ui_failed; fi
    echo "[ERROR] installation failed at line $1; see output above" >&2
}
trap 'on_error $LINENO' ERR

say() { printf '\n[%s] %s\n' 'AWG31' "$*"; }
die() {
    if [[ "$UI" == whiptail && -n "${WIZ_GAUGE_PID:-}" ]]; then ui_failed; fi
    echo "[ERROR] $*" >&2; exit 1
}
# step PERCENT KEY TEXT: a progress bar step with whiptail, a heading otherwise.
step() { if [[ "$UI" == whiptail ]]; then ui_progress "$1" "$2"; else say "$3"; fi; }
UNATTENDED="${AWG31_UNATTENDED:-0}"
# Interactive: ask, Enter accepts the default. Unattended: AWG31_<NAME> or the default.
ask() {
    local key="$1" text="$2" default="$3" preset="AWG31_$1" answer
    if [[ "$UNATTENDED" == 1 ]]; then
        answer="${!preset:-$default}"
        printf '%s: %s\n' "$text" "$answer"
    else
        read -r -p "$text [$default]: " answer
    fi
    printf -v "$key" '%s' "${answer:-$default}"
}
# Yes/no question. Unattended runs answer yes. "yes_default" makes Enter mean yes.
confirm() {
    local reply
    if [[ "$UNATTENDED" == 1 ]]; then return 0; fi
    # With screens every question is asked before the installation starts.
    if [[ "$UI" == whiptail ]]; then return 0; fi
    read -r -p "$1 " reply
    if [[ -z "$reply" && "${2:-}" == yes_default ]]; then return 0; fi
    [[ "${reply,,}" == y || "${reply,,}" == yes || "$reply" == 'д' || "$reply" == 'да' ]]
}

[[ $EUID -eq 0 ]] || die 'Запустите установку от root: bash install.sh'
[[ -f "$DIR/src/awg31ctl" && -f "$DIR/src/web.py" ]] || die 'Мастер запускается через install.sh из полного каталога проекта'
source "$DIR/scripts/os-support.sh"
awg31_detect_os
case "$(uname -m)" in x86_64|aarch64) ;; *) die 'Поддерживаются x86_64 и aarch64';; esac
[[ -e /etc/amnezia/amneziawg/awg0.conf || -e /var/lib/awg31-panel/state.sqlite3 ]] && die 'Найдены существующие настройки awg0, перезапись запрещена'
if ip link show awg0 >/dev/null 2>&1; then die 'Интерфейс awg0 уже существует'; fi
if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
    say "IPv6 kernel switch: $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6). IPv6 не включаем и не настраиваем."
else
    say 'IPv6 в ядре не обнаружен — это допустимо.'
fi

say 'Мастер установки AmneziaWG 3.1 · только модуль ядра · IPv4 only · без Docker'
DEFAULT_UPLINK="$(ip -4 route show default | awk '/default/ {print $5; exit}')"
DEFAULT_IP="$(curl -4fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
if [[ -z "$DEFAULT_IP" ]]; then
    DEFAULT_IP="$(ip -4 -o addr show dev "${DEFAULT_UPLINK:-lo}" scope global | awk 'NR==1 {split($4,a,"/"); print a[1]}')"
    say 'Публичный IPv4 не определён. Для локального теста будет предложен адрес интерфейса; для доступа из интернета укажите внешний IP/DNS и настройте проброс UDP.'
fi
# Screens (whiptail) when someone is at a terminal; plain questions with AWG31_UI=text or without whiptail.
if [[ "$UNATTENDED" != 1 && "${AWG31_UI:-auto}" != text && -t 0 && -t 1 && "${TERM:-dumb}" != dumb ]]; then
    if ! command -v whiptail >/dev/null 2>&1 && [[ "$AWG31_OS_FAMILY" == rpm ]]; then
        dnf -q -y install newt >/dev/null 2>&1 || :          # whiptail lives in newt on Rocky
    fi
    if command -v whiptail >/dev/null 2>&1; then
        UI=whiptail
        source "$DIR/scripts/wizard-ui.sh"
    fi
fi
# Random subnet: every installation gets its own 10.x.y.0/24 instead of the same 10.77.10.0/24.
RANDOM_SUBNET="${AWG31_RANDOM_SUBNET:-0}"
if [[ "$UI" == whiptail ]]; then
    SUBNET='10.77.10.0/24' PORT=51820 MTU=1280 ENDPOINT="$DEFAULT_IP" ENDPOINT_DOMAIN="${AWG31_ENDPOINT_DOMAIN:-}" DNS=1.1.1.1 MODE=full UPLINK="${DEFAULT_UPLINK:-eth0}"
    PANEL_PORT=8080 FIRST_CLIENT=test-client NGINX_MODE=none NGINX_HOST='' NGINX_HTTPS_PORT=443 NGINX_CERT='' NGINX_KEY=''
    WIZ_PASSWORD='' WIZ_FIREWALL='' AWG31_OPEN_FIREWALL="${AWG31_OPEN_FIREWALL:-yes}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then WIZ_FIREWALL=ufw
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then WIZ_FIREWALL=firewalld; fi
elif [[ "$UNATTENDED" != 1 ]]; then
    read -r -p 'Случайная VPN-подсеть 10.x.y.0/24 вместо 10.77.10.0/24? [y/N]: ' reply
    case "${reply,,}" in y|yes|д|да) RANDOM_SUBNET=1 ;; *) RANDOM_SUBNET=0 ;; esac
fi
if [[ "$UI" != whiptail ]]; then
SUBNET_DEFAULT='10.77.10.0/24'
[[ "$RANDOM_SUBNET" == 1 ]] && SUBNET_DEFAULT="$(awg31_random_subnet)"
ask SUBNET 'VPN-подсеть (CIDR, /24…/29)' "$SUBNET_DEFAULT"
ask PORT 'UDP-порт AmneziaWG' '51820'
ask MTU 'MTU туннеля (576…1420)' '1280'
ask ENDPOINT 'Публичный IPv4 сервера (или DNS-имя), без порта' "$DEFAULT_IP"
ask ENDPOINT_DOMAIN 'Домен для конфигураций клиентов вместо IP, например vpn.example.com (необязательно; Enter — IP)' ''
ask DNS 'DNS клиентов (IPv4; без локального DNS по умолчанию)' '1.1.1.1'
ask MODE 'Трафик клиента: full (весь IPv4 через VPN; рекомендуется) или split (только VPN-подсеть)' 'full'
ask UPLINK 'Внешний интерфейс для выхода клиентов в интернет (NAT в режиме full)' "${DEFAULT_UPLINK:-eth0}"
ask PANEL_PORT 'TCP-порт localhost для веб-панели' '8080'
ask FIRST_CLIENT 'Имя первого клиента (skip = не создавать)' 'test-client'
[[ "$FIRST_CLIENT" == 'skip' ]] && FIRST_CLIENT='' || true
fi
# Plain ASCII digits only. Python's int() also accepts '8_080', '+8080' and
# full-width digits, which would pass validation and then break systemd/curl
# after the VPN has already been created.
need_number() {  # name value min max
    [[ "$2" =~ ^[0-9]{1,5}$ ]] && ((10#$2 >= $3 && 10#$2 <= $4)) || die "$1: нужно целое число $3…$4 (только цифры), получено '$2'"
}
if [[ "$UI" != whiptail ]]; then
need_number 'UDP-порт AmneziaWG' "$PORT" 1 65535
need_number 'MTU туннеля' "$MTU" 576 1420
need_number 'TCP-порт веб-панели' "$PANEL_PORT" 1 65535
PORT=$((10#$PORT)); MTU=$((10#$MTU)); PANEL_PORT=$((10#$PANEL_PORT))

say 'HTTPS reverse proxy — по желанию (веб-панель всегда слушает только localhost)'
echo '  0) Без Nginx / reverse proxy (можно настроить позднее)'
echo '  1) Nginx + новый самоподписанный сертификат (браузер предупредит о недоверенном CA)'
echo '  2) Nginx + существующий сертификат и приватный ключ PEM'
ask NGINX_CHOICE 'Выберите вариант 0/1/2' '0'
case "$NGINX_CHOICE" in
    0) NGINX_MODE=none ;;
    1) NGINX_MODE=self-signed ;;
    2) NGINX_MODE=existing ;;
    *) die 'Нужно выбрать 0, 1 или 2' ;;
esac
NGINX_HOST='' NGINX_HTTPS_PORT=443 NGINX_CERT='' NGINX_KEY=''
fi
# Pure validation; aborts before apt installation or writing any system files.
validate_values() {
export AWG31_SUBNET="$SUBNET" AWG31_PORT="$PORT" AWG31_MTU="$MTU" AWG31_ENDPOINT="$ENDPOINT" AWG31_ENDPOINT_DOMAIN="$ENDPOINT_DOMAIN" AWG31_DNS="$DNS" AWG31_MODE="$MODE" AWG31_UPLINK="$UPLINK" AWG31_PANEL_PORT="$PANEL_PORT" AWG31_FIRST_CLIENT="$FIRST_CLIENT"
python3 - "$DIR/src" <<'PY'
import importlib.util,ipaddress,json,os,pathlib,subprocess,sys
from importlib.machinery import SourceFileLoader
loader=SourceFileLoader('awg31ctl',str(pathlib.Path(sys.argv[1])/'awg31ctl'))
m=importlib.util.module_from_spec(importlib.util.spec_from_loader('awg31ctl',loader));loader.exec_module(m)
d={k:os.environ[f'AWG31_{k.upper()}'] for k in ('subnet','port','mtu','endpoint','endpoint_domain','dns','mode','uplink')}
setting=m.validate_settings(d,initial=True)
port=int(os.environ['AWG31_PANEL_PORT'])
assert 1<=port<=65535 and port!=setting['port'], 'Порт веб-панели некорректен или совпадает с UDP VPN'
name=os.environ['AWG31_FIRST_CLIENT']
assert not name or m.NAME_RE.fullmatch(name), 'Неверное имя первого клиента'
net=ipaddress.ip_network(d['subnet'])
for line in subprocess.run(['ip','-4','-o','addr','show'],capture_output=True,text=True,check=True).stdout.splitlines():
    fields=line.split()
    if 'inet' in fields:
        current=ipaddress.ip_interface(fields[fields.index('inet')+1]).network
        if current.overlaps(net): raise ValueError(f'VPN-подсеть пересекается с адресами сервера: {current}')
for line in subprocess.run(['ip','-4','route','show'],capture_output=True,text=True,check=True).stdout.splitlines():
    target=line.split()[0]
    try: route=ipaddress.ip_network(target,strict=False)
    except ValueError: continue
    if route.prefixlen and route.overlaps(net): raise ValueError(f'VPN-подсеть пересекается с маршрутом: {route}')
if setting['mode']=='full':
    subprocess.run(['ip','link','show',setting['uplink']],check=True,capture_output=True)
print('Параметры проверены: ',json.dumps(setting,ensure_ascii=False))
PY
}
# A domain that does not lead to this server is a warning, not an error: the A record may come later.
domain_warning() {
    [[ -n "${ENDPOINT_DOMAIN:-}" ]] || return 0
    AWG31_ENDPOINT="$ENDPOINT" AWG31_ENDPOINT_DOMAIN="$ENDPOINT_DOMAIN" python3 - "$DIR/src" <<'PY' || :
import importlib.util,os,pathlib,sys
from importlib.machinery import SourceFileLoader
loader=SourceFileLoader('awg31ctl_dns',str(pathlib.Path(sys.argv[1])/'awg31ctl'))
m=importlib.util.module_from_spec(importlib.util.spec_from_loader('awg31ctl_dns',loader));loader.exec_module(m)
endpoint,domain=os.environ['AWG31_ENDPOINT'],os.environ['AWG31_ENDPOINT_DOMAIN'].lower()
state=m.domain_check({'endpoint':endpoint,'endpoint_domain':domain,'use_domain':'on'})
if state=='unresolved': print(f'Домен {domain} сейчас не находится в DNS: клиенты не подключатся, пока у него нет A-записи на {endpoint}.')
elif state=='mismatch': print(f'Домен {domain} указывает не на {endpoint}: клиенты будут подключаться туда, куда он указывает. Проверьте A-запись.')
PY
}
# Checks of everything chosen, before any package or file changes. The screens run them
# in a subshell when Install is pressed and show what is wrong; plain questions stop here.
check_nginx() {
    source "$DIR/scripts/setup-nginx.sh"
    proxy_validate_host "$NGINX_HOST"
    proxy_validate_port "$NGINX_HTTPS_PORT"
    [[ "$NGINX_HTTPS_PORT" != "$PANEL_PORT" ]] || die 'Порт Nginx совпадает с портом панели'
    if [[ "$NGINX_MODE" == existing ]]; then
        [[ -r "$NGINX_CERT" && -r "$NGINX_KEY" ]] || die 'Сертификат или ключ отсутствуют / недоступны'
    fi
    if [[ "$(getenforce 2>/dev/null || :)" == Enforcing && "$AWG31_OS_FAMILY" == rpm ]]; then
        [[ "$NGINX_HTTPS_PORT" == 443 ]] || die 'Для Rocky с SELinux Enforcing пока поддерживается HTTPS-порт 443'
    fi
}
wizard_check() {
    need_number 'UDP-порт AmneziaWG' "$PORT" 1 65535
    need_number 'MTU туннеля' "$MTU" 576 1420
    need_number 'TCP-порт веб-панели' "$PANEL_PORT" 1 65535
    [[ -z "$FIRST_CLIENT" || "$FIRST_CLIENT" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ ]] || die 'Имя первого клиента: латиница, цифры, - и _, до 32 символов'
    [[ "$NGINX_MODE" == none ]] || check_nginx
    validate_values
    if ss -H -ltn "sport = :$((10#$PANEL_PORT))" | grep -q .; then die 'TCP-порт панели уже занят'; fi
    if ss -H -lun "sport = :$((10#$PORT))" | grep -q .; then die 'UDP-порт VPN уже занят'; fi
}
if [[ "$UI" == whiptail ]]; then
    ui_language
    ui_welcome
    ui_configure
    PORT=$((10#$PORT)); MTU=$((10#$MTU)); PANEL_PORT=$((10#$PANEL_PORT)); NGINX_HTTPS_PORT=$((10#$NGINX_HTTPS_PORT))
    warning="$(domain_warning)"
    if [[ -n "$warning" ]]; then
        ui_yesno "$(ui_t domain_warn_title)" "$warning"$'\n\n'"$([[ "$WIZ_LANG" == en ]] && echo 'Continue anyway?' || echo 'Всё равно продолжить?')" ||
            die 'Установка отменена: исправьте A-запись домена или уберите домен'
    fi
    if [[ "$NGINX_MODE" != none && "$(getenforce 2>/dev/null || :)" == Enforcing && "$AWG31_OS_FAMILY" == rpm ]]; then
        ui_yesno 'SELinux' "$(ui_t selinux_text)" || die 'Выбор отменён: без разрешения SELinux Nginx proxy не заработает'
        NGINX_SELINUX_ACK=yes
    fi
    if [[ "$AWG31_OS_FAMILY" == rpm && "$MODE" == full ]] && systemctl is-active --quiet firewalld 2>/dev/null; then
        ui_yesno 'firewalld' "$(ui_t firewalld_text)" || die 'Отменено. Правила firewalld не изменены.'
    fi
    export AWG31_OPEN_FIREWALL
elif [[ "$NGINX_MODE" != none ]]; then
    ask NGINX_HOST 'Домен или IPv4 для HTTPS Nginx (без схемы и порта)' "${ENDPOINT_DOMAIN:-$ENDPOINT}"
    ask NGINX_HTTPS_PORT 'Публичный HTTPS TCP-порт' '443'
    if [[ "$NGINX_MODE" == existing ]]; then
        ask NGINX_CERT 'Абсолютный путь к PEM сертификату (fullchain)' '/etc/letsencrypt/live/vpn.example.net/fullchain.pem'
        ask NGINX_KEY 'Абсолютный путь к PEM приватному ключу' '/etc/letsencrypt/live/vpn.example.net/privkey.pem'
    fi
    # Pre-check input before the first package installation. A second check is
    # done by setup-nginx.sh immediately before Nginx is changed.
    source "$DIR/scripts/setup-nginx.sh"
    proxy_validate_host "$NGINX_HOST"
    proxy_validate_port "$NGINX_HTTPS_PORT"
    [[ "$NGINX_HTTPS_PORT" != "$PANEL_PORT" ]] || die 'Порт Nginx совпадает с портом панели'
    if [[ "$NGINX_MODE" == existing ]]; then
        [[ -r "$NGINX_CERT" && -r "$NGINX_KEY" ]] || die 'Сертификат или ключ отсутствуют / недоступны'
    fi
    if [[ "$(getenforce 2>/dev/null || :)" == Enforcing ]] && [[ "$AWG31_OS_FAMILY" == rpm ]]; then
        [[ "$NGINX_HTTPS_PORT" == 443 ]] || die 'Для Rocky с SELinux Enforcing пока поддерживается HTTPS-порт 443'
        echo 'Rocky SELinux: Nginx потребуется право httpd_can_network_connect для reverse proxy.'
        confirm 'Разрешить установщику включить SELinux boolean (без отключения SELinux)? [y/N]:' || die 'Выбор отменён: без разрешения SELinux Nginx proxy не заработает'
        NGINX_SELINUX_ACK=yes
    fi
fi

validate_values
if [[ "$UI" != whiptail ]]; then
    warning="$(domain_warning)"
    if [[ -n "$warning" ]]; then say "ВНИМАНИЕ: $warning"; fi
fi

if [[ "$AWG31_OS_FAMILY" == rpm ]] && systemctl is-active --quiet firewalld 2>/dev/null; then
    say 'ВНИМАНИЕ: Rocky Linux использует firewalld. Для Full Tunnel может понадобиться отдельная настройка policy/masquerading; наши правила iptables не гарантируют обход политики firewalld.'
    if [[ "$MODE" == 'full' ]]; then
        confirm 'Продолжить установку с firewalld (после установки проверить NAT)? [y/N]:' || die 'Отменено. Правила firewalld не изменены.'
    fi
fi
if ss -H -ltn "sport = :$PANEL_PORT" | grep -q .; then die 'TCP-порт панели уже занят'; fi
if ss -H -lun "sport = :$PORT" | grep -q .; then die 'UDP-порт VPN уже занят'; fi
say 'Проверка завершена. AWG 3.1 устанавливается Quick Start отдельно (prepare-awg31.sh). PPA и Docker не требуются.'
confirm 'Подтверждаете установку? [y/N]:' || die 'Установка отменена'

if [[ "$UI" == whiptail ]]; then ui_progress_start; fi
step 5 deps 'Проверяем зависимости для выбранной системы'
awg31_install_packages
step 25 module 'Проверяем заранее установленный модуль и инструменты AmneziaWG 3.1'
command -v dkms >/dev/null || die 'Отсутствует DKMS'
command -v awg >/dev/null || die 'Отсутствует awg (требуется amneziawg-tools 3.1)'
command -v awg-quick >/dev/null || die 'Отсутствует awg-quick (требуется amneziawg-tools 3.1)'
modprobe amneziawg || die 'Не удалось загрузить amneziawg. Проверьте DKMS, Secure Boot и зарегистрированный MOK.'
MODVER="$(cat /sys/module/amneziawg/version 2>/dev/null || modinfo -F version amneziawg || true)"
TOOLSVER="$(awg --version 2>/dev/null || true)"
printf 'Kernel module: %s\nTools: %s\n' "$MODVER" "$TOOLSVER"
[[ "$MODVER" =~ ^3\.1\. ]] || die 'Требуется загруженный модуль AmneziaWG 3.1; устанавливать 2.0 не будем'
[[ "$TOOLSVER" =~ v3\.1\. ]] || die 'Требуются утилиты AmneziaWG 3.1; устанавливать 2.0 не будем'
if ! dkms status -m amneziawg | grep -Fq "$(uname -r)"; then
    die 'DKMS для текущего ядра не найден: проверьте dkms status'
fi
if ! systemctl list-unit-files 'awg-quick@.service' --no-legend | grep -q 'awg-quick@'; then
    die 'Отсутствует systemd unit awg-quick@.service'
fi

step 32 files 'Настройка файлов и контроллера'
install -d -o root -g root -m 700 /etc/awg31-panel /var/lib/awg31-panel /etc/amnezia/amneziawg
install -d -o root -g root -m 755 /opt/awg31-panel
install -o root -g root -m 755 "$DIR/src/awg31ctl" /usr/local/sbin/awg31ctl
install -o root -g root -m 755 "$DIR/src/awg31mgr" /usr/local/sbin/awg31mgr
install -o root -g root -m 644 "$DIR/src/awg31admin.py" /usr/local/sbin/awg31admin.py
install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
install -o root -g root -m 755 "$DIR/src/awg31bot.py" /usr/local/libexec/awg31/telegram-probe.py
install -o root -g root -m 755 "$DIR/scripts/restore-backup.py" /usr/local/libexec/awg31/scripts/restore-backup.py
install -o root -g root -m 755 "$DIR/scripts/awg31-snapshot.py" /usr/local/libexec/awg31/scripts/awg31-snapshot.py
install -o root -g root -m 755 "$DIR/scripts/update-run.sh" /usr/local/libexec/awg31/scripts/update-run.sh
install -o root -g root -m 644 "$DIR/src/web.py" /opt/awg31-panel/web.py
install -o root -g root -m 644 "$DIR/src/awg31client.py" /opt/awg31-panel/awg31client.py
install -o root -g root -m 644 "$DIR/src/amnezialink.py" /opt/awg31-panel/amnezialink.py
install -o root -g root -m 644 "$DIR/src/quicinitial.py" /opt/awg31-panel/quicinitial.py
install -o root -g root -m 644 "$DIR/src/awg31import.py" /opt/awg31-panel/awg31import.py
install -o root -g root -m 644 "$DIR/src/awg31bot.py" /opt/awg31-panel/awg31bot.py
install -o root -g root -m 644 "$DIR/src/panel.css" /opt/awg31-panel/panel.css
install -o root -g root -m 644 "$DIR/src/md3.css" /opt/awg31-panel/md3.css
install -o root -g root -m 644 "$DIR/src/panel.js" /opt/awg31-panel/panel.js
install -d -o root -g root -m 755 /opt/awg31-panel/fonts
install -o root -g root -m 644 "$DIR"/src/fonts/* /opt/awg31-panel/fonts/
install -o root -g root -m 644 "$DIR/src/requirements.txt" /opt/awg31-panel/requirements.txt
install -o root -g root -m 644 "$DIR/VERSION" /opt/awg31-panel/VERSION

step 38 venv 'Настройка Python-окружения'
python3 -m venv /opt/awg31-panel/.venv
/opt/awg31-panel/.venv/bin/pip install --disable-pip-version-check -r /opt/awg31-panel/requirements.txt

# Enable IPv4 forwarding before bringing up the VPN, not after it.
# We deliberately do not reference net.ipv6.*: IPv6 can be compiled out.
if [[ "$MODE" == 'full' ]]; then
    say 'Включаем IPv4 forwarding для выхода VPN-клиентов в интернет'
    printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/96-awg31-ipv4.conf
    sysctl -p /etc/sysctl.d/96-awg31-ipv4.conf
    [[ "$(sysctl -n net.ipv4.ip_forward)" == '1' ]] || die 'IPv4 forwarding не включился'
fi

step 62 net 'Сетевые настройки ядра для VPN: rp_filter, redirects, SYN cookies'
awg31_network_sysctl

step 66 vpn 'Инициализация профиля AWG 3.1 и запуск awg0'
# Fresh random S/H/Jc values for the primary server, exactly like servers
# created later from the panel. Never ship the static WireGuard-like defaults.
python3 - <<'PY' | AWG31_GENERATE_PARAMS=1 /usr/local/sbin/awg31ctl init
import json,os
print(json.dumps({k:os.environ[f'AWG31_{k.upper()}'] for k in ('subnet','port','mtu','endpoint','endpoint_domain','dns','mode','uplink')}))
PY
# If awg-quick cannot accept a 3.1 parameter, the controller stops here.
awg show awg0 >/dev/null || die 'awg0 не отвечает после запуска'

if [[ -n "$FIRST_CLIENT" ]]; then
    printf '%s\n' "$FIRST_CLIENT" | python3 -c 'import json,sys; print(json.dumps({"name":sys.stdin.read().strip()}))' | /usr/local/sbin/awg31ctl add >/dev/null
    say "Создан первый клиент: $FIRST_CLIENT (конфигурация доступна в панели)"
fi

step 74 user 'Создание системного пользователя и администратора панели'
if ! id awgpanel >/dev/null 2>&1; then
    useradd --system --no-create-home --home /nonexistent --shell /usr/sbin/nologin awgpanel
fi
# Let awgpanel execute venv entry points without granting write privileges.
chgrp -R awgpanel /opt/awg31-panel/.venv
chmod -R g+rX /opt/awg31-panel/.venv
install -d -o root -g awgpanel -m 750 /etc/awg31-panel
PASSWORD_FILE=''
PANEL_PASSWORD=''
generate_password() {
    # 24 URL-safe characters from the OS random source (144 bits). It goes to a
    # root-only file, not to the terminal: scrollback and session logs keep text.
    PANEL_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
    PASSWORD_FILE=/root/awg31-initial-password.txt
    (umask 077; printf '%s\n' "$PANEL_PASSWORD" > "$PASSWORD_FILE")
    chmod 600 "$PASSWORD_FILE"
}
if [[ "$UI" == whiptail ]]; then
    # Chosen on the settings screen: empty means a generated one.
    if [[ -n "$WIZ_PASSWORD" ]]; then PANEL_PASSWORD="$WIZ_PASSWORD"; else generate_password; fi
    unset WIZ_PASSWORD
elif [[ "$UNATTENDED" == 1 ]]; then
    if [[ -n "${AWG31_PASSWORD_FILE:-}" ]]; then
        [[ -r "$AWG31_PASSWORD_FILE" ]] || die "AWG31_PASSWORD_FILE не читается: $AWG31_PASSWORD_FILE"
        IFS= read -r PANEL_PASSWORD < "$AWG31_PASSWORD_FILE" || :
        [[ ${#PANEL_PASSWORD} -ge 12 && ${#PANEL_PASSWORD} -le 256 ]] || die 'Пароль в AWG31_PASSWORD_FILE должен быть длиной 12–256 символов'
    else
        generate_password
    fi
else
    echo 'Пароль администратора: введите свой (минимум 12 символов) или нажмите Enter — будет создан случайный.'
    while :; do
        IFS= read -r -s -p 'Пароль администратора веб-панели: ' PANEL_PASSWORD; echo
        if [[ -z "$PANEL_PASSWORD" ]]; then generate_password; break; fi
        if [[ ${#PANEL_PASSWORD} -lt 12 ]]; then echo 'Пароль слишком короткий'; continue; fi
        if [[ ${#PANEL_PASSWORD} -gt 256 ]]; then echo 'Пароль длиннее 256 символов'; continue; fi
        IFS= read -r -s -p 'Повторите пароль: ' PANEL_PASSWORD_REPEAT; echo
        [[ "$PANEL_PASSWORD" == "$PANEL_PASSWORD_REPEAT" ]] && break
        echo 'Пароли не совпадают, попробуйте ещё раз'
    done
    unset PANEL_PASSWORD_REPEAT
fi
# Password travels over stdin, not argv or environment.
printf '%s' "$PANEL_PASSWORD" | python3 -c '
import hashlib,json,secrets,sys
salt=secrets.token_bytes(16)
password=sys.stdin.buffer.read()
cred={"salt":salt.hex(), "password_hash":hashlib.scrypt(password,salt=salt,n=2**14,r=8,p=1,dklen=32).hex(), "session_key":secrets.token_urlsafe(48)}
with open("/etc/awg31-panel/auth.json","w") as f: json.dump(cred,f)
'
unset PANEL_PASSWORD
echo 'Забытый пароль можно сбросить из консоли сервера: sudo awg31 reset-password'
chown root:awgpanel /etc/awg31-panel/auth.json
chmod 640 /etc/awg31-panel/auth.json

say 'Настройка минимального sudo-доступа для контроллера'
# Ubuntu 26.04 sudo does not recognize the legacy requiretty setting.
# Validate candidate in an ignored (dot-prefixed) file, then install.
source "$DIR/scripts/sudoers.sh"
awg31_install_sudoers /etc/sudoers.d/awg31-panel || die 'Не удалось установить sudoers для панели'

cat >/etc/systemd/system/awg31-panel.service <<EOF
[Unit]
Description=Local-only AmneziaWG 3.1 admin panel
After=network-online.target awg-quick@awg0.service
Wants=network-online.target

[Service]
Type=simple
User=awgpanel
Group=awgpanel
WorkingDirectory=/opt/awg31-panel
Environment=AWG31_COOKIE_SECURE=1
ExecStart=/opt/awg31-panel/.venv/bin/uvicorn web:app --host 127.0.0.1 --port $PANEL_PORT --no-access-log
Restart=on-failure
RestartSec=5
UMask=0077
PrivateTmp=true
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
awg31_unit_compat /etc/systemd/system/awg31-panel.service
say 'Запуск помощника контроллера (быстрый доступ панели к VPN без sudo на каждый запрос)'
awg31_install_helper "$DIR" || echo '[AWG31 WARNING] Помощник контроллера не запустился: панель работает через sudo, только медленнее' >&2
systemctl daemon-reload
systemctl enable awg31-panel.service
# restart, not start: a panel left running by an earlier attempt must pick up this unit.
systemctl restart awg31-panel.service
step 82 panel 'Ждём запуска веб-панели'
awg31_wait_panel "$PANEL_PORT" || die 'Панель не ответила на /health. VPN awg0 создан и работает; повторный запуск команды установки завершит настройку.'

step 88 timers 'Службы, расписания и меню'
# Keep optional Nginx wizard installed even if user skips it initially.
install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
install -o root -g root -m 755 "$DIR/scripts/setup-nginx.sh" /usr/local/libexec/awg31/scripts/setup-nginx.sh
install -o root -g root -m 644 "$DIR/scripts/os-support.sh" /usr/local/libexec/awg31/scripts/os-support.sh
install -o root -g root -m 755 "$DIR/scripts/awg31-menu" /usr/local/bin/awg31
install -o root -g root -m 755 "$DIR/scripts/uninstall.sh" /usr/local/libexec/awg31/scripts/uninstall.sh
install -o root -g root -m 755 "$DIR/install.sh" /usr/local/libexec/awg31/install.sh
install -o root -g root -m 755 "$DIR/scripts/setup-telegram.sh" /usr/local/libexec/awg31/scripts/setup-telegram.sh
install -o root -g root -m 755 "$DIR/src/awg31bot.py" /usr/local/libexec/awg31/telegram-probe.py
install -o root -g root -m 644 "$DIR/scripts/sudoers.sh" /usr/local/libexec/awg31/scripts/sudoers.sh
install -o root -g root -m 644 "$DIR/scripts/awg31-bot.service" /usr/local/libexec/awg31/scripts/awg31-bot.service

# Periodic usage enforcement, historical metrics and kernel health checks.
# Limit growth of root-owned audit log without exposing credentials.
if command -v logrotate >/dev/null 2>&1; then
    install -o root -g root -m 644 "$DIR/scripts/awg31-audit.logrotate" /etc/logrotate.d/awg31-panel
fi
install -o root -g root -m 755 "$DIR/scripts/kernel-check.sh" /usr/local/libexec/awg31/scripts/kernel-check.sh
for unit in awg31-sampler.service awg31-sampler.timer awg31-kernel-check.service awg31-kernel-check.timer awg31-backup.service; do
    install -o root -g root -m 644 "$DIR/scripts/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now awg31-sampler.timer awg31-kernel-check.timer

# Nginx is optional, installed last and never changes VPN or panel bindings.
# A proxy failure leaves the functional AWG server intact and can be retried
# separately using `sudo awg31 nginx`.
NGINX_RESULT=skipped
if [[ "$NGINX_MODE" != none ]]; then
    step 92 nginx 'Устанавливаем/настраиваем Nginx с HTTPS для веб-панели'
    if AWG31_PROXY_MODE="$NGINX_MODE" \
       AWG31_PROXY_HOST="$NGINX_HOST" \
       AWG31_PROXY_HTTPS_PORT="$NGINX_HTTPS_PORT" \
       AWG31_PANEL_PORT="$PANEL_PORT" \
       AWG31_PROXY_CERT="$NGINX_CERT" \
       AWG31_PROXY_KEY="$NGINX_KEY" \
       AWG31_PROXY_SELINUX_ACK="${NGINX_SELINUX_ACK:-no}" \
       AWG31_PROXY_ALLOW="${AWG31_NGINX_ALLOW:-}" \
       AWG31_PROXY_SKIP_FIREWALL_PROMPT="$([[ "$UNATTENDED" == 1 || "$UI" == whiptail ]] && echo yes || echo no)" \
       bash "$DIR/scripts/setup-nginx.sh"; then
        NGINX_RESULT=ready
    else
        NGINX_RESULT=failed
        echo '[AWG31 WARNING] VPN + панель работают, но настройка Nginx не завершена.' >&2
        echo '[AWG31 WARNING] Повтор: sudo awg31 nginx' >&2
    fi
fi
# The Telegram bot is optional: unattended installs enable it with two variables,
# everybody else runs `sudo awg31 telegram` whenever they want it.
TELEGRAM_RESULT=skipped
if [[ -n "${AWG31_TELEGRAM_TOKEN:-}" && -n "${AWG31_TELEGRAM_ADMINS:-}" ]]; then
    step 95 telegram 'Подключаем Telegram-бота'
    if bash /usr/local/libexec/awg31/scripts/setup-telegram.sh; then
        TELEGRAM_RESULT=ready
    else
        TELEGRAM_RESULT=failed
        echo '[AWG31 WARNING] VPN и панель работают, но Telegram-бот не подключён. Повтор: sudo awg31 telegram' >&2
    fi
fi
# An active host firewall silently drops the VPN port unless it is opened.
FIREWALL_NOTE="Откройте UDP $PORT в firewall провайдера и сервера."
open_vpn_port() {
    local tool="$1"
    if [[ "${AWG31_OPEN_FIREWALL:-yes}" == no ]] ||
       ! confirm "Обнаружен активный $tool. Открыть в нём UDP $PORT для VPN? [Y/n]:" yes_default; then
        FIREWALL_NOTE="ВНИМАНИЕ: $tool активен, UDP $PORT в нём НЕ открыт — VPN не заработает, пока вы не откроете порт."
        return 0
    fi
    if [[ "$tool" == ufw ]]; then
        ufw allow "$PORT/udp" >/dev/null
    else
        firewall-cmd --permanent --add-port="$PORT/udp" >/dev/null && firewall-cmd --reload >/dev/null
    fi && FIREWALL_NOTE="UDP $PORT открыт в $tool. Проверьте также firewall провайдера." ||
        FIREWALL_NOTE="ВНИМАНИЕ: не удалось открыть UDP $PORT в $tool — откройте порт вручную."
}
step 97 firewall 'Файрвол'
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    open_vpn_port ufw
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    open_vpn_port firewalld
fi

if [[ "$UI" == whiptail ]]; then
    ui_progress 100 done
    ui_progress_stop
fi
say 'Установка завершена'
LINE='────────────────────────────────────────────────────────────'
echo "$LINE"
echo "  AmneziaWG 3.1 Console $(cat "$DIR/VERSION" 2>/dev/null || :)"
echo "$LINE"
echo "  VPN:      UDP $PORT · подсеть $SUBNET · интерфейс awg0"
if [[ -n "$ENDPOINT_DOMAIN" ]]; then echo "  Домен:    $ENDPOINT_DOMAIN (в конфигурациях клиентов вместо $ENDPOINT)"; fi
echo "  Панель:   http://127.0.0.1:$PANEL_PORT (только с самого сервера)"
case "$NGINX_RESULT" in
    ready)   echo "  HTTPS:    https://$NGINX_HOST:$NGINX_HTTPS_PORT" ;;
    failed)  echo '  HTTPS:    Nginx НЕ настроен (повтор: sudo awg31 nginx); VPN и панель работают' ;;
    skipped) echo "  Доступ:   ssh -L $PANEL_PORT:127.0.0.1:$PANEL_PORT root@$ENDPOINT → http://localhost:$PANEL_PORT"
             echo '            или HTTPS через Nginx: sudo awg31 nginx' ;;
esac
case "$TELEGRAM_RESULT" in
    ready)   echo '  Telegram: бот подключён (sudo awg31 telegram status)' ;;
    failed)  echo '  Telegram: бот НЕ подключён (повтор: sudo awg31 telegram)' ;;
    skipped) echo '  Telegram: управление и уведомления через бота — sudo awg31 telegram' ;;
esac
if [[ -n "$PASSWORD_FILE" ]]; then
    echo "  Пароль:   в файле $PASSWORD_FILE (доступен только root)"
    echo "            Посмотреть: sudo cat $PASSWORD_FILE — затем удалите файл. Сменить: sudo awg31 reset-password"
else
    echo '  Пароль:   заданный вами. Сбросить: sudo awg31 reset-password'
fi
if [[ -n "$FIRST_CLIENT" ]]; then echo "  Клиент:   $FIRST_CLIENT (конфигурация и QR — в панели)"; fi
echo '  Меню:     sudo awg31'
echo "$LINE"
echo "$FIREWALL_NOTE"
if [[ "$MODE" == 'full' ]]; then
    echo 'Режим full: через VPN идёт весь IPv4 клиента. IPv6 на клиентах не туннелируется — отключите его или заблокируйте.'
else
    echo 'Режим split: через VPN проходит только внутренняя VPN-подсеть.'
fi
