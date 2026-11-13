#!/usr/bin/env bash
# AWG31 installer for Ubuntu 24.04/26.04 and Rocky Linux 9/10.
set -Eeuo pipefail
umask 077
trap 'echo "[ERROR] installation failed at line $LINENO; see output above" >&2' ERR
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\n[%s] %s\n' 'AWG31' "$*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }
ask() { local key="$1" text="$2" default="$3" answer; read -r -p "$text [$default]: " answer; printf -v "$key" '%s' "${answer:-$default}"; }

[[ $EUID -eq 0 ]] || die 'Запустите: sudo bash install.sh'
[[ -f "$DIR/src/awg31ctl" && -f "$DIR/src/web.py" ]] || die 'Запустите install.sh из полного каталога проекта'
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
ask SUBNET 'VPN-подсеть (CIDR, /24…/29)' '10.77.10.0/24'
ask PORT 'UDP-порт AmneziaWG' '51820'
ask MTU 'MTU туннеля (576…1420)' '1280'
ask ENDPOINT 'Публичный IPv4 или DNS-имя (без порта)' "$DEFAULT_IP"
ask DNS 'DNS клиентов (IPv4; без локального DNS по умолчанию)' '1.1.1.1'
ask MODE 'Трафик клиента: full (весь IPv4 через VPN; рекомендуется) или split (только VPN-подсеть)' 'full'
ask UPLINK 'Внешний интерфейс для выхода клиентов в интернет (NAT в режиме full)' "${DEFAULT_UPLINK:-eth0}"
ask PANEL_PORT 'TCP-порт localhost для веб-панели' '8080'
ask FIRST_CLIENT 'Имя первого клиента (skip = не создавать)' 'test-client'
[[ "$FIRST_CLIENT" == 'skip' ]] && FIRST_CLIENT='' || true

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
if [[ "$NGINX_MODE" != none ]]; then
    ask NGINX_HOST 'Домен или IPv4 для HTTPS Nginx (без схемы и порта)' "$ENDPOINT"
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
        read -r -p 'Разрешить установщику включить SELinux boolean (без отключения SELinux)? [y/N]: ' ACK_SELINUX
        [[ "${ACK_SELINUX,,}" == y || "${ACK_SELINUX,,}" == yes ]] || die 'Выбор отменён: без разрешения SELinux Nginx proxy не заработает'
        NGINX_SELINUX_ACK=yes
    fi
fi

# Pure validation; aborts before apt installation or writing any system files.
export AWG31_SUBNET="$SUBNET" AWG31_PORT="$PORT" AWG31_MTU="$MTU" AWG31_ENDPOINT="$ENDPOINT" AWG31_DNS="$DNS" AWG31_MODE="$MODE" AWG31_UPLINK="$UPLINK" AWG31_PANEL_PORT="$PANEL_PORT" AWG31_FIRST_CLIENT="$FIRST_CLIENT"
python3 - "$DIR/src" <<'PY'
import ipaddress,json,os,pathlib,subprocess,sys
from importlib.machinery import SourceFileLoader
m=SourceFileLoader('awg31ctl',str(pathlib.Path(sys.argv[1])/'awg31ctl')).load_module()
d={k:os.environ[f'AWG31_{k.upper()}'] for k in ('subnet','port','mtu','endpoint','dns','mode','uplink')}
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

if [[ "$AWG31_OS_FAMILY" == rpm ]] && systemctl is-active --quiet firewalld 2>/dev/null; then
    say 'ВНИМАНИЕ: Rocky Linux использует firewalld. Для Full Tunnel может понадобиться отдельная настройка policy/masquerading; наши правила iptables не гарантируют обход политики firewalld.'
    if [[ "$MODE" == 'full' ]]; then
        read -r -p 'Продолжить экспериментальную установку с firewalld (после установки проверить NAT)? [y/N]: ' FIREWALL_ACK
        [[ "${FIREWALL_ACK,,}" == y || "${FIREWALL_ACK,,}" == yes ]] || die 'Отменено. Правила firewalld не изменены.'
    fi
fi
if ss -H -ltn "sport = :$PANEL_PORT" | grep -q .; then die 'TCP-порт панели уже занят'; fi
if ss -H -lun "sport = :$PORT" | grep -q .; then die 'UDP-порт VPN уже занят'; fi
say 'Проверка завершена. AWG 3.1 устанавливается Quick Start отдельно (prepare-awg31.sh). PPA и Docker не требуются.'
read -r -p 'Подтверждаете установку? [y/N]: ' AGREE
[[ "${AGREE,,}" == y || "${AGREE,,}" == yes || "$AGREE" == 'д' ]] || die 'Установка отменена'

say 'Проверяем зависимости для выбранной системы'
awg31_install_packages
say 'Проверяем заранее установленный модуль и инструменты AmneziaWG 3.1'
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

say 'Настройка файлов и контроллера'
install -d -o root -g root -m 700 /etc/awg31-panel /var/lib/awg31-panel /etc/amnezia/amneziawg
install -d -o root -g root -m 755 /opt/awg31-panel
install -o root -g root -m 755 "$DIR/src/awg31ctl" /usr/local/sbin/awg31ctl
install -o root -g root -m 755 "$DIR/src/awg31mgr" /usr/local/sbin/awg31mgr
install -o root -g root -m 644 "$DIR/src/awg31admin.py" /usr/local/sbin/awg31admin.py
install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
install -o root -g root -m 755 "$DIR/scripts/restore-backup.py" /usr/local/libexec/awg31/scripts/restore-backup.py
install -o root -g root -m 644 "$DIR/src/web.py" /opt/awg31-panel/web.py
install -o root -g root -m 644 "$DIR/src/amnezialink.py" /opt/awg31-panel/amnezialink.py
install -o root -g root -m 644 "$DIR/src/panel.css" /opt/awg31-panel/panel.css
install -o root -g root -m 644 "$DIR/src/md3.css" /opt/awg31-panel/md3.css
install -o root -g root -m 644 "$DIR/src/panel.js" /opt/awg31-panel/panel.js
install -o root -g root -m 644 "$DIR/src/requirements.txt" /opt/awg31-panel/requirements.txt

say 'Настройка Python-окружения'
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

say 'Инициализация профиля AWG 3.1 и запуск awg0'
python3 - <<'PY' | /usr/local/sbin/awg31ctl init
import json,os
print(json.dumps({k:os.environ[f'AWG31_{k.upper()}'] for k in ('subnet','port','mtu','endpoint','dns','mode','uplink')}))
PY
# If awg-quick cannot accept a 3.1 parameter, the controller stops here.
awg show awg0 >/dev/null || die 'awg0 не отвечает после запуска'

if [[ -n "$FIRST_CLIENT" ]]; then
    printf '%s\n' "$FIRST_CLIENT" | python3 -c 'import json,sys; print(json.dumps({"name":sys.stdin.read().strip()}))' | /usr/local/sbin/awg31ctl add >/dev/null
    say "Создан первый клиент: $FIRST_CLIENT (конфигурация доступна в панели)"
fi

say 'Создание системного пользователя и администратора панели'
if ! id awgpanel >/dev/null 2>&1; then
    useradd --system --no-create-home --home /nonexistent --shell /usr/sbin/nologin awgpanel
fi
# Let awgpanel execute venv entry points without granting write privileges.
chgrp -R awgpanel /opt/awg31-panel/.venv
chmod -R g+rX /opt/awg31-panel/.venv
install -d -o root -g awgpanel -m 750 /etc/awg31-panel
while :; do
    read -r -s -p 'Пароль администратора веб-панели (минимум 12 символов): ' PANEL_PASSWORD; echo
    [[ ${#PANEL_PASSWORD} -ge 12 ]] && break
    echo 'Пароль слишком короткий'
done
# Password travels over stdin, not argv or environment.
printf '%s' "$PANEL_PASSWORD" | python3 -c '
import hashlib,json,secrets,sys
salt=secrets.token_bytes(16)
password=sys.stdin.buffer.read()
cred={"salt":salt.hex(), "password_hash":hashlib.scrypt(password,salt=salt,n=2**14,r=8,p=1,dklen=32).hex(), "session_key":secrets.token_urlsafe(48)}
with open("/etc/awg31-panel/auth.json","w") as f: json.dump(cred,f)
'
unset PANEL_PASSWORD
chown root:awgpanel /etc/awg31-panel/auth.json
chmod 640 /etc/awg31-panel/auth.json

say 'Настройка минимального sudo-доступа для контроллера'
# Ubuntu 26.04 sudo does not recognize the legacy requiretty setting.
# Validate candidate in an ignored (dot-prefixed) file, then install.
SUDOERS_TMP="$(mktemp /etc/sudoers.d/.awg31-panel.XXXXXX)"
trap 'rm -f -- "${SUDOERS_TMP:-}"' EXIT
cat >"$SUDOERS_TMP" <<'TXT'
awgpanel ALL=(root) NOPASSWD: /usr/local/sbin/awg31mgr servers, /usr/local/sbin/awg31mgr server-create, /usr/local/sbin/awg31mgr server-start, /usr/local/sbin/awg31mgr server-stop, /usr/local/sbin/awg31mgr server-delete, /usr/local/sbin/awg31mgr status, /usr/local/sbin/awg31mgr list, /usr/local/sbin/awg31mgr add, /usr/local/sbin/awg31mgr download, /usr/local/sbin/awg31mgr enable, /usr/local/sbin/awg31mgr disable, /usr/local/sbin/awg31mgr delete, /usr/local/sbin/awg31mgr settings, /usr/local/sbin/awg31mgr client-network, /usr/local/sbin/awg31mgr client-policy, /usr/local/sbin/awg31mgr history, /usr/local/sbin/awg31mgr diagnostics, /usr/local/sbin/awg31mgr profile-export, /usr/local/sbin/awg31mgr profile-import, /usr/local/sbin/awg31mgr backup-create, /usr/local/sbin/awg31mgr backup-list, /usr/local/sbin/awg31mgr backup-export, /usr/local/sbin/awg31mgr backup-check, /usr/local/sbin/awg31mgr backup-restore, /usr/local/sbin/awg31mgr audit, /usr/local/sbin/awg31mgr audit-list, /usr/local/sbin/awg31mgr password-change
TXT
chmod 440 "$SUDOERS_TMP"
visudo -cf "$SUDOERS_TMP"
install -o root -g root -m 440 "$SUDOERS_TMP" /etc/sudoers.d/awg31-panel
rm -f -- "$SUDOERS_TMP"
trap - EXIT
visudo -cf /etc/sudoers.d/awg31-panel

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
systemctl daemon-reload
systemctl enable --now awg31-panel.service
systemctl is-active --quiet awg31-panel.service || die 'Панель не запустилась; systemctl status awg31-panel'
curl --noproxy '*' -4fsS --max-time 5 "http://127.0.0.1:$PANEL_PORT/health" >/dev/null || die 'HTTP /health не отвечает'

# Keep optional Nginx wizard installed even if user skips it initially.
install -d -o root -g root -m 755 /usr/local/libexec/awg31/scripts
install -o root -g root -m 755 "$DIR/scripts/setup-nginx.sh" /usr/local/libexec/awg31/scripts/setup-nginx.sh
install -o root -g root -m 644 "$DIR/scripts/os-support.sh" /usr/local/libexec/awg31/scripts/os-support.sh
install -o root -g root -m 755 "$DIR/scripts/awg31-menu" /usr/local/bin/awg31

# Periodic usage enforcement, historical metrics and kernel health checks.
# Limit growth of root-owned audit log without exposing credentials.
if command -v logrotate >/dev/null 2>&1; then
    install -o root -g root -m 644 "$DIR/scripts/awg31-audit.logrotate" /etc/logrotate.d/awg31-panel
fi
install -o root -g root -m 755 "$DIR/scripts/kernel-check.sh" /usr/local/libexec/awg31/scripts/kernel-check.sh
for unit in awg31-sampler.service awg31-sampler.timer awg31-kernel-check.service awg31-kernel-check.timer; do
    install -o root -g root -m 644 "$DIR/scripts/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now awg31-sampler.timer awg31-kernel-check.timer

# Nginx is optional, installed last and never changes VPN or panel bindings.
# A proxy failure leaves the functional AWG server intact and can be retried
# separately using `sudo bash scripts/setup-nginx.sh --interactive`.
NGINX_RESULT=skipped
if [[ "$NGINX_MODE" != none ]]; then
    say 'Устанавливаем/настраиваем Nginx с HTTPS для веб-панели'
    if AWG31_PROXY_MODE="$NGINX_MODE" \
       AWG31_PROXY_HOST="$NGINX_HOST" \
       AWG31_PROXY_HTTPS_PORT="$NGINX_HTTPS_PORT" \
       AWG31_PANEL_PORT="$PANEL_PORT" \
       AWG31_PROXY_CERT="$NGINX_CERT" \
       AWG31_PROXY_KEY="$NGINX_KEY" \
       AWG31_PROXY_SELINUX_ACK="${NGINX_SELINUX_ACK:-no}" \
       bash "$DIR/scripts/setup-nginx.sh"; then
        NGINX_RESULT=ready
    else
        NGINX_RESULT=failed
        echo '[AWG31 WARNING] VPN + панель работают, но настройка Nginx не завершена.' >&2
        echo "[AWG31 WARNING] Повтор: sudo bash $DIR/scripts/setup-nginx.sh --interactive" >&2
    fi
fi
say 'Установка VPN и панели завершена. Проверьте sudo awg show awg0 и systemctl status awg31-panel.'
echo "Web UI: http://127.0.0.1:$PANEL_PORT (только localhost; для входа нужна HTTPS-прокси)"
case "$NGINX_RESULT" in
    ready) echo "Nginx: https://$NGINX_HOST:$NGINX_HTTPS_PORT (HTTPS)" ;;
    failed) echo 'Nginx: НАСТРОЙКА НЕ УДАЛАСЬ; VPN и веб-панель сохранены.' ;;
    skipped) echo 'Nginx: пропущен (можно настроить позднее).' ;;
esac
echo "VPN: UDP $PORT, сервер VPN ${SUBNET}, порт нужно разрешить в firewall провайдера/сервера."
if [[ "$MODE" == 'full' ]]; then
    echo 'Маршрут клиента: 0.0.0.0/0 (весь IPv4 через VPN); NAT и forwarding включены.'
    echo 'Важное замечание: IPv6-трафик на самих клиентах не туннелируется и требует отдельных мер против утечек.'
else
    echo 'Режим split: через VPN проходит только внутренняя VPN-подсеть.'
fi
echo 'Никакие дополнительные сервисы, кроме выбранного Nginx, не устанавливаются.'
