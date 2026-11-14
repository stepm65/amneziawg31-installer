#!/usr/bin/env bash
# Finish an installation that stopped after the VPN was created but before the
# panel service existed. Never regenerate keys, clients, DB or the awg0 interface.
set -Eeuo pipefail
umask 077
say() { printf '[AWG31 recovery] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Запустите от root: bash scripts/resume-panel.sh'
[[ -f /etc/amnezia/amneziawg/awg0.conf ]] || die 'Нет /etc/amnezia/amneziawg/awg0.conf; не является частичной установкой'
[[ -f /var/lib/awg31-panel/state.sqlite3 ]] || die 'Нет базы клиентов; восстановление не подходит'
[[ -f /etc/awg31-panel/auth.json ]] || die 'Нет auth.json; сначала завершите настройку пароля'
[[ -x /usr/local/sbin/awg31ctl ]] || die 'Не найден установленный контроллер'
[[ -x /usr/local/sbin/awg31mgr ]] || die 'Не найден awg31mgr: установите менеджер через scripts/upgrade-core.sh'
[[ -x /opt/awg31-panel/.venv/bin/uvicorn && -f /opt/awg31-panel/web.py ]] || die 'Нет установленной веб-панели'
id awgpanel >/dev/null 2>&1 || die 'Нет системного пользователя awgpanel'
awg show awg0 >/dev/null || die 'awg0 не работает: сперва проверьте systemctl status awg-quick@awg0'

if [[ -e /etc/systemd/system/awg31-panel.service ]]; then
  die 'awg31-panel.service уже есть; не будем его перезаписывать'
fi
PANEL_PORT="${PANEL_PORT:-}"
if [[ -z "$PANEL_PORT" ]]; then
  read -r -p 'TCP-порт панели, выбранный при установке [8080]: ' PANEL_PORT
  PANEL_PORT="${PANEL_PORT:-8080}"
fi
[[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || die 'TCP-порт должен быть числом'
(( 10#$PANEL_PORT >= 1 && 10#$PANEL_PORT <= 65535 )) || die 'TCP-порт вне диапазона 1…65535'
if ss -H -ltn "sport = :$PANEL_PORT" | grep -q .; then
  die 'Порт панели уже занят другим процессом'
fi

say 'Проверяем минимальные права sudo'
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/sudoers.sh"
awg31_install_sudoers /etc/sudoers.d/awg31-panel || die 'Не удалось установить sudoers для панели'

say 'Проверяем доступ панели к контроллеру'
runuser -u awgpanel -- sudo -n /usr/local/sbin/awg31mgr status >/dev/null 

say 'Проверяем права файла авторизации'
chown root:awgpanel /etc/awg31-panel/auth.json
chmod 640 /etc/awg31-panel/auth.json
chown root:awgpanel /etc/awg31-panel
chmod 750 /etc/awg31-panel

say 'Создаём службу веб-панели (только 127.0.0.1)'
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
chmod 644 /etc/systemd/system/awg31-panel.service
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/os-support.sh"
awg31_unit_compat /etc/systemd/system/awg31-panel.service
systemctl daemon-reload
systemctl enable awg31-panel.service
systemctl restart awg31-panel.service
awg31_wait_panel "$PANEL_PORT" || die 'Панель не ответила на /health'
printf '\n'
say "Готово. Панель: 127.0.0.1:$PANEL_PORT (используйте Nginx HTTPS)"
say 'Конфигурация awg0, ключи и клиенты не изменялись'
