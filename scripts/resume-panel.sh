#!/usr/bin/env bash
# Finish an installation stopped by the unsupported sudoers requiretty line
# in v0.1.2-test. Never regenerate keys, clients, DB or the awg0 interface.
set -Eeuo pipefail
umask 077
say() { printf '[AWG31 recovery] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Запустите от root: bash scripts/resume-panel.sh'
[[ -f /etc/amnezia/amneziawg/awg0.conf ]] || die 'Нет /etc/amnezia/amneziawg/awg0.conf; не является частичной установкой'
[[ -f /var/lib/awg31-panel/state.sqlite3 ]] || die 'Нет базы клиентов; восстановление не подходит'
[[ -f /etc/awg31-panel/auth.json ]] || die 'Нет auth.json; сначала завершите настройку пароля'
[[ -x /usr/local/sbin/awg31ctl ]] || die 'Не найден установленный контроллер'
[[ -x /usr/local/sbin/awg31mgr ]] || die 'Для v0.2 установите менеджер через scripts/upgrade-core.sh' 
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
SUDOERS_TMP="$(mktemp /etc/sudoers.d/.awg31-panel.XXXXXX)"
trap 'rm -f -- "${SUDOERS_TMP:-}"' EXIT
cat >"$SUDOERS_TMP" <<'TXT'
awgpanel ALL=(root) NOPASSWD: /usr/local/sbin/awg31mgr servers, /usr/local/sbin/awg31mgr server-create, /usr/local/sbin/awg31mgr server-start, /usr/local/sbin/awg31mgr server-stop, /usr/local/sbin/awg31mgr server-delete, /usr/local/sbin/awg31mgr status, /usr/local/sbin/awg31mgr list, /usr/local/sbin/awg31mgr add, /usr/local/sbin/awg31mgr download, /usr/local/sbin/awg31mgr enable, /usr/local/sbin/awg31mgr disable, /usr/local/sbin/awg31mgr delete, /usr/local/sbin/awg31mgr settings
TXT
chmod 440 "$SUDOERS_TMP"
visudo -cf "$SUDOERS_TMP"
install -o root -g root -m 440 "$SUDOERS_TMP" /etc/sudoers.d/awg31-panel
rm -f -- "$SUDOERS_TMP"
trap - EXIT
visudo -cf /etc/sudoers.d/awg31-panel
visudo -c

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
systemctl daemon-reload
systemctl enable --now awg31-panel.service
if ! systemctl is-active --quiet awg31-panel.service; then
  journalctl -u awg31-panel.service -n 40 --no-pager || true
  die 'Панель не запустилась'
fi
if ! curl --noproxy '*' -4fsS --max-time 5 "http://127.0.0.1:$PANEL_PORT/health"; then
  journalctl -u awg31-panel.service -n 40 --no-pager || true
  die 'Панель не ответила на /health'
fi
printf '\n'
say "Готово. Панель: 127.0.0.1:$PANEL_PORT (используйте Nginx HTTPS)"
say 'Конфигурация awg0, ключи и клиенты не изменялись'
