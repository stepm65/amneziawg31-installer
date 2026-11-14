#!/usr/bin/env bash
# Telegram bot of AmneziaWG 3.1 Console.
#
#   sudo awg31 telegram           connect or reconfigure the bot (interactive)
#   sudo awg31 telegram status    show whether the bot runs and who may use it
#   sudo awg31 telegram test      send a test message to the administrators
#   sudo awg31 telegram off       stop the bot and delete its token
#
# Viewers (read-only), the digest and notification groups are edited in the panel:
# Maintenance -> Telegram bot.
#
# Unattended: AWG31_TELEGRAM_TOKEN and AWG31_TELEGRAM_ADMINS (numeric IDs,
# comma-separated); optional AWG31_TELEGRAM_LANG (ru|en) and
# AWG31_TELEGRAM_NOTIFY (all, none or a list of server,clients,security,backups).
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo 'Run as root: sudo awg31 telegram' >&2; exit 1; }
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP=/opt/awg31-panel
BOT="$APP/awg31bot.py"
PY="$APP/.venv/bin/python3"
CONFIG_DIR=/etc/awg31-bot
CONFIG="$CONFIG_DIR/telegram.json"
UNIT=awg31-bot.service
say(){ printf '[AWG31 Telegram] %s\n' "$*"; }
die(){ printf '[AWG31 Telegram] ОШИБКА: %s\n' "$*" >&2; exit 1; }

turn_off() {
    systemctl disable --now "$UNIT" >/dev/null 2>&1 || :
    rm -f /etc/sudoers.d/awg31-bot "$CONFIG"
    rm -rf /var/lib/awg31-bot
    say 'Бот остановлен, токен удалён с сервера. Сам бот в Telegram можно удалить через @BotFather.'
}

show_status() {
    if [[ ! -f "$CONFIG" ]]; then say 'Бот не настроен. Настройка: sudo awg31 telegram'; return 0; fi
    say "Служба: $(systemctl is-active "$UNIT" 2>/dev/null || :)"
    # The token is never printed.
    python3 - "$CONFIG" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
print('  Администраторы (Telegram ID):', ', '.join(str(x) for x in c.get('admins', [])))
print('  Наблюдатели (только просмотр):', ', '.join(str(x) for x in c.get('viewers', [])) or 'нет')
print('  Сводка:', c.get('digest', 'off'))
print('  Язык:', c.get('lang', 'ru'))
print('  Уведомления:', ', '.join(k for k, v in c.get('notify', {}).items() if v) or 'выключены')
PY
}

case "${1:-setup}" in
    off) turn_off; exit 0 ;;
    status) show_status; exit 0 ;;
    test)
        [[ -f "$CONFIG" ]] || die 'Бот не настроен'
        "$PY" "$BOT" send-test || die 'Не удалось отправить сообщение. Каждый администратор должен сначала написать боту /start.'
        say 'Тестовое сообщение отправлено'; exit 0 ;;
    setup) ;;
    *) echo 'Usage: awg31 telegram [status|test|off]' >&2; exit 2 ;;
esac

[[ -f "$BOT" && -x "$PY" ]] || die 'Панель не установлена или повреждена (нет awg31bot.py)'
[[ -f "$DIR/sudoers.sh" && -f "$DIR/awg31-bot.service" ]] || die 'Не найдены файлы установки бота'
UNATTENDED="${AWG31_UNATTENDED:-0}"
TOKEN="${AWG31_TELEGRAM_TOKEN:-}"
ADMINS="${AWG31_TELEGRAM_ADMINS:-}"
BOT_LANG="${AWG31_TELEGRAM_LANG:-}"
NOTIFY="${AWG31_TELEGRAM_NOTIFY:-}"
VIEWERS="${AWG31_TELEGRAM_VIEWERS:-}"; VIEWERS="${VIEWERS// /}"
DIGEST="${AWG31_TELEGRAM_DIGEST:-off}"
[[ -z "$VIEWERS" || "$VIEWERS" =~ ^[0-9]{3,15}(,[0-9]{3,15}){0,19}$ ]] || die 'AWG31_TELEGRAM_VIEWERS: числа через запятую'
[[ "$DIGEST" =~ ^(off|daily|weekly)$ ]] || die 'AWG31_TELEGRAM_DIGEST: off, daily или weekly'
[[ -n "$TOKEN" && -n "$ADMINS" ]] && UNATTENDED=1

if [[ "$UNATTENDED" != 1 ]]; then
    [[ -t 0 ]] || die 'Запустите из консоли сервера или задайте AWG31_TELEGRAM_TOKEN и AWG31_TELEGRAM_ADMINS'
    cat <<'INTRO'
Бот управляет клиентами и серверами из Telegram и присылает уведомления.
Он сам опрашивает Telegram: входящий порт открывать не нужно.

1. В Telegram откройте @BotFather, отправьте /newbot и получите токен.
2. Вставьте токен ниже (ввод скрыт).
INTRO
    IFS= read -r -s -p 'Токен бота: ' TOKEN; echo
fi
[[ "$TOKEN" =~ ^[0-9]{5,14}:[A-Za-z0-9_-]{30,60}$ ]] || die 'Токен не похож на токен Telegram (123456789:AA...)'

# A running bot and the helper below must not poll Telegram at the same time.
systemctl stop "$UNIT" >/dev/null 2>&1 || :
# The token goes to the helper over stdin: it never appears in a process list.
username="$(printf '%s\n' "$TOKEN" | "$PY" "$BOT" check-token)" ||
    die 'Telegram не принял токен, или api.telegram.org недоступен с этого сервера'
say "Токен принят: бот @$username"

if [[ -z "$ADMINS" ]]; then
    read -r -p 'Ваш числовой Telegram ID (Enter — определить автоматически): ' ADMINS
    if [[ -z "$ADMINS" ]]; then
        say "Откройте в Telegram @$username и отправьте ему /start. Жду до двух минут…"
        found="$(printf '%s\n' "$TOKEN" | "$PY" "$BOT" find-admin)" || die 'Сообщение не пришло. Запустите настройку ещё раз.'
        ADMINS="${found%%$'\t'*}"
        # Anybody can write to a bot: the owner confirms that this is their account.
        read -r -p "Написал: ${found#*$'\t'} (ID $ADMINS). Это вы? [y/N]: " answer
        [[ "${answer,,}" =~ ^(y|yes|д|да)$ ]] || die 'Отменено: администратор не подтверждён'
    fi
fi
ADMINS="${ADMINS// /}"
[[ "$ADMINS" =~ ^[0-9]{3,15}(,[0-9]{3,15}){0,9}$ ]] || die 'ID администраторов: числа через запятую (не больше 10)'

if [[ -z "$BOT_LANG" && "$UNATTENDED" != 1 ]]; then
    read -r -p 'Язык бота [ru/en] (ru): ' BOT_LANG
fi
BOT_LANG="${BOT_LANG:-ru}"
[[ "$BOT_LANG" == ru || "$BOT_LANG" == en ]] || die 'Язык: ru или en'

if [[ -z "$NOTIFY" && "$UNATTENDED" != 1 ]]; then
    echo 'Уведомления: server (сервер, модуль ядра, панель), clients (отключение по сроку/лимиту),'
    echo '             security (входы в панель, смена пароля), backups (резервные копии).'
    read -r -p 'Какие включить — список через запятую, all или none (all): ' NOTIFY
fi
NOTIFY="${NOTIFY:-all}"; NOTIFY="${NOTIFY// /}"
[[ "$NOTIFY" =~ ^(all|none|(server|clients|security|backups)(,(server|clients|security|backups)){0,3})$ ]] ||
    die 'Уведомления: all, none или список из server,clients,security,backups'

if ! id awgbot >/dev/null 2>&1; then
    useradd --system --no-create-home --home /nonexistent --shell /usr/sbin/nologin awgbot
fi
# The bot only needs to read the interpreter and libraries (qrcode); no secrets live there.
chmod -R o+rX "$APP/.venv"
install -d -o root -g awgbot -m 750 "$CONFIG_DIR"
candidate="$(mktemp "$CONFIG_DIR/.telegram.XXXXXX")"
trap 'rm -f -- "$candidate"' EXIT
AWG31_T="$TOKEN" AWG31_A="$ADMINS" AWG31_L="$BOT_LANG" AWG31_N="$NOTIFY" AWG31_B="${AWG31_TELEGRAM_API:-}" \
AWG31_V="$VIEWERS" AWG31_D="$DIGEST" AWG31_OLD="$CONFIG" \
python3 - "$candidate" <<'PY'
import json, os, sys
groups = ('server', 'clients', 'security', 'backups')
chosen = os.environ['AWG31_N']
enabled = set(groups) if chosen == 'all' else set() if chosen == 'none' else set(chosen.split(','))
config = {'token': os.environ['AWG31_T'], 'admins': sorted({int(x) for x in os.environ['AWG31_A'].split(',')}),
          'lang': os.environ['AWG31_L'], 'notify': {g: g in enabled for g in groups}}
# Viewers and the digest are edited in the panel: a reconnect keeps them unless variables say otherwise.
try:
    old = json.load(open(os.environ['AWG31_OLD']))
except (OSError, ValueError):
    old = {}
viewers = os.environ.get('AWG31_V', '')
config['viewers'] = sorted({int(x) for x in viewers.split(',')} - set(config['admins'])) if viewers else \
    [x for x in old.get('viewers', []) if x not in config['admins']]
config['digest'] = os.environ['AWG31_D'] if os.environ.get('AWG31_D', 'off') != 'off' else old.get('digest', 'off')
if os.environ.get('AWG31_B'):
    config['api_base'] = os.environ['AWG31_B']          # tests only
with open(sys.argv[1], 'w') as handle:
    json.dump(config, handle, indent=1)
PY
chown root:awgbot "$candidate"; chmod 640 "$candidate"
mv -f -- "$candidate" "$CONFIG"
trap - EXIT
unset TOKEN AWG31_TELEGRAM_TOKEN

. "$DIR/sudoers.sh"
awg31_install_bot_sudoers || die 'Не удалось установить правило sudo для бота'
runuser -u awgbot -- sudo -n /usr/local/sbin/awg31mgr servers </dev/null >/dev/null || die 'Правило sudo для бота не работает'
install -o root -g root -m 644 "$DIR/awg31-bot.service" "/etc/systemd/system/$UNIT"
. "$DIR/os-support.sh"
awg31_unit_compat "/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemctl enable "$UNIT" >/dev/null 2>&1
systemctl restart "$UNIT"
sleep 2
systemctl is-active --quiet "$UNIT" || die "Бот не запустился: journalctl -u $UNIT -n 30"
if "$PY" "$BOT" send-test 2>/dev/null; then
    say 'Готово: бот прислал вам сообщение. Отправьте ему /menu.'
else
    say "Бот запущен. Напишите @$username команду /start — до этого Telegram не даёт боту писать вам первым."
fi
say 'Состояние: sudo awg31 telegram status · отключить: sudo awg31 telegram off'
