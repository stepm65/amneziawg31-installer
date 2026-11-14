#!/usr/bin/env python3
"""Telegram bot for AmneziaWG 3.1 Console.

Runs as the unprivileged user `awgbot` with long polling: no inbound port, no
webhook. Every action goes through the same root controller as the web panel
(`sudo awg31mgr <command>`), but through a narrower allowlist: the bot can
manage clients, start and stop servers and create backups. It cannot delete a
server, restore a backup, change server settings or the panel password, and it
never receives a backup archive.

Only the numeric Telegram user IDs listed in the configuration are served, and
only in a private chat. Everybody else gets no answer at all.
"""
import html
import io
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

CONFIG = Path(os.environ.get('AWG31_BOT_CONFIG', '/etc/awg31-bot/telegram.json'))
STATE = Path(os.environ.get('AWG31_BOT_STATE', '/var/lib/awg31-bot/state.json'))
MANAGER = os.environ.get('AWG31_MGR_PATH', '/usr/local/sbin/awg31mgr')
NAME_RE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}')
IFACE_RE = re.compile(r'awg(?:0|[1-9][0-9]?)')
TOKEN_RE = re.compile(r'[0-9]{5,14}:[A-Za-z0-9_-]{30,60}')
PAGE = 8
PENDING_SECONDS = 300
OWNERS_TTL = 60          # how long the list of client owners is trusted
OWNER_INTERVAL = 3       # seconds between answers to one client owner
EXPIRY_WARNING = timedelta(hours=72)

TEXT = {
    'ru': {
        'menu': '<b>AmneziaWG 3.1 Console</b>\nВыберите раздел.',
        'b_servers': '🖥 Серверы', 'b_clients': '👥 Клиенты', 'b_status': '📈 Состояние', 'b_backup': '💾 Бэкап',
        'b_help': '❓ Помощь', 'b_back': '« Назад', 'b_menu': '« Меню', 'b_add': '➕ Добавить клиента',
        'b_conf': '📄 Конфиг', 'b_qr': '🔳 QR', 'b_on': '▶️ Включить', 'b_off': '⏸ Отключить',
        'b_exp': '⏳ Срок', 'b_quota': '📊 Лимит', 'b_del': '🗑 Удалить', 'b_yes': '✅ Да', 'b_no': '✖️ Отмена',
        'b_start': '▶️ Запустить', 'b_stop': '⏹ Остановить', 'b_restart': '🔄 Перезапустить',
        'b_refresh': '🔄 Обновить', 'b_make_backup': '💾 Создать бэкап', 'b_nolimit': 'Без лимита', 'b_days': '+{n} дн.', 'b_gib': '{n} ГиБ', 'b_noexp': 'Без срока',
        'servers': '<b>Серверы</b>', 'no_servers': 'Серверов нет. Создайте сервер в веб-панели.',
        'running': 'работает', 'stopped': 'остановлен',
        'server': '<b>{iface}</b> — {state}\nПодсеть: <code>{subnet}</code>\nUDP-порт: <code>{port}</code>\nРежим: {mode}\nКлиентов: {clients}',
        'clients': '<b>Клиенты {iface}</b> — {count}', 'no_clients': 'Клиентов пока нет.',
        'client': ('<b>{name}</b> · {iface}\nСостояние: {state}\nVPN-адрес: <code>{ip}</code>\n'
                   'Трафик: ↓ {rx} · ↑ {tx}\nИспользовано: {used}{quota}\nПоследнее соединение: {seen}\nСрок: {expiry}{comment}{owner}{stale}'),
        'enabled': 'включён', 'disabled': 'отключён', 'reason_expired': ' (истёк срок)', 'reason_quota': ' (лимит трафика)',
        'never': 'не было', 'no_expiry': 'без срока', 'of_quota': ' из {quota}', 'comment': '\nКомментарий: {text}',
        'stale': '\n⚠️ Настройки изменились: клиенту нужна новая конфигурация.',
        'ask_name': 'Отправьте имя нового клиента для <b>{iface}</b>: латиница, цифры, «-», «_», до 32 символов.',
        'bad_name': 'Имя не подходит: латиница, цифры, «-», «_», первый символ — буква или цифра, до 32 символов.',
        'created': '✅ Клиент <b>{name}</b> создан на {iface}.',
        'conf_caption': 'Конфигурация {name} ({iface}). В файле приватный ключ: не пересылайте его в общие чаты.',
        'qr_caption': 'QR-код {name} ({iface}) для приложения AmneziaWG.',
        'qr_too_big': 'Конфигурация слишком велика для QR-кода (длинный I1). Используйте файл.',
        'ask_exp': 'Срок действия <b>{name}</b>. Выберите или отправьте дату в формате ДД.ММ.ГГГГ.',
        'ask_quota': 'Лимит трафика <b>{name}</b>. Выберите или отправьте число в ГиБ (0 — без лимита).',
        'bad_quota': 'Нужно число ГиБ от 0 до 100000.',
        'saved': '✅ Сохранено.', 'confirm_del': 'Удалить клиента <b>{name}</b> с {iface}? Отменить будет нельзя.',
        'confirm_stop': 'Остановить <b>{iface}</b>? Все его клиенты потеряют соединение.',
        'confirm_restart': 'Перезапустить <b>{iface}</b>? Клиенты ненадолго отключатся.',
        'deleted': '🗑 Клиент <b>{name}</b> удалён.', 'done': '✅ Готово.', 'cancelled': 'Отменено.',
        'error': '⚠️ Ошибка: {message}', 'expired_input': 'Время ожидания ввода истекло. Начните заново из меню.',
        'status': '<b>Состояние</b>', 'st_server': '{icon} <b>{iface}</b>: {state}, клиентов {clients}, на связи {online}',
        'st_module': 'Модуль ядра: {value}', 'st_panel': 'Веб-панель: {value}', 'st_kernel': 'Ядро: {value}',
        'backup': '<b>Резервные копии</b>\nАрхивов на сервере: {count}', 'backup_note': '\n\nАрхив содержит все ключи, поэтому в Telegram не отправляется: скачайте его в веб-панели.',
        'backup_last': '\nПоследний: <code>{name}</code>', 'backup_done': '✅ Бэкап создан: <code>{name}</code> ({size})',
        'help': ('<b>Что умеет бот</b>\n• клиенты: создать, выдать конфиг и QR, включить и отключить, срок, лимит, удалить\n• владелец клиента (Telegram ID) видит в боте состояние своего доступа\n'
                 '• серверы: состояние, запуск, остановка, перезапуск\n• резервная копия: создать\n• уведомления о событиях\n\n'
                 'Удаление сервера, восстановление из бэкапа, настройки сервера и пароль панели доступны только в веб-панели и консоли.\n\n'
                 'Команды: /menu /servers /clients /status /backup /help'),
        'n_down': '🔴 Сервер <b>{iface}</b> остановлен.', 'n_up': '🟢 Сервер <b>{iface}</b> снова работает.',
        'n_module_bad': '🔴 Модуль ядра AmneziaWG недоступен ({detail}). После обновления ядра запустите установщик ещё раз: он пересоберёт модуль.',
        'n_module_ok': '🟢 Модуль ядра AmneziaWG снова загружен.',
        'n_panel_bad': '🔴 Веб-панель не работает (служба awg31-panel: {detail}).', 'n_panel_ok': '🟢 Веб-панель снова работает.',
        'n_disabled': '⏸ Клиент <b>{target}</b> отключён автоматически (срок или лимит).',
        'n_expiring': '⏳ У клиента <b>{name}</b> ({iface}) срок истекает {when}.',
        'n_login': '🔐 Вход в веб-панель с адреса <code>{target}</code>.',
        'n_login_failed': '⚠️ Неудачные попытки входа в веб-панель: {count} (последний адрес <code>{target}</code>).',
        'n_password': '🔑 Пароль веб-панели изменён.',
        'b_tg': '👤 Telegram ID', 'ask_tg': 'Отправьте числовой Telegram ID владельца <b>{name}</b>. Он сможет смотреть состояние этого клиента в боте (только просмотр). 0 — убрать.',
        'bad_tg': 'Нужен числовой ID (только цифры), а не @имя. 0 — убрать.', 'owner': '\nВладелец (Telegram ID): {id}',
        'my': '<b>Ваш VPN</b>', 'my_client': ('<b>{name}</b>\nСостояние: {state}\nИспользовано: {used}{quota}\n'
                                              'Последнее соединение: {seen}\nДействует до: {expiry}'),
        'my_hint': 'По вопросам доступа обратитесь к администратору.',
        'n_user_expiring': '⏳ Срок вашего VPN-доступа <b>{name}</b> истекает {when}. Обратитесь к администратору.',
        'test': '✅ Бот AmneziaWG 3.1 Console подключён. Отправьте /menu.',
        'n_backup': '💾 Создана резервная копия <code>{target}</code>.', 'n_backup_failed': '⚠️ Резервная копия по расписанию не создана: {target}',
    },
    'en': {
        'menu': '<b>AmneziaWG 3.1 Console</b>\nChoose a section.',
        'b_servers': '🖥 Servers', 'b_clients': '👥 Clients', 'b_status': '📈 Status', 'b_backup': '💾 Backup',
        'b_help': '❓ Help', 'b_back': '« Back', 'b_menu': '« Menu', 'b_add': '➕ Add client',
        'b_conf': '📄 Config', 'b_qr': '🔳 QR', 'b_on': '▶️ Enable', 'b_off': '⏸ Disable',
        'b_exp': '⏳ Expiry', 'b_quota': '📊 Quota', 'b_del': '🗑 Delete', 'b_yes': '✅ Yes', 'b_no': '✖️ Cancel',
        'b_start': '▶️ Start', 'b_stop': '⏹ Stop', 'b_restart': '🔄 Restart',
        'b_refresh': '🔄 Refresh', 'b_make_backup': '💾 Create backup', 'b_nolimit': 'Unlimited', 'b_days': '+{n} d', 'b_gib': '{n} GiB', 'b_noexp': 'No expiry',
        'servers': '<b>Servers</b>', 'no_servers': 'No servers. Create one in the web panel.',
        'running': 'running', 'stopped': 'stopped',
        'server': '<b>{iface}</b> — {state}\nSubnet: <code>{subnet}</code>\nUDP port: <code>{port}</code>\nMode: {mode}\nClients: {clients}',
        'clients': '<b>Clients of {iface}</b> — {count}', 'no_clients': 'No clients yet.',
        'client': ('<b>{name}</b> · {iface}\nState: {state}\nVPN address: <code>{ip}</code>\n'
                   'Traffic: ↓ {rx} · ↑ {tx}\nUsed: {used}{quota}\nLast handshake: {seen}\nExpiry: {expiry}{comment}{owner}{stale}'),
        'enabled': 'enabled', 'disabled': 'disabled', 'reason_expired': ' (expired)', 'reason_quota': ' (traffic quota)',
        'never': 'never', 'no_expiry': 'none', 'of_quota': ' of {quota}', 'comment': '\nComment: {text}',
        'stale': '\n⚠️ Settings changed: this client needs a new configuration.',
        'ask_name': 'Send the name of the new client for <b>{iface}</b>: Latin letters, digits, “-”, “_”, up to 32 characters.',
        'bad_name': 'Invalid name: Latin letters, digits, “-”, “_”, starting with a letter or digit, up to 32 characters.',
        'created': '✅ Client <b>{name}</b> created on {iface}.',
        'conf_caption': 'Configuration of {name} ({iface}). The file contains a private key: do not forward it to shared chats.',
        'qr_caption': 'QR code of {name} ({iface}) for the AmneziaWG app.',
        'qr_too_big': 'The configuration is too large for a QR code (long I1). Use the file.',
        'ask_exp': 'Expiry of <b>{name}</b>. Choose, or send a date as YYYY-MM-DD.',
        'ask_quota': 'Traffic quota of <b>{name}</b>. Choose, or send a number of GiB (0 = unlimited).',
        'bad_quota': 'Send a number of GiB between 0 and 100000.',
        'saved': '✅ Saved.', 'confirm_del': 'Delete client <b>{name}</b> from {iface}? This cannot be undone.',
        'confirm_stop': 'Stop <b>{iface}</b>? All its clients lose the connection.',
        'confirm_restart': 'Restart <b>{iface}</b>? Clients disconnect for a moment.',
        'deleted': '🗑 Client <b>{name}</b> deleted.', 'done': '✅ Done.', 'cancelled': 'Cancelled.',
        'error': '⚠️ Error: {message}', 'expired_input': 'Input timed out. Start again from the menu.',
        'status': '<b>Status</b>', 'st_server': '{icon} <b>{iface}</b>: {state}, {clients} clients, {online} online',
        'st_module': 'Kernel module: {value}', 'st_panel': 'Web panel: {value}', 'st_kernel': 'Kernel: {value}',
        'backup': '<b>Backups</b>\nArchives on the server: {count}', 'backup_note': '\n\nAn archive contains every key, so it is not sent to Telegram: download it in the web panel.',
        'backup_last': '\nLatest: <code>{name}</code>', 'backup_done': '✅ Backup created: <code>{name}</code> ({size})',
        'help': ('<b>What the bot can do</b>\n• clients: create, hand out config and QR, enable and disable, expiry, quota, delete\n• a client’s owner (Telegram ID) sees the state of their access in the bot\n'
                 '• servers: status, start, stop, restart\n• backup: create\n• event notifications\n\n'
                 'Deleting a server, restoring a backup, server settings and the panel password are available only in the web panel and the console.\n\n'
                 'Commands: /menu /servers /clients /status /backup /help'),
        'n_down': '🔴 Server <b>{iface}</b> is stopped.', 'n_up': '🟢 Server <b>{iface}</b> is running again.',
        'n_module_bad': '🔴 The AmneziaWG kernel module is unavailable ({detail}). After a kernel update run the installer again: it rebuilds the module.',
        'n_module_ok': '🟢 The AmneziaWG kernel module is loaded again.',
        'n_panel_bad': '🔴 The web panel is down (service awg31-panel: {detail}).', 'n_panel_ok': '🟢 The web panel is running again.',
        'n_disabled': '⏸ Client <b>{target}</b> was disabled automatically (expiry or quota).',
        'n_expiring': '⏳ Client <b>{name}</b> ({iface}) expires {when}.',
        'n_login': '🔐 Sign-in to the web panel from <code>{target}</code>.',
        'n_login_failed': '⚠️ Failed sign-in attempts to the web panel: {count} (last address <code>{target}</code>).',
        'n_password': '🔑 The web panel password was changed.',
        'b_tg': '👤 Telegram ID', 'ask_tg': 'Send the numeric Telegram ID of the owner of <b>{name}</b>. That person can view the state of this client in the bot (read only). 0 removes it.',
        'bad_tg': 'Send a numeric ID (digits only), not a @username. 0 removes it.', 'owner': '\nOwner (Telegram ID): {id}',
        'my': '<b>Your VPN</b>', 'my_client': ('<b>{name}</b>\nState: {state}\nUsed: {used}{quota}\n'
                                               'Last handshake: {seen}\nValid until: {expiry}'),
        'my_hint': 'For access questions contact the administrator.',
        'n_user_expiring': '⏳ Your VPN access <b>{name}</b> expires {when}. Contact the administrator.',
        'test': '✅ The AmneziaWG 3.1 Console bot is connected. Send /menu.',
        'n_backup': '💾 Backup <code>{target}</code> was created.', 'n_backup_failed': '⚠️ The scheduled backup was not created: {target}',
    },
}


class BotError(Exception):
    """A message that is safe to show to the administrator."""


def log(message):
    print(message, file=sys.stderr, flush=True)


def human_size(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return '—'
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if number < 1024 or unit == 'TiB':
            return f'{number:.0f} {unit}' if unit == 'B' else f'{number:.1f} {unit}'
        number /= 1024


def ctl(command, data=None):
    """Run one allowlisted controller command as root; data travels over stdin."""
    try:
        proc = subprocess.run(['sudo', '-n', MANAGER, command], input=json.dumps(data) if data is not None else None,
                              capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BotError(type(exc).__name__) from None
    if proc.returncode:
        try:
            message = json.loads(proc.stderr).get('error', 'controller error')
        except ValueError:
            message = 'controller error (not permitted or unavailable)'
        raise BotError(str(message)[:300])
    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise BotError('unexpected controller reply') from None


class Api:
    """Minimal Telegram Bot API client on the standard library. Never logs the token."""

    def __init__(self, token, base='https://api.telegram.org'):
        if not TOKEN_RE.fullmatch(token):
            raise ValueError('Malformed bot token')
        self._root = f'{base.rstrip("/")}/bot{token}/'

    def _open(self, request, timeout):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as reply:
                body = json.load(reply)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.load(exc).get('description', '')
            except ValueError:
                detail = ''
            raise BotError(f'Telegram API {exc.code} {detail}'.strip()) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # str(exc) of these never contains the request URL, hence never the token.
            raise BotError(f'Telegram API unreachable: {type(exc).__name__}') from None
        if not body.get('ok'):
            raise BotError('Telegram API: ' + str(body.get('description', 'error'))[:200])
        return body.get('result')

    def call(self, method, http_timeout=30, **params):
        payload = json.dumps({k: v for k, v in params.items() if v is not None}).encode()
        request = urllib.request.Request(self._root + method, data=payload, headers={'Content-Type': 'application/json'})
        return self._open(request, http_timeout)

    def send_file(self, method, field, chat_id, filename, content, caption):
        boundary = 'awg31' + secrets.token_hex(16)
        parts = []
        for name, value in (('chat_id', str(chat_id)), ('caption', caption)):
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                     'Content-Type: application/octet-stream\r\n\r\n'.encode() + content + b'\r\n')
        parts.append(f'--{boundary}--\r\n'.encode())
        request = urllib.request.Request(self._root + method, data=b''.join(parts),
                                         headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
        return self._open(request, 60)


def load_config(path=CONFIG):
    data = json.loads(Path(path).read_text())
    admins = {int(item) for item in data.get('admins', [])}
    if not admins:
        raise ValueError('No administrators configured')
    lang = data.get('lang', 'ru')
    notify = {key: bool(data.get('notify', {}).get(key, True)) for key in ('server', 'clients', 'security', 'backups')}
    return {'token': str(data['token']), 'admins': admins, 'lang': lang if lang in TEXT else 'ru', 'notify': notify,
            'api_base': str(data.get('api_base') or 'https://api.telegram.org')}


def parse_expiry(text, now=None):
    """DD.MM.YYYY or YYYY-MM-DD -> ISO date; must be today or later."""
    value = text.strip()
    for pattern in ('%d.%m.%Y', '%Y-%m-%d'):
        try:
            day = datetime.strptime(value, pattern).date()
        except ValueError:
            continue
        if day < (now or datetime.now(timezone.utc)).date():
            raise ValueError('past')
        return day.isoformat()
    raise ValueError('format')


class Bot:
    def __init__(self, config, api=None, controller=ctl, state_path=STATE, clock=time.time):
        self.config = config
        self.api = api or Api(config['token'], config['api_base'])
        self.ctl = controller
        self.state_path = Path(state_path)
        self.clock = clock
        self.pending = {}            # admin id -> (kind, iface, name, deadline)
        self.own_actions = {}        # things the bot did itself: no notification about them
        self.state = self._load_state()
        self.next_tick = 0
        self.owners_map, self.owners_at = {}, None    # Telegram ID -> [(iface, client)], refreshed at most every OWNERS_TTL
        self.owner_seen = {}                          # Telegram ID -> time of the last answered request

    # ------------------------------------------------------------ helpers
    def t(self, key, **values):
        return TEXT[self.config['lang']][key].format(**{k: html.escape(str(v)) for k, v in values.items()})

    def plain(self, key, **values):
        """Unescaped text for use as a value of t(), which escapes it once."""
        return TEXT[self.config['lang']][key].format(**values)

    def _load_state(self):
        try:
            data = json.loads(self.state_path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self):
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_suffix('.tmp')
            temporary.write_text(json.dumps(self.state))
            os.replace(temporary, self.state_path)
        except OSError as exc:
            log(f'cannot save state: {exc}')

    def audit(self, event, target, admin):
        try:
            self.ctl('audit', {'event': event, 'target': f'{target} (telegram {admin})'[:120]})
        except BotError:
            pass

    def keyboard(self, rows):
        return {'inline_keyboard': [[{'text': text, 'callback_data': data} for text, data in row] for row in rows]}

    def show(self, chat, text, rows=None, message_id=None):
        markup = self.keyboard(rows) if rows else None
        if message_id:
            try:
                self.api.call('editMessageText', chat_id=chat, message_id=message_id, text=text, parse_mode='HTML',
                              reply_markup=markup, disable_web_page_preview=True)
                return
            except BotError:
                pass                 # message too old or unchanged: send a new one
        self.api.call('sendMessage', chat_id=chat, text=text, parse_mode='HTML', reply_markup=markup,
                      disable_web_page_preview=True)

    def servers(self):
        return [s for s in self.ctl('servers', {}).get('servers', []) if IFACE_RE.fullmatch(str(s.get('interface', '')))]

    def clients(self, iface):
        return self.ctl('list', {'interface': iface}).get('clients', [])

    def client(self, iface, name):
        for item in self.clients(iface):
            if item.get('name') == name:
                return item
        raise BotError('client not found')

    def default_server(self):
        servers = self.servers()
        if not servers:
            raise BotError(TEXT[self.config['lang']]['no_servers'])
        return servers[0]['interface']

    # ------------------------------------------------------------ screens
    def screen_menu(self):
        return self.t('menu'), [[(self.t('b_servers'), 's'), (self.t('b_clients'), 'cl')],
                                [(self.t('b_status'), 'st'), (self.t('b_backup'), 'bk')], [(self.t('b_help'), 'h')]]

    def screen_servers(self):
        servers = self.servers()
        if not servers:
            return self.t('no_servers'), [[(self.t('b_menu'), 'm')]]
        rows = [[(f"{'🟢' if s.get('running') else '🔴'} {s['interface']} · {s.get('clients', 0)}", f"s:{s['interface']}")] for s in servers]
        return self.t('servers'), rows + [[(self.t('b_menu'), 'm')]]

    def screen_server(self, iface):
        info = next((s for s in self.servers() if s['interface'] == iface), None)
        if info is None:
            raise BotError('server not found')
        running = bool(info.get('running'))
        text = self.t('server', iface=iface, state=self.t('running' if running else 'stopped'), subnet=info.get('subnet', ''),
                      port=info.get('port', ''), mode=info.get('mode', ''), clients=info.get('clients', 0))
        actions = ([(self.t('b_restart'), f'sa:{iface}:restart'), (self.t('b_stop'), f'sa:{iface}:stop')] if running
                   else [(self.t('b_start'), f'sa:{iface}:start')])
        return text, [[(self.t('b_clients'), f'cl:{iface}:0'), (self.t('b_add'), f'add:{iface}')], actions,
                      [(self.t('b_back'), 's')]]

    def screen_clients(self, iface, page=0):
        clients = self.clients(iface)
        pages = max(1, (len(clients) + PAGE - 1) // PAGE)
        page = min(max(page, 0), pages - 1)
        rows = [[(f"{'🟢' if c.get('enabled') else '⏸'} {c['name']}", f"c:{iface}:{c['name']}")]
                for c in clients[page * PAGE:(page + 1) * PAGE]]
        nav = []
        if page > 0: nav.append(('‹', f'cl:{iface}:{page - 1}'))
        if pages > 1: nav.append((f'{page + 1}/{pages}', f'cl:{iface}:{page}'))
        if page < pages - 1: nav.append(('›', f'cl:{iface}:{page + 1}'))
        if nav: rows.append(nav)
        rows.append([(self.t('b_add'), f'add:{iface}'), (self.t('b_back'), f's:{iface}')])
        text = self.t('clients', iface=iface, count=len(clients))
        if not clients:
            text += '\n' + self.t('no_clients')
        return text, rows

    def screen_client(self, iface, name):
        c = self.client(iface, name)
        stats = c.get('stats') or {}
        enabled = bool(c.get('enabled'))
        state = self.plain('enabled' if enabled else 'disabled')
        reason = c.get('disabled_reason')
        if not enabled and reason in ('expired', 'quota'):
            state += self.plain('reason_' + reason)
        handshake = int(stats.get('handshake') or 0)
        seen = datetime.fromtimestamp(handshake, timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if handshake else self.plain('never')
        limit = int(c.get('traffic_limit_bytes') or 0)
        text = self.t('client', name=name, iface=iface, state=state, ip=c.get('ip', ''),
                      rx=human_size(stats.get('received', 0)), tx=human_size(stats.get('sent', 0)),
                      used=human_size(c.get('used_bytes', 0)),
                      quota=self.plain('of_quota', quota=human_size(limit)) if limit else '', seen=seen,
                      expiry=(c.get('expires_at') or '')[:10] or self.plain('no_expiry'),
                      comment=self.plain('comment', text=c['comment']) if c.get('comment') else '',
                      owner=self.plain('owner', id=c['telegram_id']) if c.get('telegram_id') else '',
                      stale=self.plain('stale') if c.get('config_stale') else '')
        toggle = (self.t('b_off'), f'ca:{iface}:{name}:off') if enabled else (self.t('b_on'), f'ca:{iface}:{name}:on')
        rows = [[(self.t('b_conf'), f'ca:{iface}:{name}:conf'), (self.t('b_qr'), f'ca:{iface}:{name}:qr')],
                [toggle, (self.t('b_exp'), f'ca:{iface}:{name}:exp'), (self.t('b_quota'), f'ca:{iface}:{name}:quota')],
                [(self.t('b_tg'), f'ca:{iface}:{name}:tg'), (self.t('b_del'), f'ca:{iface}:{name}:del'),
                 (self.t('b_refresh'), f'c:{iface}:{name}')],
                [(self.t('b_back'), f'cl:{iface}:0')]]
        return text, rows

    def screen_status(self):
        lines = [self.t('status')]
        servers = self.servers()
        now = self.clock()
        for s in servers:
            iface = s['interface']
            try:
                clients = self.clients(iface)
            except BotError:
                clients = []
            online = sum(1 for c in clients if c.get('enabled') and int((c.get('stats') or {}).get('handshake') or 0) > now - 180)
            lines.append(self.t('st_server', icon='🟢' if s.get('running') else '🔴', iface=iface,
                                state=self.t('running' if s.get('running') else 'stopped'), clients=len(clients), online=online))
        if servers:
            try:
                diag = self.ctl('diagnostics', {'interface': servers[0]['interface']})
                lines.append(self.t('st_kernel', value=(diag.get('kernel') or {}).get('output', '—')))
                lines.append(self.t('st_module', value=(diag.get('loaded_module') or {}).get('output', '—')))
                lines.append(self.t('st_panel', value=(diag.get('panel') or {}).get('output', '—')))
            except BotError:
                pass
        else:
            lines.append(self.t('no_servers'))
        return '\n'.join(lines), [[(self.t('b_refresh'), 'st'), (self.t('b_menu'), 'm')]]

    def screen_backup(self):
        backups = self.ctl('backup-list', {}).get('backups', [])
        text = self.t('backup', count=len(backups))
        if backups:
            text += self.t('backup_last', name=backups[0]['name'])
        text += self.t('backup_note')
        return text, [[(self.t('b_make_backup'), 'bky')], [(self.t('b_menu'), 'm')]]

    # ------------------------------------------------------------ actions
    def send_config(self, chat, iface, name, as_qr):
        export = self.ctl('download', {'interface': iface, 'name': name, 'mark': True})
        config = export['config']
        if as_qr:
            import qrcode
            try:
                image = qrcode.make(config, error_correction=qrcode.constants.ERROR_CORRECT_L)
            except (qrcode.exceptions.DataOverflowError, ValueError):
                self.show(chat, self.t('qr_too_big'))
                return
            buffer = io.BytesIO()
            image.save(buffer, format='PNG')
            self.api.send_file('sendPhoto', 'photo', chat, f'{name}-qr.png', buffer.getvalue(),
                               TEXT[self.config['lang']]['qr_caption'].format(name=name, iface=iface))
        else:
            self.api.send_file('sendDocument', 'document', chat, f'{name}.conf', config.encode(),
                               TEXT[self.config['lang']]['conf_caption'].format(name=name, iface=iface))

    def add_client(self, chat, admin, iface, name):
        if not NAME_RE.fullmatch(name):
            self.show(chat, self.t('bad_name'))
            return False
        self.ctl('add', {'interface': iface, 'name': name})
        self.audit('client_added', f'{iface}/{name}', admin)
        self.show(chat, self.t('created', name=name, iface=iface))
        self.send_config(chat, iface, name, as_qr=False)
        self.send_config(chat, iface, name, as_qr=True)
        self.show(chat, *self.screen_client(iface, name))
        return True

    def set_policy(self, admin, iface, name, **fields):
        self.ctl('client-policy', {'interface': iface, 'name': name, **fields})
        self.audit('client_modified', f'{iface}/{name}', admin)

    # ------------------------------------------------------------ updates
    def authorized(self, user, chat):
        return bool(user) and int(user.get('id', 0)) in self.config['admins'] and (chat or {}).get('type') == 'private'

    # A client owner is somebody whose Telegram ID the administrator put on a
    # client. They get one read-only screen with their own clients and nothing else.
    def owners(self):
        now = self.clock()
        if self.owners_at is None or now - self.owners_at > OWNERS_TTL:
            found = {}
            for s in self.servers():
                for c in self.clients(s['interface']):
                    if str(c.get('telegram_id') or '').isdigit():
                        found.setdefault(int(c['telegram_id']), []).append((s['interface'], c))
            self.owners_map, self.owners_at = found, now
        return self.owners_map

    def serve_owner(self, user, chat, message_id=None, callback_id=None):
        """Answer a non-administrator; returns silently unless they own a client."""
        if not user or (chat or {}).get('type') != 'private':
            return
        try:
            user_id = int(user.get('id', 0))
            now = self.clock()
            # Strangers cost one dictionary lookup: the list is rebuilt at most once a minute.
            if user_id not in self.owners() or now - self.owner_seen.get(user_id, -OWNER_INTERVAL) < OWNER_INTERVAL:
                return
            self.owner_seen[user_id] = now
            if callback_id:
                try:
                    self.api.call('answerCallbackQuery', callback_query_id=callback_id)
                except BotError:
                    pass
            self.owners_at = None                       # a known owner gets fresh numbers
            mine = self.owners().get(user_id, [])
            if not mine:
                return
            parts = [self.t('my')]
            for _, c in mine:
                enabled = bool(c.get('enabled'))
                state = self.plain('enabled' if enabled else 'disabled')
                if not enabled and c.get('disabled_reason') in ('expired', 'quota'):
                    state += self.plain('reason_' + c['disabled_reason'])
                handshake = int((c.get('stats') or {}).get('handshake') or 0)
                limit = int(c.get('traffic_limit_bytes') or 0)
                parts.append(self.t('my_client', name=c['name'], state=state, used=human_size(c.get('used_bytes', 0)),
                                    quota=self.plain('of_quota', quota=human_size(limit)) if limit else '',
                                    seen=datetime.fromtimestamp(handshake, timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if handshake else self.plain('never'),
                                    expiry=(c.get('expires_at') or '')[:10] or self.plain('no_expiry')))
            parts.append(self.t('my_hint'))
            self.show(chat['id'], '\n\n'.join(parts), [[(self.t('b_refresh'), 'me')]], message_id)
        except BotError as exc:
            log(f'owner request failed: {exc}')

    def handle_update(self, update):
        if 'callback_query' in update:
            query = update['callback_query']
            message = query.get('message') or {}
            if not self.authorized(query.get('from'), message.get('chat')):
                self.serve_owner(query.get('from'), message.get('chat'), message.get('message_id'), query.get('id'))
                return
            try:
                self.api.call('answerCallbackQuery', callback_query_id=query['id'])
            except BotError:
                pass
            self.guarded(message['chat']['id'], lambda: self.on_callback(message['chat']['id'], int(query['from']['id']),
                                                                         str(query.get('data', '')), message.get('message_id')))
        elif 'message' in update:
            message = update['message']
            if not self.authorized(message.get('from'), message.get('chat')):
                # Strangers and group chats get no reply at all; a client owner gets their status.
                self.serve_owner(message.get('from'), message.get('chat'))
                return
            text = str(message.get('text') or '').strip()
            if text:
                self.guarded(message['chat']['id'], lambda: self.on_text(message['chat']['id'], int(message['from']['id']), text))

    def guarded(self, chat, action):
        try:
            action()
        except BotError as exc:
            try:
                self.show(chat, self.t('error', message=str(exc)))
            except BotError as failure:
                log(f'cannot report an error: {failure}')
        except Exception as exc:              # a broken handler must not stop the bot
            log(f'handler failed: {type(exc).__name__}: {exc}')
            try:
                self.show(chat, self.t('error', message=type(exc).__name__))
            except BotError:
                pass

    def on_text(self, chat, admin, text):
        if text.startswith('/'):
            self.pending.pop(admin, None)
            command = text.split()[0].split('@')[0].lower()
            argument = text.split(maxsplit=1)[1].strip() if ' ' in text else ''
            if command in ('/start', '/menu'):
                self.show(chat, *self.screen_menu())
            elif command == '/servers':
                self.show(chat, *self.screen_servers())
            elif command == '/clients':
                self.show(chat, *self.screen_clients(self.default_server(), 0))
            elif command == '/status':
                self.show(chat, *self.screen_status())
            elif command == '/backup':
                self.show(chat, *self.screen_backup())
            elif command == '/add' and argument:
                self.add_client(chat, admin, self.default_server(), argument)
            else:
                self.show(chat, self.t('help'), [[(self.t('b_menu'), 'm')]])
            return
        waiting = self.pending.get(admin)
        if not waiting:
            self.show(chat, *self.screen_menu())
            return
        kind, iface, name, deadline = waiting
        if self.clock() > deadline:
            self.pending.pop(admin, None)
            self.show(chat, self.t('expired_input'), [[(self.t('b_menu'), 'm')]])
            return
        if kind == 'add':
            if self.add_client(chat, admin, iface, text):
                self.pending.pop(admin, None)
        elif kind == 'exp':
            try:
                day = parse_expiry(text)
            except ValueError:
                self.show(chat, self.t('ask_exp', name=name))
                return
            self.pending.pop(admin, None)
            self.set_policy(admin, iface, name, expires_at=day)
            self.show(chat, *self.screen_client(iface, name))
        elif kind == 'quota':
            if not re.fullmatch(r'[0-9]{1,6}(?:[.,][0-9]{1,3})?', text) or float(text.replace(',', '.')) > 100000:
                self.show(chat, self.t('bad_quota'))
                return
            self.pending.pop(admin, None)
            self.set_policy(admin, iface, name, traffic_limit_bytes=int(float(text.replace(',', '.')) * 1024 ** 3))
            self.show(chat, *self.screen_client(iface, name))
        elif kind == 'tg':
            if not re.fullmatch(r'0|[1-9][0-9]{2,14}', text):
                self.show(chat, self.t('bad_tg'))
                return
            self.pending.pop(admin, None)
            self.set_policy(admin, iface, name, telegram_id='' if text == '0' else text)
            self.owners_at = None
            self.show(chat, *self.screen_client(iface, name))

    def on_callback(self, chat, admin, data, message_id):
        self.pending.pop(admin, None)
        parts = data.split(':')
        kind = parts[0]
        iface = parts[1] if len(parts) > 1 else ''
        if iface and not IFACE_RE.fullmatch(iface):
            raise BotError('bad request')
        name = parts[2] if len(parts) > 2 else ''
        if kind in ('c', 'ca', 'cy', 'ce', 'cq') and not NAME_RE.fullmatch(name):
            raise BotError('bad request')
        value = parts[3] if len(parts) > 3 else ''
        if kind == 'm':
            self.show(chat, *self.screen_menu(), message_id=message_id)
        elif kind == 'h':
            self.show(chat, self.t('help'), [[(self.t('b_menu'), 'm')]], message_id)
        elif kind == 's':
            screen = self.screen_server(iface) if iface else self.screen_servers()
            self.show(chat, *screen, message_id=message_id)
        elif kind == 'sa' and name in ('start', 'stop', 'restart'):
            if name == 'start':
                self.server_action(chat, admin, iface, 'start', message_id)
            else:
                self.show(chat, self.t('confirm_' + name, iface=iface),
                          [[(self.t('b_yes'), f'sy:{iface}:{name}'), (self.t('b_no'), f's:{iface}')]], message_id)
        elif kind == 'sy' and name in ('stop', 'restart'):
            self.server_action(chat, admin, iface, name, message_id)
        elif kind == 'cl':
            target = iface or self.default_server()
            self.show(chat, *self.screen_clients(target, int(name) if name.isdigit() else 0), message_id=message_id)
        elif kind == 'c':
            self.show(chat, *self.screen_client(iface, name), message_id=message_id)
        elif kind == 'add':
            self.pending[admin] = ('add', iface, '', self.clock() + PENDING_SECONDS)
            self.show(chat, self.t('ask_name', iface=iface), [[(self.t('b_no'), f'cl:{iface}:0')]], message_id)
        elif kind == 'ca':
            self.client_action(chat, admin, iface, name, value, message_id)
        elif kind == 'cy' and value == 'del':
            self.ctl('delete', {'interface': iface, 'name': name})
            self.audit('client_deleted', f'{iface}/{name}', admin)
            self.show(chat, self.t('deleted', name=name), message_id=message_id)
            self.show(chat, *self.screen_clients(iface, 0))
        elif kind == 'ce' and value in ('0', '7', '30', '90'):
            day = '' if value == '0' else (datetime.now(timezone.utc) + timedelta(days=int(value))).date().isoformat()
            self.set_policy(admin, iface, name, expires_at=day)
            self.show(chat, *self.screen_client(iface, name), message_id=message_id)
        elif kind == 'cq' and value in ('0', '10', '50', '100', '500'):
            self.set_policy(admin, iface, name, traffic_limit_bytes=int(value) * 1024 ** 3)
            self.show(chat, *self.screen_client(iface, name), message_id=message_id)
        elif kind == 'st':
            self.show(chat, *self.screen_status(), message_id=message_id)
        elif kind == 'bk':
            self.show(chat, *self.screen_backup(), message_id=message_id)
        elif kind == 'bky':
            result = self.ctl('backup-create', {})
            self.own_actions['backup:' + str(result.get('name'))] = self.clock()
            self.show(chat, self.t('backup_done', name=result.get('name', ''), size=human_size(result.get('size', 0))),
                      [[(self.t('b_menu'), 'm')]], message_id)
        else:
            raise BotError('bad request')

    def server_action(self, chat, admin, iface, action, message_id):
        self.own_actions[f'server:{iface}'] = self.clock()
        self.ctl('server-' + action, {'interface': iface})
        self.audit({'start': 'server_started', 'stop': 'server_stopped', 'restart': 'server_restarted'}[action], iface, admin)
        self.show(chat, *self.screen_server(iface), message_id=message_id)

    def client_action(self, chat, admin, iface, name, action, message_id):
        if action in ('conf', 'qr'):
            self.send_config(chat, iface, name, as_qr=action == 'qr')
        elif action in ('on', 'off'):
            self.ctl('enable' if action == 'on' else 'disable', {'interface': iface, 'name': name})
            self.audit('client_enabled' if action == 'on' else 'client_disabled', f'{iface}/{name}', admin)
            self.show(chat, *self.screen_client(iface, name), message_id=message_id)
        elif action == 'del':
            self.show(chat, self.t('confirm_del', name=name, iface=iface),
                      [[(self.t('b_yes'), f'cy:{iface}:{name}:del'), (self.t('b_no'), f'c:{iface}:{name}')]], message_id)
        elif action == 'exp':
            self.pending[admin] = ('exp', iface, name, self.clock() + PENDING_SECONDS)
            self.show(chat, self.t('ask_exp', name=name),
                      [[(self.t('b_days', n=n), f'ce:{iface}:{name}:{n}') for n in (7, 30, 90)],
                       [(self.t('b_noexp'), f'ce:{iface}:{name}:0'), (self.t('b_no'), f'c:{iface}:{name}')]], message_id)
        elif action == 'tg':
            self.pending[admin] = ('tg', iface, name, self.clock() + PENDING_SECONDS)
            self.show(chat, self.t('ask_tg', name=name), [[(self.t('b_no'), f'c:{iface}:{name}')]], message_id)
        elif action == 'quota':
            self.pending[admin] = ('quota', iface, name, self.clock() + PENDING_SECONDS)
            self.show(chat, self.t('ask_quota', name=name),
                      [[(self.t('b_gib', n=n), f'cq:{iface}:{name}:{n}') for n in (10, 50, 100, 500)],
                       [(self.t('b_nolimit'), f'cq:{iface}:{name}:0'), (self.t('b_no'), f'c:{iface}:{name}')]], message_id)
        else:
            raise BotError('bad request')

    # ------------------------------------------------------------ notifications
    def notify(self, text):
        for admin in sorted(self.config['admins']):
            try:
                self.api.call('sendMessage', chat_id=admin, text=text, parse_mode='HTML', disable_web_page_preview=True)
            except BotError as exc:
                log(f'cannot notify {admin}: {exc}')

    def recently_own(self, key, window=180):
        stamp = self.own_actions.get(key)
        return stamp is not None and self.clock() - stamp < window

    def tick(self):
        """Look for things worth telling the administrators about. Called once a minute."""
        notify = self.config['notify']
        try:
            self.check_audit(notify)
        except Exception as exc:              # a failed check must not stop the bot
            log(f'audit check failed: {type(exc).__name__}: {exc}')
        try:                                      # runs always: owners are warned about expiry even with admin groups off
            self.check_servers(notify)
        except Exception as exc:
            log(f'server check failed: {type(exc).__name__}: {exc}')
        self.own_actions = {key: stamp for key, stamp in self.own_actions.items() if self.clock() - stamp < 600}
        self._save_state()

    def check_audit(self, notify):
        entries = self.ctl('audit-list').get('entries', [])
        seen = self.state.get('audit_seen')
        stamps = [str(e.get('timestamp', '')) for e in entries]
        if seen is None:
            # First start: do not replay history.
            self.state['audit_seen'] = max(stamps, default='')
            return
        fresh = [e for e in entries if str(e.get('timestamp', '')) > seen]
        if not fresh:
            return
        self.state['audit_seen'] = max(str(e.get('timestamp', '')) for e in fresh)
        failed = [e for e in fresh if e.get('event') == 'login_failed']
        if failed and notify['security']:
            self.notify(self.t('n_login_failed', count=len(failed), target=failed[-1].get('target', '')))
        for entry in fresh:
            event, target = entry.get('event'), str(entry.get('target', ''))
            if '(telegram ' in target:
                continue                    # the administrator did this through the bot and already saw the result
            if event == 'login_success' and notify['security']:
                self.notify(self.t('n_login', target=target))
            elif event == 'password_changed' and notify['security']:
                self.notify(self.t('n_password'))
            elif event == 'client_disabled' and target.endswith('(auto)') and notify['clients']:
                self.notify(self.t('n_disabled', target=target[:-len('(auto)')].strip()))
            elif event == 'backup_created' and notify['backups'] and not self.recently_own('backup:' + target, 600):
                self.notify(self.t('n_backup', target=target))
            elif event == 'backup_failed' and notify['backups']:
                self.notify(self.t('n_backup_failed', target=target))

    def check_servers(self, notify):
        servers = self.servers()
        known = self.state.setdefault('running', {})
        for s in servers:
            iface, running = s['interface'], bool(s.get('running'))
            before = known.get(iface)
            known[iface] = running
            if notify['server'] and before is not None and before != running and not self.recently_own(f'server:{iface}'):
                self.notify(self.t('n_up' if running else 'n_down', iface=iface))
        for iface in [name for name in known if name not in {s['interface'] for s in servers}]:
            known.pop(iface)
        if notify['server'] and servers:
            diag = self.ctl('diagnostics', {'interface': servers[0]['interface']})
            for key, part, bad_text, ok_text in (('module_ok', 'loaded_module', 'n_module_bad', 'n_module_ok'),
                                                 ('panel_ok', 'panel', 'n_panel_bad', 'n_panel_ok')):
                item = diag.get(part) or {}
                healthy = bool(item.get('ok')) and (part != 'panel' or item.get('output') == 'active')
                before = self.state.get(key)
                self.state[key] = healthy
                if before is not None and before != healthy:
                    self.notify(self.t(ok_text) if healthy else self.t(bad_text, detail=item.get('output') or 'not loaded'))
        warned = self.state.setdefault('expiry_warned', {})
        now = datetime.fromtimestamp(self.clock(), timezone.utc)
        current = set()
        for s in servers:
            for c in self.clients(s['interface']):
                expiry = c.get('expires_at')
                if not expiry or not c.get('enabled'):
                    continue
                key = f"{s['interface']}/{c['name']}/{expiry}"
                current.add(key)
                try:
                    moment = datetime.fromisoformat(expiry)
                except ValueError:
                    continue
                if moment.tzinfo is None:
                    moment = moment.replace(tzinfo=timezone.utc)
                if now < moment <= now + EXPIRY_WARNING and key not in warned:
                    warned[key] = True
                    if notify['clients']:
                        self.notify(self.t('n_expiring', name=c['name'], iface=s['interface'], when=expiry[:10]))
                    owner = str(c.get('telegram_id') or '')
                    if owner.isdigit() and int(owner) not in self.config['admins']:
                        try:
                            self.api.call('sendMessage', chat_id=int(owner), parse_mode='HTML',
                                          text=self.t('n_user_expiring', name=c['name'], when=expiry[:10]))
                        except BotError as exc:     # usually: the owner never started the bot
                            log(f'cannot warn the owner of {c["name"]}: {exc}')
        for key in [k for k in warned if k not in current]:
            warned.pop(key)

    # ------------------------------------------------------------ main loop
    def run(self):
        try:
            self.api.call('deleteWebhook', drop_pending_updates=False)     # long polling needs no webhook
        except BotError as exc:
            log(f'deleteWebhook: {exc}')
        log('awg31 bot started')
        offset = self.state.get('offset')
        delay = 1
        while True:
            if self.clock() >= self.next_tick:
                self.next_tick = self.clock() + 60
                self.tick()
            try:
                updates = self.api.call('getUpdates', http_timeout=40, offset=offset, timeout=25,
                                        allowed_updates=['message', 'callback_query'])
                delay = 1
            except BotError as exc:
                log(f'getUpdates: {exc}')
                time.sleep(delay)
                delay = min(delay * 2, 60)
                continue
            for update in updates or []:
                offset = int(update['update_id']) + 1
                self.state['offset'] = offset
                self.handle_update(update)
            if updates:
                self._save_state()


def setup_helper(mode):
    """Helpers for `sudo awg31 telegram`. The token arrives on stdin, never in argv."""
    base = os.environ.get('AWG31_TELEGRAM_API') or 'https://api.telegram.org'
    try:
        if mode == 'send-test':
            config = load_config()
            api = Api(config['token'], config['api_base'])
            for admin in sorted(config['admins']):
                api.call('sendMessage', chat_id=admin, text=TEXT[config['lang']]['test'])
            return 0
        api = Api(sys.stdin.readline().strip(), base)
        if mode == 'check-token':
            print(api.call('getMe').get('username', ''))
            return 0
        # find-admin: wait for the first private message and report who sent it.
        api.call('deleteWebhook', drop_pending_updates=True)
        deadline, offset = time.time() + 120, None
        while time.time() < deadline:
            for update in api.call('getUpdates', http_timeout=20, offset=offset, timeout=10, allowed_updates=['message']) or []:
                offset = int(update['update_id']) + 1
                message = update.get('message') or {}
                sender = message.get('from') or {}
                if (message.get('chat') or {}).get('type') == 'private' and sender.get('id'):
                    name = ' '.join(str(sender.get(k, '')) for k in ('first_name', 'last_name')).strip()
                    label = re.sub(r'[^\w .@-]', '', f"{name} @{sender.get('username', '')}")[:80]
                    print(f"{int(sender['id'])}\t{label}")
                    return 0
        return 3
    except (BotError, ValueError, OSError, KeyError) as exc:
        log(str(exc) if isinstance(exc, (BotError, ValueError)) else type(exc).__name__)
        return 1


def main():
    if len(sys.argv) == 2 and sys.argv[1] in ('check-token', 'find-admin', 'send-test'):
        return setup_helper(sys.argv[1])
    try:
        config = load_config()
    except (OSError, ValueError, KeyError) as exc:
        log(f'Cannot read {CONFIG}: {type(exc).__name__}. Run: sudo awg31 telegram')
        return 2
    Bot(config).run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
