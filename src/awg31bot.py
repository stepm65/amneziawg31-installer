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
import base64
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
NAME_RE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}')
IFACE_RE = re.compile(r'awg(?:0|[1-9][0-9]?)')
TOKEN_RE = re.compile(r'[0-9]{5,14}:[A-Za-z0-9_-]{30,60}')
PAGE = 8
PENDING_SECONDS = 300
READ_KINDS = {'m', 'h', 's', 'cl', 'c', 'st', 'bk'}     # buttons a viewer may press: screens only
QUOTA_WARNING = 0.8
RENEW_INTERVAL = 86400
OWNERS_TTL = 60          # how long the list of client owners is trusted
OWNER_INTERVAL = 3       # seconds between answers to one client owner
INVITE_RE = re.compile(r'^[A-Za-z0-9_-]{20,64}$')
INVITE_TRIES = 5         # attempts per person in INVITE_WINDOW seconds; codes are 144-bit random anyway
INVITE_WINDOW = 600
INVITE_DAYS = (1, 7, 30)
EXPIRY_WARNING = timedelta(hours=72)
# Event switches as the panel shows them: each event belongs to one card (group).
EVENTS = {
    'server_state': 'server', 'module': 'server', 'kernel': 'server', 'panel': 'server',
    'client_auto': 'clients', 'client_expiring': 'clients', 'client_quota': 'clients',
    'login': 'security', 'login_failed': 'security', 'password': 'security', 'owner_export': 'security',
    'totp_recovery': 'security', 'invite': 'clients', 'update': 'server', 'rotation': 'server', 'blocking': 'server',
    'backup_created': 'backups', 'backup_failed': 'backups', 'upload_failed': 'backups',
    'cpu': 'system', 'memory': 'system', 'disk': 'system',
}
THRESHOLDS = {'cpu': 90, 'memory': 90, 'disk': 90}     # percent; the panel lets each be changed
LOAD_MINUTES = 3         # CPU must stay above its threshold this many checks in a row
CRON_ALIASES = {'@hourly': '0 * * * *', '@daily': '0 9 * * *', '@weekly': '0 9 * * 1', '@monthly': '0 9 1 * *',
                'daily': '0 9 * * *', 'weekly': '0 9 * * 1'}
CRON_LIMITS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


def cron_fields(expression):
    """Parse a five-field crontab line (numbers, *, a-b, lists, /step) into sets of values."""
    text = CRON_ALIASES.get(str(expression).strip(), str(expression).strip())
    parts = text.split()
    if len(parts) != 5:
        raise ValueError('Schedule: five crontab fields, e.g. 0 9 * * *')
    fields = []
    for part, (low, high) in zip(parts, CRON_LIMITS):
        values = set()
        for item in part.split(','):
            match = re.fullmatch(r'(\*|[0-9]{1,2}(?:-[0-9]{1,2})?)(?:/([0-9]{1,2}))?', item)
            if not match:
                raise ValueError(f'Schedule: cannot read "{item}"')
            base, step = match.group(1), int(match.group(2) or 1)
            if base == '*':
                first, last = low, high
            elif '-' in base:
                first, last = (int(x) for x in base.split('-'))
            else:
                first = int(base)
                last = high if match.group(2) else first
            if step < 1 or not low <= first <= last <= high:
                raise ValueError(f'Schedule: "{item}" is out of range {low}-{high}')
            values.update(range(first, last + 1, step))
        fields.append(values)
    if 7 in fields[4]:
        fields[4].add(0)                                  # both 0 and 7 mean Sunday
    return fields


def cron_due(fields, moment):
    """Does a local time.struct_time fall on the schedule? Day of month and weekday follow cron's OR rule."""
    minute, hour, days, months, weekdays = fields
    if moment.tm_min not in minute or moment.tm_hour not in hour or moment.tm_mon not in months:
        return False
    any_day, any_weekday = days == set(range(1, 32)), weekdays >= set(range(0, 7))
    on_day, on_weekday = moment.tm_mday in days, (moment.tm_wday + 1) % 7 in weekdays
    if any_day or any_weekday:
        return on_day and on_weekday
    return on_day or on_weekday

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
                   'Трафик: ↓ {rx} · ↑ {tx}\nИспользовано: {used}{quota}\nПоследнее соединение: {seen}\nСрок: {expiry}{speed}{comment}{owner}{stale}'),
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
        'help': ('<b>Что умеет бот</b>\n• клиенты: создать, выдать конфиг и QR, включить и отключить, срок, лимит, новый ключ, удалить\n• приглашение: одноразовая ссылка, по которой человек сам становится владельцем клиента\n• владелец клиента (Telegram ID) видит в боте состояние своего доступа\n'
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
        'read_only': 'У вас доступ только для просмотра.',
        'n_next_kernel_bad': '⚠️ Установлено новое ядро <b>{version}</b>, но модуль AmneziaWG для него не собран. После перезагрузки VPN не запустится. До перезагрузки выполните на сервере: <code>sudo awg31 update</code>',
        'n_next_kernel_ok': '🟢 Модуль AmneziaWG для нового ядра собран: перезагружать сервер можно.',
        'n_upload_failed': '⚠️ Резервная копия не отправлена во внешнее хранилище: {target}',
        'speed': '\nСкорость: до {n} Мбит/с', 'monthly': ' в месяц', 'b_speed': '🚦 Скорость', 'b_nospeed': 'Без ограничения',
        'b_mbit': '{n} Мбит/с', 'ask_speed': 'Ограничение скорости <b>{name}</b> (в обе стороны).',
        'b_renew': '🙏 Продлить {name}', 'renew_sent': 'Запрос на продление <b>{name}</b> отправлен администратору.',
        'renew_wait': 'Запрос по <b>{name}</b> уже отправлен. Повторить можно через сутки.',
        'renew_ask': '🙏 Владелец клиента <b>{name}</b> ({iface}, Telegram ID {owner}) просит продлить доступ.\nСейчас: {expiry}',
        'b_refuse': '✖️ Отказать', 'renew_done': '✅ <b>{name}</b> продлён до {when}.', 'renew_refused': '✖️ В продлении <b>{name}</b> отказано.',
        'n_user_renewed': '✅ Ваш VPN-доступ <b>{name}</b> продлён до {when}.',
        'n_user_refused': 'В продлении VPN-доступа <b>{name}</b> отказано. Обратитесь к администратору.',
        'n_user_disabled': '⏸ Ваш VPN-доступ <b>{name}</b> отключён: {reason}.', 'why_expired': 'истёк срок', 'why_quota': 'израсходован лимит трафика',
        'n_user_enabled': '▶️ Ваш VPN-доступ <b>{name}</b> снова работает: начался новый месяц, счётчик трафика сброшен.',
        'n_user_quota': '📊 По VPN-доступу <b>{name}</b> израсходовано {percent}% лимита ({used} из {quota}).',
        'n_quota': '📊 Клиент <b>{name}</b> ({iface}) израсходовал {percent}% лимита ({used} из {quota}).',
        'n_enabled': '▶️ Клиент <b>{target}</b> включён автоматически: новый месяц, счётчик трафика сброшен.',
        'n_backup_file': 'Зашифрованная резервная копия. Для расшифровки нужен пароль шифрования копий.',
        'dg_title': '📊 <b>Сводка {period}</b>', 'dg_day': 'за сутки', 'dg_week': 'за неделю',
        'dg_hour': 'за час', 'dg_hours': 'за {n} ч', 'dg_days': 'за {n} дн.',
        'n_cpu': '🔥 Загрузка процессора {value}% уже {minutes} мин (порог {limit}%).',
        'n_cpu_ok': '🟢 Загрузка процессора снова ниже порога: {value}%.',
        'n_memory': '🧠 Занято памяти {value}% (порог {limit}%), свободно {free}.',
        'n_memory_ok': '🟢 Память снова ниже порога: занято {value}%.',
        'n_disk': '💽 Диск заполнен на {value}% (порог {limit}%), свободно {free}.',
        'n_disk_ok': '🟢 Диск снова ниже порога: заполнен на {value}%.',
        'dg_server': '{icon} <b>{iface}</b>: клиентов {clients}, на связи {online}, отключено {off}',
        'dg_traffic': 'Трафик клиентов: {total}', 'dg_top': 'Самые активные:', 'dg_top_row': '• {name} ({iface}) — {used}',
        'dg_expiring': 'Срок истекает в течение 7 дней: {names}', 'dg_idle': 'Не подключались более 30 дней: {names}',
        'dg_first': 'Трафик за период появится в следующей сводке.',
        'b_tg_export_on': '🔓 Разрешить владельцу конфиг', 'b_tg_export_off': '🔒 Запретить владельцу конфиг',
        'owner_export': ' · может получить конфиг', 'my_conf_caption': 'Конфигурация {name}. В файле приватный ключ: никому его не пересылайте.',
        'my_qr_caption': 'QR-код {name} для приложения AmneziaWG. Никому его не показывайте.',
        'n_owner_export': '📤 Владелец получил конфигурацию клиента <b>{target}</b> через бота.',
        'n_user_expiring': '⏳ Срок вашего VPN-доступа <b>{name}</b> истекает {when}. Обратитесь к администратору.',
        'test': '✅ Бот AmneziaWG 3.1 Console подключён. Отправьте /menu.',
        'your_id': 'Ваш Telegram ID: <code>{id}</code>',
        'n_backup': '💾 Создана резервная копия <code>{target}</code>.', 'n_backup_failed': '⚠️ Резервная копия по расписанию не создана: {target}',
        'b_invite': '✉️ Пригласить', 'b_rekey': '🔑 Новый ключ',
        'ask_invite': ('Приглашение для <b>{name}</b>: одноразовая ссылка. Человек открывает её, нажимает «Старт» '
                       'и становится владельцем клиента{export}. Сколько дней ссылка действует?'),
        'invite_export_note': ' и может сам получить конфигурацию', 'b_invite_days': '{n} дн.',
        'invite_link': ('✉️ Приглашение для <b>{name}</b> ({iface}), действует до {when} UTC, один раз:\n{link}\n\n'
                        'Перешлите ссылку человеку. Прежняя ссылка этого клиента больше не работает.'),
        'invite_no_username': 'Не удалось узнать имя бота. Отправьте человеку команду: <code>/start {code}</code>',
        'invite_ok': '✅ Готово: VPN-доступ <b>{name}</b> теперь ваш.',
        'invite_bad': 'Приглашение недействительно: истёк срок, оно уже использовано или отозвано. Попросите новое у администратора.',
        'invite_wait': 'Слишком много попыток. Попробуйте позже.',
        'n_invite': '✉️ Приглашение использовано: <b>{name}</b> ({iface}) теперь у {who}.',
        'n_totp_recovery': '🔐 Вход в веб-панель по резервному коду. Осталось кодов: {left}.',
        'n_updated': '⬆️ Панель обновлена: {target}.', 'n_update_failed': '⚠️ Обновление панели не удалось: {target}. Ход — в «Обслуживание → Обновление».',
        'n_rolled_back': '↩️ Панель откачена: {target}.',
        'b_probe': '📡 Пакеты 15 с', 'b_rotate': '🔀 Сменить порт',
        'confirm_rotate': ('Сменить порт и параметры обфускации <b>{iface}</b>? Сервер перезапустится. Роутеры с подпиской '
                           'получат новые параметры сами, остальным клиентам нужно импортировать конфигурацию заново.'),
        'rotated': '🔀 <b>{iface}</b>: порт {old} → <b>{port}</b>, обфускация новая. Откройте порт в облачном файрволе, если он есть.',
        'probe_wait': '📡 Слушаю UDP-порт <b>{iface}</b> 15 секунд — включите VPN на клиенте…',
        'probe_result': '📡 <b>{iface}</b>, {port}/udp за 15 с\nОт клиентов: <b>{incoming}</b>\nОтветов сервера: <b>{outgoing}</b>\nОткуда: {sources}\n\n{verdict}',
        'probe_none': 'Пакеты не доходят до сервера: проверьте облачный файрвол; если открыт — порт или протокол режет провайдер.',
        'probe_no_answer': 'Пакеты доходят, но сервер не отвечает: у клиента другие ключи или обфускация. Нужна свежая конфигурация.',
        'probe_ok': 'Пакеты доходят, сервер отвечает.',
        'n_user_newconf': '🔄 Параметры VPN-сервера изменились. Новая конфигурация <b>{name}</b> ниже: импортируйте её заново, прежняя больше не работает.',
        'n_user_changed': '🔄 Параметры VPN-сервера изменились: конфигурация <b>{name}</b> больше не работает. Попросите у администратора новую.',
        'n_delivered': '📨 Новые конфигурации отправлены владельцам: {count}.',
        'n_silent': ('🚫 Клиенты пропали все сразу: {target}. Возможно, порт или протокол заблокирован. '
                     'Проверьте входящие пакеты (📡 в меню сервера) или смените порт (🔀).'),
        'n_back': '✅ Клиенты снова подключаются: {target}.',
        'n_rotated': '🔀 Параметры сервера сменены: {target}.', 'n_rotate_failed': '⚠️ Смена параметров сервера не удалась: {target}.',
        'confirm_rekey': ('Выпустить для <b>{name}</b> новый ключ? Текущая конфигурация перестанет работать сразу, '
                          'клиенту нужно будет импортировать новую. Адрес, лимиты, срок и владелец сохранятся.'),
        'rekeyed': '🔑 Ключ <b>{name}</b> перевыпущен. Новая конфигурация ниже.',
        'n_user_rekeyed': '🔑 Ключ вашего VPN-доступа <b>{name}</b> перевыпущен: прежняя конфигурация больше не работает. {how}',
        'how_bot': 'Получите новую кнопкой «Конфиг» в /start.', 'how_admin': 'Новую конфигурацию выдаст администратор.',
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
                   'Traffic: ↓ {rx} · ↑ {tx}\nUsed: {used}{quota}\nLast handshake: {seen}\nExpiry: {expiry}{speed}{comment}{owner}{stale}'),
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
        'help': ('<b>What the bot can do</b>\n• clients: create, hand out config and QR, enable and disable, expiry, quota, new key, delete\n• invitation: a one-time link with which a person becomes the client’s owner\n• a client’s owner (Telegram ID) sees the state of their access in the bot\n'
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
        'read_only': 'You have read-only access.',
        'n_next_kernel_bad': '⚠️ A new kernel <b>{version}</b> is installed, but the AmneziaWG module is not built for it. After a reboot the VPN will not start. Before rebooting run on the server: <code>sudo awg31 update</code>',
        'n_next_kernel_ok': '🟢 The AmneziaWG module for the new kernel is built: the server can be rebooted.',
        'n_upload_failed': '⚠️ The backup was not sent to the remote storage: {target}',
        'speed': '\nSpeed: up to {n} Mbit/s', 'monthly': ' per month', 'b_speed': '🚦 Speed', 'b_nospeed': 'Unlimited',
        'b_mbit': '{n} Mbit/s', 'ask_speed': 'Speed limit of <b>{name}</b> (both directions).',
        'b_renew': '🙏 Extend {name}', 'renew_sent': 'The request to extend <b>{name}</b> was sent to the administrator.',
        'renew_wait': 'A request for <b>{name}</b> was already sent. You can repeat it in a day.',
        'renew_ask': '🙏 The owner of client <b>{name}</b> ({iface}, Telegram ID {owner}) asks to extend the access.\nNow: {expiry}',
        'b_refuse': '✖️ Refuse', 'renew_done': '✅ <b>{name}</b> extended until {when}.', 'renew_refused': '✖️ Extension of <b>{name}</b> refused.',
        'n_user_renewed': '✅ Your VPN access <b>{name}</b> was extended until {when}.',
        'n_user_refused': 'The extension of VPN access <b>{name}</b> was refused. Contact the administrator.',
        'n_user_disabled': '⏸ Your VPN access <b>{name}</b> was disabled: {reason}.', 'why_expired': 'it expired', 'why_quota': 'the traffic quota is used up',
        'n_user_enabled': '▶️ Your VPN access <b>{name}</b> works again: a new month started and the traffic counter was reset.',
        'n_user_quota': '📊 VPN access <b>{name}</b> has used {percent}% of its quota ({used} of {quota}).',
        'n_quota': '📊 Client <b>{name}</b> ({iface}) has used {percent}% of its quota ({used} of {quota}).',
        'n_enabled': '▶️ Client <b>{target}</b> was enabled automatically: a new month, the traffic counter was reset.',
        'n_backup_file': 'Encrypted backup. Decrypting it needs the backup passphrase.',
        'dg_title': '📊 <b>Digest {period}</b>', 'dg_day': 'for the last day', 'dg_week': 'for the last week',
        'dg_hour': 'for the last hour', 'dg_hours': 'for the last {n} h', 'dg_days': 'for the last {n} days',
        'n_cpu': '🔥 CPU load has been {value}% for {minutes} min (threshold {limit}%).',
        'n_cpu_ok': '🟢 CPU load is below the threshold again: {value}%.',
        'n_memory': '🧠 Memory use is {value}% (threshold {limit}%), {free} free.',
        'n_memory_ok': '🟢 Memory use is below the threshold again: {value}%.',
        'n_disk': '💽 The disk is {value}% full (threshold {limit}%), {free} free.',
        'n_disk_ok': '🟢 The disk is below the threshold again: {value}% full.',
        'dg_server': '{icon} <b>{iface}</b>: {clients} clients, {online} online, {off} disabled',
        'dg_traffic': 'Client traffic: {total}', 'dg_top': 'Most active:', 'dg_top_row': '• {name} ({iface}) — {used}',
        'dg_expiring': 'Expire within 7 days: {names}', 'dg_idle': 'No connection for over 30 days: {names}',
        'dg_first': 'Traffic for the period appears in the next digest.',
        'b_tg_export_on': '🔓 Let the owner get the config', 'b_tg_export_off': '🔒 Stop config for the owner',
        'owner_export': ' · may get the config', 'my_conf_caption': 'Configuration of {name}. The file contains a private key: do not forward it to anybody.',
        'my_qr_caption': 'QR code of {name} for the AmneziaWG app. Do not show it to anybody.',
        'n_owner_export': '📤 The owner fetched the configuration of client <b>{target}</b> through the bot.',
        'n_user_expiring': '⏳ Your VPN access <b>{name}</b> expires {when}. Contact the administrator.',
        'test': '✅ The AmneziaWG 3.1 Console bot is connected. Send /menu.',
        'your_id': 'Your Telegram ID: <code>{id}</code>',
        'n_backup': '💾 Backup <code>{target}</code> was created.', 'n_backup_failed': '⚠️ The scheduled backup was not created: {target}',
        'b_invite': '✉️ Invite', 'b_rekey': '🔑 New key',
        'ask_invite': ('An invitation for <b>{name}</b>: a one-time link. The person opens it, presses Start '
                       'and becomes the owner of the client{export}. How many days is the link valid?'),
        'invite_export_note': ' and can get the configuration themselves', 'b_invite_days': '{n} d',
        'invite_link': ('✉️ Invitation for <b>{name}</b> ({iface}), valid until {when} UTC, once:\n{link}\n\n'
                        'Forward the link to the person. The previous link of this client no longer works.'),
        'invite_no_username': 'Could not learn the bot name. Send the person this command: <code>/start {code}</code>',
        'invite_ok': '✅ Done: the VPN access <b>{name}</b> is now yours.',
        'invite_bad': 'The invitation is not valid: it expired, was used or was revoked. Ask the administrator for a new one.',
        'invite_wait': 'Too many attempts. Try again later.',
        'n_invite': '✉️ Invitation used: <b>{name}</b> ({iface}) now belongs to {who}.',
        'n_totp_recovery': '🔐 Sign-in to the web panel with a recovery code. Codes left: {left}.',
        'n_updated': '⬆️ The panel was updated: {target}.', 'n_update_failed': '⚠️ The panel update failed: {target}. The log is under Maintenance → Update.',
        'n_rolled_back': '↩️ The panel was rolled back: {target}.',
        'b_probe': '📡 Packets 15 s', 'b_rotate': '🔀 Change port',
        'confirm_rotate': ('Change the port and obfuscation parameters of <b>{iface}</b>? The server restarts. Routers with a '
                           'subscription pick up the new parameters by themselves; other clients must import the configuration again.'),
        'rotated': '🔀 <b>{iface}</b>: port {old} → <b>{port}</b>, new obfuscation. Open the port in a cloud firewall if there is one.',
        'probe_wait': '📡 Listening on the UDP port of <b>{iface}</b> for 15 seconds: switch the VPN on at the client…',
        'probe_result': '📡 <b>{iface}</b>, {port}/udp in 15 s\nFrom clients: <b>{incoming}</b>\nServer answers: <b>{outgoing}</b>\nFrom: {sources}\n\n{verdict}',
        'probe_none': 'Packets do not reach the server: check the cloud firewall; if it is open, the provider drops the port or protocol.',
        'probe_no_answer': 'Packets arrive but the server does not answer: the client has other keys or obfuscation. It needs a fresh configuration.',
        'probe_ok': 'Packets arrive and the server answers.',
        'n_user_newconf': '🔄 The VPN server settings changed. The new configuration of <b>{name}</b> is below: import it again, the old one no longer works.',
        'n_user_changed': '🔄 The VPN server settings changed: the configuration of <b>{name}</b> no longer works. Ask the administrator for a new one.',
        'n_delivered': '📨 New configurations sent to their owners: {count}.',
        'n_silent': ('🚫 All clients vanished at once: {target}. The port or protocol may be blocked. '
                     'Check incoming packets (📡 in the server menu) or change the port (🔀).'),
        'n_back': '✅ Clients connect again: {target}.',
        'n_rotated': '🔀 Server parameters changed: {target}.', 'n_rotate_failed': '⚠️ The server parameter change failed: {target}.',
        'confirm_rekey': ('Issue a new key for <b>{name}</b>? The current configuration stops working at once and '
                          'the client must import the new one. Address, limits, expiry and owner stay.'),
        'rekeyed': '🔑 The key of <b>{name}</b> was replaced. The new configuration follows.',
        'n_user_rekeyed': '🔑 The key of your VPN access <b>{name}</b> was replaced: the old configuration no longer works. {how}',
        'how_bot': 'Get the new one with the Config button in /start.', 'how_admin': 'The administrator will give you the new configuration.',
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
    """Run one allowlisted controller command as root (control helper, else sudo); data travels as JSON."""
    # Token helpers use only the standard library and must also work outside /opt.
    import awg31client
    try:
        code, stdout, stderr = awg31client.call(command, json.dumps(data) if data is not None else None, 90)
    except (OSError, ConnectionError, subprocess.TimeoutExpired) as exc:
        raise BotError(type(exc).__name__) from None
    if code:
        try:
            message = json.loads(stderr).get('error', 'controller error')
        except ValueError:
            message = 'controller error (not permitted or unavailable)'
        raise BotError(str(message)[:300])
    try:
        return json.loads(stdout)
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
    groups = {key: bool((data.get('notify') or {}).get(key, True)) for key in ('server', 'clients', 'security', 'backups')}
    chosen = data.get('events') if isinstance(data.get('events'), dict) else {}
    # Older settings had one switch per group: each event starts from its group's switch.
    events = {key: bool(chosen.get(key, groups.get(group, True))) for key, group in EVENTS.items()}
    limits = data.get('thresholds') if isinstance(data.get('thresholds'), dict) else {}
    thresholds = {}
    for key, default in THRESHOLDS.items():
        try:
            thresholds[key] = min(100, max(10, int(limits.get(key, default))))
        except (TypeError, ValueError):
            thresholds[key] = default
    digest = str(data.get('digest') or 'off').strip()
    if digest != 'off':
        try:
            cron_fields(digest)
        except ValueError:
            digest = 'off'
    return {'token': str(data['token']), 'admins': admins, 'lang': lang if lang in TEXT else 'ru',
            'events': events, 'thresholds': thresholds, 'backup_file': bool(data.get('backup_file', groups['backups'])),
            # Viewers see the menus and get notifications but cannot change anything.
            'viewers': {int(item) for item in data.get('viewers', [])} - admins,
            'digest': CRON_ALIASES.get(digest, digest),
            'api_base': str(data.get('api_base') or 'https://api.telegram.org'),
            'username': str(data.get('username') or '')}


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
        self.viewing = False                          # the update being handled comes from a viewer
        self.invite_tries = {}                        # Telegram ID -> times of recent invitation attempts

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
        if self.viewing and rows:
            rows = [[button for button in row if button[1].split(':')[0] in READ_KINDS] for row in rows]
            rows = [row for row in rows if row]
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
                      [(self.t('b_probe'), f'pr:{iface}'), (self.t('b_rotate'), f'ro:{iface}')],
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
                      quota=(self.plain('of_quota', quota=human_size(limit))
                             + (self.plain('monthly') if c.get('quota_period') == 'monthly' else '')) if limit else '', seen=seen,
                      expiry=(c.get('expires_at') or '')[:10] or self.plain('no_expiry'),
                      speed=self.plain('speed', n=int(c['speed_limit_mbit'])) if c.get('speed_limit_mbit') else '',
                      comment=self.plain('comment', text=c['comment']) if c.get('comment') else '',
                      owner=(self.plain('owner', id=c['telegram_id']) + (self.plain('owner_export') if c.get('owner_export') else ''))
                      if c.get('telegram_id') else '',
                      stale=self.plain('stale') if c.get('config_stale') else '')
        toggle = (self.t('b_off'), f'ca:{iface}:{name}:off') if enabled else (self.t('b_on'), f'ca:{iface}:{name}:on')
        rows = [[(self.t('b_conf'), f'ca:{iface}:{name}:conf'), (self.t('b_qr'), f'ca:{iface}:{name}:qr')],
                [toggle, (self.t('b_exp'), f'ca:{iface}:{name}:exp'), (self.t('b_quota'), f'ca:{iface}:{name}:quota')],
                [(self.t('b_speed'), f'ca:{iface}:{name}:speed'), (self.t('b_tg'), f'ca:{iface}:{name}:tg'),
                 (self.t('b_del'), f'ca:{iface}:{name}:del'),
                 (self.t('b_refresh'), f'c:{iface}:{name}')],
                [(self.t('b_invite'), f'ca:{iface}:{name}:inv'), (self.t('b_rekey'), f'ca:{iface}:{name}:key')]]
        if c.get('telegram_id'):
            rows.append([(self.t('b_tg_export_off'), f'ca:{iface}:{name}:xoff')] if c.get('owner_export')
                        else [(self.t('b_tg_export_on'), f'ca:{iface}:{name}:xon')])
        rows.append([(self.t('b_back'), f'cl:{iface}:0')])
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
                if not (diag.get('next_kernel') or {}).get('ok', True):
                    lines.append(self.t('n_next_kernel_bad', version=diag['next_kernel'].get('output') or '?'))
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
    def send_config(self, chat, iface, name, as_qr, owner=False):
        export = self.ctl('download', {'interface': iface, 'name': name, 'mark': True})
        captions = ('my_qr_caption', 'my_conf_caption') if owner else ('qr_caption', 'conf_caption')
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
                               TEXT[self.config['lang']][captions[0]].format(name=name, iface=iface))
        else:
            self.api.send_file('sendDocument', 'document', chat, f'{name}.conf', config.encode(),
                               TEXT[self.config['lang']][captions[1]].format(name=name, iface=iface))

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
        if not user or (chat or {}).get('type') != 'private':
            return False
        user_id = int(user.get('id', 0))
        self.viewing = user_id in self.config.get('viewers', ())
        return user_id in self.config['admins'] or self.viewing

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

    def serve_owner(self, user, chat, message_id=None, callback_id=None, data=''):
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
            wanted = data.split(':')
            if len(wanted) == 3 and wanted[0] in ('mc', 'mq'):
                # The request is checked against the fresh list: the client must be this
                # person's, enabled, and the administrator must have allowed the export.
                for iface, c in mine:
                    if (iface, c['name']) == (wanted[1], wanted[2]) and c.get('owner_export') and c.get('enabled'):
                        self.send_config(chat['id'], iface, c['name'], as_qr=wanted[0] == 'mq', owner=True)
                        try:
                            self.ctl('audit', {'event': 'client_config_sent', 'target': f'{iface}/{c["name"]} (owner {user_id})'})
                        except BotError:
                            pass
                        return
            if len(wanted) == 3 and wanted[0] == 'mr':
                for iface, c in mine:
                    if (iface, c['name']) == (wanted[1], wanted[2]) and c.get('expires_at'):
                        self.ask_renewal(chat['id'], user_id, iface, c)
                        return
            parts = [self.t('my')]
            rows = []
            for iface, c in mine:
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
                if c.get('owner_export') and enabled:
                    rows.append([(f"{self.t('b_conf')} {c['name']}", f"mc:{iface}:{c['name']}"),
                                 (f"{self.t('b_qr')} {c['name']}", f"mq:{iface}:{c['name']}")])
                if c.get('expires_at') and (enabled or c.get('disabled_reason') == 'expired'):
                    rows.append([(self.t('b_renew', name=c['name']), f"mr:{iface}:{c['name']}")])
            parts.append(self.t('my_hint'))
            self.show(chat['id'], '\n\n'.join(parts), rows + [[(self.t('b_refresh'), 'me')]], message_id)
        except BotError as exc:
            log(f'owner request failed: {exc}')

    def ask_renewal(self, chat, owner, iface, c):
        """An owner asks for more time: administrators get the request with ready answers."""
        asked = self.state.setdefault('renew_asked', {})
        key = f"{iface}/{c['name']}"
        if self.clock() - asked.get(key, 0) < RENEW_INTERVAL:
            self.show(chat, self.t('renew_wait', name=c['name']))
            return
        asked[key] = self.clock()
        text = self.t('renew_ask', name=c['name'], iface=iface, owner=owner, expiry=(c.get('expires_at') or '')[:10])
        buttons = self.keyboard([[(self.t('b_days', n=n), f"rn:{iface}:{c['name']}:{n}") for n in (7, 30, 90)],
                                 [(self.t('b_refuse'), f"rn:{iface}:{c['name']}:0")]])
        for admin in sorted(self.config['admins']):             # viewers cannot grant it
            try:
                self.api.call('sendMessage', chat_id=admin, text=text, parse_mode='HTML', reply_markup=buttons)
            except BotError as exc:
                log(f'cannot notify {admin}: {exc}')
        self.show(chat, self.t('renew_sent', name=c['name']))
        self._save_state()

    def renew(self, chat, admin, iface, name, days, message_id):
        c = self.client(iface, name)
        self.state.setdefault('renew_asked', {}).pop(f'{iface}/{name}', None)
        if not days:
            self.show(chat, self.t('renew_refused', name=name), message_id=message_id)
            self.tell_owner(c, self.t('n_user_refused', name=name))
            return
        now = datetime.fromtimestamp(self.clock(), timezone.utc)
        try:
            current = datetime.fromisoformat(c.get('expires_at') or '')
            if current.tzinfo is None:
                current = current.replace(tzinfo=timezone.utc)
        except ValueError:
            current = now
        when = (max(current, now) + timedelta(days=days)).date().isoformat()
        self.set_policy(admin, iface, name, expires_at=when)
        if not c.get('enabled') and c.get('disabled_reason') == 'expired':
            self.ctl('enable', {'interface': iface, 'name': name})
            self.audit('client_enabled', f'{iface}/{name}', admin)
        self.show(chat, self.t('renew_done', name=name, when=when), [[(self.t('b_clients'), f'c:{iface}:{name}')]], message_id)
        self.tell_owner(c, self.t('n_user_renewed', name=name, when=when))

    def tell_id(self, user):
        asked = getattr(self, 'id_asked', {})
        now = self.clock()
        self.id_asked = {key: stamp for key, stamp in asked.items() if now - stamp < 30}
        if user in self.id_asked:
            return                                        # one answer per person every 30 seconds
        self.id_asked[user] = now
        try:
            self.api.call('sendMessage', chat_id=user, parse_mode='HTML', text=self.t('your_id', id=user))
        except BotError as exc:
            log(f'cannot answer /id: {exc}')

    def deliver_new_configs(self, iface, names=None):
        """After the server's parameters changed: owners allowed to export get the new .conf and QR code,
        other owners are told to ask for one. Routers with a subscription fetch theirs and are skipped."""
        try:
            clients = self.clients(iface)
        except BotError:
            return 0
        sent = 0
        for c in clients:
            owner = str(c.get('telegram_id') or '')
            if names is not None and c.get('name') not in names:
                continue
            if not owner.isdigit() or int(owner) in self.config['admins'] or c.get('subscription') or not c.get('enabled'):
                continue
            if not c.get('owner_export'):
                self.tell_owner(c, self.t('n_user_changed', name=c['name']))
                continue
            try:
                self.api.call('sendMessage', chat_id=int(owner), parse_mode='HTML', text=self.t('n_user_newconf', name=c['name']))
                self.send_config(int(owner), iface, c['name'], as_qr=False, owner=True)
                self.send_config(int(owner), iface, c['name'], as_qr=True, owner=True)
                sent += 1
            except BotError as exc:             # usually: the owner never started the bot
                log(f'cannot send the new configuration of {c.get("name")}: {exc}')
        return sent

    def after_server_change(self, event, target):
        """Which clients got a new configuration from a rotation, a masking profile or a move."""
        if event == 'client_moved':
            match = re.match(r'awg[0-9]{1,2}/([A-Za-z0-9_-]{1,32}) → (awg[0-9]{1,2})/', target)
            return self.deliver_new_configs(match.group(2), {match.group(1)}) if match else 0
        match = re.match(r'(awg[0-9]{1,2}): ', target)
        if not match:
            return 0
        if event == 'server_settings_changed' and not re.match(r'awg[0-9]{1,2}: [1-9][0-9]* client configurations changed', target):
            return 0
        if event == 'mask_profile_applied':
            changed = re.search(r', ([0-9]+) clients, port ([0-9]+) → ([0-9]+)', target)
            if not changed or (changed.group(1) == '0' and changed.group(2) == changed.group(3)):
                return 0
        return self.deliver_new_configs(match.group(1))

    def tell_owner(self, c, text):
        """A message to the person whose Telegram ID is on the client; never fatal."""
        owner = str(c.get('telegram_id') or '')
        if not owner.isdigit() or int(owner) in self.config['admins']:
            return
        try:
            self.api.call('sendMessage', chat_id=int(owner), parse_mode='HTML', text=text)
        except BotError as exc:                 # usually: the owner never started the bot
            log(f'cannot write to the owner of {c.get("name")}: {exc}')

    def redeem_invite(self, sender, chat, code):
        user = int(sender['id'])
        now = self.clock()
        tries = [stamp for stamp in self.invite_tries.get(user, []) if now - stamp < INVITE_WINDOW]
        self.invite_tries = {k: v for k, v in self.invite_tries.items() if v and now - v[-1] < INVITE_WINDOW}
        if len(tries) >= INVITE_TRIES:
            if len(tries) == INVITE_TRIES:          # say it once, then stay quiet
                tries.append(now)
                self.invite_tries[user] = tries
                self.api.call('sendMessage', chat_id=chat, text=self.t('invite_wait'))
            return
        self.invite_tries[user] = tries + [now]
        found = None
        try:
            for server in self.servers():
                result = self.ctl('invite-redeem', {'interface': server['interface'], 'code': code, 'telegram_id': str(user)})
                if result.get('found'):
                    found = (server['interface'], result)
                    break
        except BotError as exc:
            log(f'invitation check failed: {exc}')
        if not found:
            self.api.call('sendMessage', chat_id=chat, text=self.t('invite_bad'))
            return
        iface, result = found
        name = result['name']
        self.invite_tries.pop(user, None)
        try:
            self.ctl('audit', {'event': 'client_invite_used', 'target': f'{iface}/{name} (owner {user})'})
        except BotError:
            pass
        self.owners_at = None
        self.owner_seen.pop(user, None)
        self.api.call('sendMessage', chat_id=chat, parse_mode='HTML', text=self.t('invite_ok', name=name))
        who = re.sub(r'[^\w .@-]', '', ' '.join(str(sender.get(k) or '') for k in ('first_name', 'last_name')).strip())[:40]
        handle = re.sub(r'[^A-Za-z0-9_]', '', str(sender.get('username') or ''))[:32]
        label = (who + (f' @{handle}' if handle else '')).strip() or str(user)
        if self.on('invite'):
            self.notify(self.t('n_invite', name=name, iface=iface, who=f'{label} (ID {user})'))
        self.serve_owner(sender, {'id': chat, 'type': 'private'})

    def bot_username(self):
        if not self.config.get('username'):
            try:
                self.config['username'] = str(self.api.call('getMe').get('username') or '')
            except BotError:
                return ''
        name = self.config['username']
        return name if re.fullmatch(r'[A-Za-z0-9_]{3,32}', name) else ''

    def invite(self, chat, admin, iface, name, days, message_id):
        result = self.ctl('client-invite', {'interface': iface, 'name': name, 'days': days, 'export': True})
        self.audit('client_invite_created', f'{iface}/{name}', admin)
        username = self.bot_username()
        when = str(result.get('expires_at', ''))[:16].replace('T', ' ')
        if username:
            text = self.t('invite_link', name=name, iface=iface, when=when, link=f"https://t.me/{username}?start={result['code']}")
        else:
            text = self.t('invite_no_username', code=result['code'])
        self.show(chat, text, [[(self.t('b_back'), f'c:{iface}:{name}')]], message_id)

    def rekey(self, chat, admin, iface, name, message_id):
        before = self.client(iface, name)
        self.ctl('client-rekey', {'interface': iface, 'name': name})
        self.audit('client_rekeyed', f'{iface}/{name}', admin)
        self.show(chat, self.t('rekeyed', name=name), message_id=message_id)
        self.send_config(chat, iface, name, as_qr=False)
        self.send_config(chat, iface, name, as_qr=True)
        how = 'how_bot' if before.get('owner_export') and before.get('enabled') else 'how_admin'
        self.tell_owner(before, self.t('n_user_rekeyed', name=name, how=self.plain(how)))
        self.show(chat, *self.screen_client(iface, name))

    def find_client(self, target):
        """'awg0/name ...' from an audit record -> (iface, client) or None."""
        match = re.match(r'(awg[0-9]{1,2})/([A-Za-z0-9_-]{1,32})', target)
        if not match:
            return None
        try:
            return match.group(1), self.client(match.group(1), match.group(2))
        except BotError:
            return None

    def handle_update(self, update):
        if 'callback_query' in update:
            query = update['callback_query']
            message = query.get('message') or {}
            if not self.authorized(query.get('from'), message.get('chat')):
                self.serve_owner(query.get('from'), message.get('chat'), message.get('message_id'), query.get('id'),
                                 str(query.get('data', '')))
                return
            try:
                self.api.call('answerCallbackQuery', callback_query_id=query['id'])
            except BotError:
                pass
            self.guarded(message['chat']['id'], lambda: self.on_callback(message['chat']['id'], int(query['from']['id']),
                                                                         str(query.get('data', '')), message.get('message_id')))
        elif 'message' in update:
            message = update['message']
            sender, chat = message.get('from') or {}, message.get('chat') or {}
            command = str(message.get('text') or '').strip().split('@')[0].lower()
            if command == '/id' and chat.get('type') == 'private' and sender.get('id'):
                self.tell_id(int(sender['id']))           # anyone may learn their own ID, to give it to the administrator
                return
            words = str(message.get('text') or '').strip().split()
            if (len(words) == 2 and words[0].split('@')[0].lower() == '/start' and chat.get('type') == 'private'
                    and sender.get('id') and INVITE_RE.fullmatch(words[1])):
                # t.me/<bot>?start=<code>: anybody may hold an invitation, administrators included.
                self.redeem_invite(sender, int(chat['id']), words[1])
                return
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
                if self.viewing:
                    raise BotError(self.plain('read_only'))
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
        if self.viewing and kind not in READ_KINDS:
            raise BotError(self.plain('read_only'))
        iface = parts[1] if len(parts) > 1 else ''
        if iface and not IFACE_RE.fullmatch(iface):
            raise BotError('bad request')
        name = parts[2] if len(parts) > 2 else ''
        if kind in ('c', 'ca', 'cy', 'ce', 'cq', 'cs', 'rn', 'iv', 'ky') and not NAME_RE.fullmatch(name):
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
        elif kind == 'pr' and iface:
            self.probe(chat, admin, iface, message_id)
        elif kind == 'ro' and iface:
            self.show(chat, self.t('confirm_rotate', iface=iface),
                      [[(self.t('b_yes'), f'ry:{iface}:go'), (self.t('b_no'), f's:{iface}')]], message_id)
        elif kind == 'ry' and iface and name == 'go':
            self.own_actions[f'server:{iface}'] = self.clock()
            result = self.ctl('rotate', {'interface': iface, 'parts': ['port', 'obfuscation']})
            self.audit('server_rotated', f"{iface}: port, obfuscation, port {result.get('old_port')} → {result.get('port')}", admin)
            self.show(chat, self.t('rotated', iface=iface, old=result.get('old_port', '?'), port=result.get('port', '?')),
                      [[(self.t('b_back'), f's:{iface}')]], message_id)
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
        elif kind == 'cs' and value in ('0', '5', '10', '20', '50', '100'):
            self.set_policy(admin, iface, name, speed_limit_mbit=int(value))
            self.show(chat, *self.screen_client(iface, name), message_id=message_id)
        elif kind == 'iv' and value in tuple(str(n) for n in INVITE_DAYS):
            self.invite(chat, admin, iface, name, int(value), message_id)
        elif kind == 'ky' and value == 'yes':
            self.rekey(chat, admin, iface, name, message_id)
        elif kind == 'rn' and value in ('0', '7', '30', '90'):
            self.renew(chat, admin, iface, name, int(value), message_id)
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

    def probe(self, chat, admin, iface, message_id):
        self.show(chat, self.t('probe_wait', iface=iface), message_id=message_id)
        result = self.ctl('probe', {'interface': iface, 'seconds': 15})
        self.audit('packet_probe', f"{iface}: in {result.get('incoming', 0)}, out {result.get('outgoing', 0)}", admin)
        incoming, outgoing = int(result.get('incoming', 0)), int(result.get('outgoing', 0))
        verdict = 'probe_none' if not incoming else 'probe_no_answer' if not outgoing else 'probe_ok'
        sources = ', '.join(f'{addr} ×{count}' for addr, count in result.get('sources', [])[:5]) or '—'
        self.show(chat, self.t('probe_result', iface=iface, port=result.get('port', '?'), incoming=incoming,
                               outgoing=outgoing, sources=html.escape(sources), verdict=self.plain(verdict)),
                  [[(self.t('b_probe'), f'pr:{iface}'), (self.t('b_back'), f's:{iface}')]])

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
        elif action == 'speed':
            self.show(chat, self.t('ask_speed', name=name),
                      [[(self.t('b_mbit', n=n), f'cs:{iface}:{name}:{n}') for n in (5, 10, 20)],
                       [(self.t('b_mbit', n=n), f'cs:{iface}:{name}:{n}') for n in (50, 100)],
                       [(self.t('b_nospeed'), f'cs:{iface}:{name}:0'), (self.t('b_no'), f'c:{iface}:{name}')]], message_id)
        elif action == 'inv':
            self.show(chat, self.t('ask_invite', name=name, export=self.plain('invite_export_note')),
                      [[(self.t('b_invite_days', n=n), f'iv:{iface}:{name}:{n}') for n in INVITE_DAYS],
                       [(self.t('b_no'), f'c:{iface}:{name}')]], message_id)
        elif action == 'key':
            self.show(chat, self.t('confirm_rekey', name=name),
                      [[(self.t('b_yes'), f'ky:{iface}:{name}:yes'), (self.t('b_no'), f'c:{iface}:{name}')]], message_id)
        elif action in ('xon', 'xoff'):
            self.set_policy(admin, iface, name, owner_export=action == 'xon')
            self.owners_at = None
            self.show(chat, *self.screen_client(iface, name), message_id=message_id)
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
        for admin in sorted(self.config['admins'] | self.config.get('viewers', set())):
            try:
                self.api.call('sendMessage', chat_id=admin, text=text, parse_mode='HTML', disable_web_page_preview=True)
            except BotError as exc:
                log(f'cannot notify {admin}: {exc}')

    def recently_own(self, key, window=180):
        stamp = self.own_actions.get(key)
        return stamp is not None and self.clock() - stamp < window

    def tick(self):
        """Look for things worth telling the administrators about. Called once a minute."""
        try:
            self.check_audit()
        except Exception as exc:              # a failed check must not stop the bot
            log(f'audit check failed: {type(exc).__name__}: {exc}')
        try:                                      # runs always: owners are warned about expiry even with admin groups off
            self.check_servers()
        except Exception as exc:
            log(f'server check failed: {type(exc).__name__}: {exc}')
        try:
            self.check_host()
        except Exception as exc:
            log(f'host check failed: {type(exc).__name__}: {exc}')
        self.own_actions = {key: stamp for key, stamp in self.own_actions.items() if self.clock() - stamp < 600}
        self._save_state()

    def on(self, event):
        return bool(self.config.get('events', {}).get(event, True))

    def check_audit(self):
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
        if failed and self.on('login_failed'):
            self.notify(self.t('n_login_failed', count=len(failed), target=failed[-1].get('target', '')))
        for entry in fresh:
            event, target = entry.get('event'), str(entry.get('target', ''))
            if event in ('server_rotated', 'mask_profile_applied', 'client_moved', 'server_settings_changed'):
                # Owners get their new configuration whoever made the change, the bot included.
                delivered = self.after_server_change(event, target)
                if delivered and self.on('rotation'):
                    self.notify(self.t('n_delivered', count=delivered))
            if event == 'client_config_sent':
                if self.on('owner_export'):
                    self.notify(self.t('n_owner_export', target=target))
                continue
            if '(telegram ' in target:
                continue                    # the administrator did this through the bot and already saw the result
            if event == 'login_success' and self.on('login'):
                self.notify(self.t('n_login', target=target))
            elif event in ('panel_updated', 'panel_update_failed', 'panel_rolled_back') and self.on('update'):
                key = {'panel_updated': 'n_updated', 'panel_update_failed': 'n_update_failed', 'panel_rolled_back': 'n_rolled_back'}[event]
                self.notify(self.t(key, target=target or '?'))
            elif event in ('server_silent', 'server_back') and self.on('blocking'):
                self.notify(self.t('n_silent' if event == 'server_silent' else 'n_back', target=html.escape(target)))
            elif event in ('server_rotated', 'server_rotate_failed') and self.on('rotation'):
                self.notify(self.t('n_rotated' if event == 'server_rotated' else 'n_rotate_failed', target=html.escape(target or '?')))
            elif event == 'totp_recovery_used' and self.on('totp_recovery'):
                self.notify(self.t('n_totp_recovery', left=target.split()[0] if target else '?'))
            elif event == 'password_changed' and self.on('password'):
                self.notify(self.t('n_password'))
            elif event in ('client_disabled', 'client_enabled') and target.endswith('(auto)'):
                if self.on('client_auto'):
                    self.notify(self.t('n_disabled' if event == 'client_disabled' else 'n_enabled', target=target[:-len('(auto)')].strip()))
                found = self.find_client(target)
                if found and event == 'client_enabled':
                    self.tell_owner(found[1], self.t('n_user_enabled', name=found[1]['name']))
                elif found:
                    reason = 'why_quota' if found[1].get('disabled_reason') == 'quota' else 'why_expired'
                    self.tell_owner(found[1], self.t('n_user_disabled', name=found[1]['name'], reason=self.plain(reason)))
            elif event == 'backup_created' and self.config.get('backup_file', True) and target.endswith('.gpg'):
                # An encrypted archive is safe to keep in Telegram: it goes to the administrators as a file.
                content = base64.b64decode(self.ctl('backup-export-encrypted', {'name': target})['content'])
                for admin in sorted(self.config['admins']):
                    try:
                        self.api.send_file('sendDocument', 'document', admin, target, content, self.plain('n_backup_file'))
                    except BotError as exc:
                        log(f'cannot send the backup to {admin}: {exc}')
            elif event == 'backup_created' and self.on('backup_created') and not self.recently_own('backup:' + target, 600):
                self.notify(self.t('n_backup', target=target))
            elif event == 'backup_failed' and self.on('backup_failed'):
                self.notify(self.t('n_backup_failed', target=target))
            elif event == 'backup_upload_failed' and self.on('upload_failed'):
                self.notify(self.t('n_upload_failed', target=target))

    def check_servers(self):
        servers = self.servers()
        known = self.state.setdefault('running', {})
        for s in servers:
            iface, running = s['interface'], bool(s.get('running'))
            before = known.get(iface)
            known[iface] = running
            if self.on('server_state') and before is not None and before != running and not self.recently_own(f'server:{iface}'):
                self.notify(self.t('n_up' if running else 'n_down', iface=iface))
        for iface in [name for name in known if name not in {s['interface'] for s in servers}]:
            known.pop(iface)
        if servers and (self.on('module') or self.on('panel') or self.on('kernel')):
            diag = self.ctl('diagnostics', {'interface': servers[0]['interface']})
            for key, part, event, bad_text, ok_text in (('module_ok', 'loaded_module', 'module', 'n_module_bad', 'n_module_ok'),
                                                        ('panel_ok', 'panel', 'panel', 'n_panel_bad', 'n_panel_ok')):
                item = diag.get(part) or {}
                healthy = bool(item.get('ok')) and (part != 'panel' or item.get('output') == 'active')
                before = self.state.get(key)
                self.state[key] = healthy
                if before is not None and before != healthy and self.on(event):
                    self.notify(self.t(ok_text) if healthy else self.t(bad_text, detail=item.get('output') or 'not loaded'))
            # A newer kernel is installed but the module is not built for it: said once, before the reboot.
            upcoming = diag.get('next_kernel') or {}
            problem = '' if upcoming.get('ok', True) else str(upcoming.get('output') or '?')
            if problem != self.state.get('next_kernel_problem', ''):
                self.state['next_kernel_problem'] = problem
                if self.on('kernel'):
                    self.notify(self.t('n_next_kernel_bad', version=problem) if problem else self.t('n_next_kernel_ok'))
        warned = self.state.setdefault('expiry_warned', {})
        quota_warned = self.state.setdefault('quota_warned', {})
        now = datetime.fromtimestamp(self.clock(), timezone.utc)
        current = set()
        snapshot = []
        for s in servers:
            for c in self.clients(s['interface']):
                snapshot.append((s, c))
                limit, used = int(c.get('traffic_limit_bytes') or 0), int(c.get('used_bytes') or 0)
                quota_key = f"{s['interface']}/{c['name']}"
                if limit and c.get('enabled') and used >= limit * QUOTA_WARNING:
                    if quota_warned.get(quota_key) != limit:
                        quota_warned[quota_key] = limit
                        values = dict(name=c['name'], percent=int(used * 100 / limit), used=human_size(used), quota=human_size(limit))
                        if self.on('client_quota'):
                            self.notify(self.t('n_quota', iface=s['interface'], **values))
                        self.tell_owner(c, self.t('n_user_quota', **values))
                elif used < limit * QUOTA_WARNING or not limit:
                    quota_warned.pop(quota_key, None)       # a raised quota or a monthly reset re-arms the warning
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
                    if self.on('client_expiring'):
                        self.notify(self.t('n_expiring', name=c['name'], iface=s['interface'], when=expiry[:10]))
                    self.tell_owner(c, self.t('n_user_expiring', name=c['name'], when=expiry[:10]))
        for key in [k for k in warned if k not in current]:
            warned.pop(key)
        self.maybe_digest(servers, snapshot)

    def host_sample(self):
        """CPU counters, memory and the root file system, read the same way as the panel does."""
        sample = {}
        try:
            counters = [int(v) for v in Path('/proc/stat').read_text().split('\n', 1)[0].split()[1:]]
            sample['cpu'] = (sum(counters), counters[3] + counters[4])
        except (OSError, ValueError, IndexError):
            pass
        try:
            memory = {}
            for line in Path('/proc/meminfo').read_text().splitlines():
                key, _, raw = line.partition(':')
                if key in ('MemTotal', 'MemAvailable'):
                    memory[key] = int(raw.split()[0]) * 1024
            sample['memory'] = (memory['MemTotal'], memory['MemAvailable'])
        except (OSError, ValueError, IndexError, KeyError):
            pass
        try:
            fs = os.statvfs('/')
            sample['disk'] = (fs.f_blocks * fs.f_frsize, fs.f_bavail * fs.f_frsize)
        except OSError:
            pass
        return sample

    def check_host(self):
        """CPU, memory and disk above the thresholds set in the panel: told once, and once when it passes."""
        keys = [key for key in ('cpu', 'memory', 'disk') if self.on(key)]
        alarms = self.state.setdefault('host_alarm', {})
        for key in [k for k in alarms if k not in keys]:
            alarms.pop(key)
        if not keys:
            return
        sample, limits = self.host_sample(), self.config.get('thresholds', THRESHOLDS)
        values, free = {}, {}
        previous, self.cpu_previous = getattr(self, 'cpu_previous', None), sample.get('cpu')
        if previous and sample.get('cpu') and sample['cpu'][0] > previous[0]:
            busy = 1 - (sample['cpu'][1] - previous[1]) / (sample['cpu'][0] - previous[0])
            values['cpu'] = max(0, min(100, round(busy * 100)))
        for key in ('memory', 'disk'):
            total, available = sample.get(key) or (0, 0)
            if total:
                values[key], free[key] = round((1 - available / total) * 100), human_size(available)
        streak = getattr(self, 'cpu_streak', 0)
        if 'cpu' in values:
            streak = streak + 1 if values['cpu'] >= limits['cpu'] else 0
        self.cpu_streak = streak
        for key in keys:
            if key not in values:
                continue
            value, limit = values[key], limits[key]
            high = streak >= LOAD_MINUTES if key == 'cpu' else value >= limit
            if high and not alarms.get(key):
                alarms[key] = True
                self.notify(self.t('n_' + key, value=value, limit=limit, minutes=streak, free=free.get(key, '')))
            elif alarms.get(key) and value < limit - 5:        # a margin, so a value near the line does not chatter
                alarms[key] = False
                self.notify(self.t(f'n_{key}_ok', value=value))

    def period_text(self, seconds):
        hours = seconds / 3600
        if hours < 1.5:
            return self.plain('dg_hour')
        if 20 <= hours <= 28:
            return self.plain('dg_day')
        if 6 * 24 <= hours <= 8 * 24:
            return self.plain('dg_week')
        if hours < 48:
            return self.plain('dg_hours', n=round(hours))
        return self.plain('dg_days', n=round(hours / 24))

    def maybe_digest(self, servers, snapshot):
        """The summary on the crontab schedule set in the panel (server local time)."""
        schedule = self.config.get('digest', 'off')
        if schedule == 'off':
            self.state.pop('digest_minute', None)
            return
        fields = cron_fields(schedule)
        now = self.clock()
        minute = int(now // 60)
        last = self.state.get('digest_minute')
        self.state['digest_minute'] = minute
        if last is None:
            return                     # just switched on or first start: wait for the next scheduled minute
        # The loop can run a little late: look at every minute since the last check (at most three hours).
        if not any(cron_due(fields, time.localtime(m * 60)) for m in range(max(int(last) + 1, minute - 180), minute + 1)):
            return
        since = self.state.get('digest_at')
        self.state['digest_at'] = now
        before = self.state.get('digest_used')
        self.state['digest_used'] = {f"{s['interface']}/{c['name']}": int(c.get('used_bytes') or 0) for s, c in snapshot}
        lines = [self.t('dg_title', period=self.period_text(now - since) if since else '')]
        for s in servers:
            mine = [c for server, c in snapshot if server is s]
            online = sum(1 for c in mine if c.get('enabled') and int((c.get('stats') or {}).get('handshake') or 0) > now - 180)
            lines.append(self.t('dg_server', icon='🟢' if s.get('running') else '🔴', iface=s['interface'], clients=len(mine),
                                online=online, off=sum(1 for c in mine if not c.get('enabled'))))
        if before is None:
            lines.append(self.t('dg_first'))
        else:
            deltas = []
            for s, c in snapshot:
                used = int(c.get('used_bytes') or 0)
                earlier = int(before.get(f"{s['interface']}/{c['name']}", 0))
                deltas.append((used - earlier if used >= earlier else used, c['name'], s['interface']))   # a reset counter starts from zero
            lines.append(self.t('dg_traffic', total=human_size(sum(d for d, _, _ in deltas))))
            top = [row for row in sorted(deltas, reverse=True)[:5] if row[0] > 0]
            if top:
                lines.append(self.t('dg_top'))
                lines.extend(self.t('dg_top_row', name=name, iface=iface, used=human_size(delta)) for delta, name, iface in top)
        horizon = datetime.fromtimestamp(now, timezone.utc) + timedelta(days=7)
        expiring = [c['name'] for _, c in snapshot if c.get('enabled') and c.get('expires_at') and c['expires_at'][:10] <= horizon.date().isoformat()]
        idle = [c['name'] for _, c in snapshot if c.get('enabled') and 0 < int((c.get('stats') or {}).get('handshake') or 0) < now - 30 * 86400]
        for key, names in (('dg_expiring', expiring), ('dg_idle', idle)):
            if names:
                lines.append(self.t(key, names=', '.join(names[:10]) + (' …' if len(names) > 10 else '')))
        self.notify('\n'.join(lines))

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
        # Discovery always requires a subsequent explicit administrator choice in
        # the panel: being first to write to a public bot is not authorization.
        if mode == 'list-candidates':
            api.call('deleteWebhook')
            deadline, offset, found = time.time() + 25, None, {}
            while time.time() <= deadline and not found:
                updates=api.call('getUpdates',http_timeout=20,offset=offset,timeout=15,allowed_updates=['message']) or []
                for update in updates:
                    offset=int(update['update_id'])+1
                    message=update.get('message') or {}
                    sender=message.get('from') or {}
                    if (message.get('chat') or {}).get('type')=='private' and sender.get('id'):
                        name=' '.join(str(sender.get(k,'')) for k in ('first_name','last_name')).strip()
                        label=re.sub(r'[^\w .@-]','',f"{name} @{sender.get('username','')}")[:100]
                        found[str(int(sender['id']))]=label
            print(json.dumps([{'id':int(key),'label':value} for key,value in found.items()]))
            return 0
        # Backward-compatible console setup; it separately asks for confirmation.
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
    if len(sys.argv) == 2 and sys.argv[1] in ('check-token', 'find-admin', 'list-candidates', 'send-test'):
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
