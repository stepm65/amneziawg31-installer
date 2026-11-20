"""Bilingual charcoal/amber AWG 3.1 console. Unprivileged; localhost only."""
import contextvars
import copy
import hashlib
import hmac
import html
import io
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit

import awg31client
import re
from datetime import datetime, timezone

import qrcode
from amnezialink import build_vpn_uri
import quicinitial
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.exception_handlers import http_exception_handler
from starlette.middleware.sessions import SessionMiddleware

AUTH_FILE = Path(os.environ.get('AWG31_AUTH', '/etc/awg31-panel/auth.json'))
AUTH = json.loads(AUTH_FILE.read_text())
STYLESHEET = Path(__file__).with_name('panel.css')
SCRIPT = Path(__file__).with_name('panel.js')
FONT_DIR = Path(__file__).with_name('fonts')
_asset_versions = {}


def asset_version(name):
    """Cache-busting token derived from the file itself, so it is never stale."""
    path = Path(__file__).with_name(name)
    try:
        stamp = path.stat().st_mtime_ns
        cached = _asset_versions.get(name)
        if not cached or cached[0] != stamp:
            cached = (stamp, hashlib.sha256(path.read_bytes()).hexdigest()[:12])
            _asset_versions[name] = cached
        return cached[1]
    except OSError:
        return '0'
COOKIE_SECURE = os.environ.get('AWG31_COOKIE_SECURE', '1') == '1'
REPOSITORY = 'stepm65/amneziawg31-installer'
_latest = {'checked': 0.0, 'tag': '', 'busy': False}


def panel_version():
    """The installed release: VERSION next to web.py (installed) or at the project root (checkout)."""
    for path in (Path(__file__).with_name('VERSION'), Path(__file__).resolve().parent.parent / 'VERSION'):
        try:
            text = path.read_text(encoding='utf-8').strip()
        except OSError:
            continue
        if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', text):
            return text
    return ''


def _version_tuple(text):
    match = re.fullmatch(r'v?([0-9]+)\.([0-9]+)\.([0-9]+)', str(text or ''))
    return tuple(int(x) for x in match.groups()) if match else None


def _fetch_latest_release():
    import urllib.request
    try:
        request = urllib.request.Request(f'https://api.github.com/repos/{REPOSITORY}/releases/latest',
                                         headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'awg31-console'})
        with urllib.request.urlopen(request, timeout=8) as reply:
            tag = str(json.loads(reply.read(262144)).get('tag_name', ''))
        if _version_tuple(tag):
            _latest['tag'] = tag
    except Exception:
        pass                                   # offline, rate-limited or blocked: simply no hint
    finally:
        _latest['busy'] = False


def newer_release():
    """A newer published release, if one is known. GitHub is asked in the background at most twice a day;
    AWG31_UPDATE_CHECK=0 in the panel's unit switches the check off."""
    if os.environ.get('AWG31_UPDATE_CHECK', '1') == '0':
        return ''
    now = time.time()
    if now - _latest['checked'] > 12 * 3600 and not _latest['busy']:
        import threading
        _latest.update(checked=now, busy=True)
        threading.Thread(target=_fetch_latest_release, name='release-check', daemon=True).start()
    installed, latest = _version_tuple(panel_version()), _version_tuple(_latest['tag'])
    return _latest['tag'] if installed and latest and latest > installed else ''
app = FastAPI(title='AWG 3.1 Panel', docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=AUTH['session_key'],
                   session_cookie='awg31_session', max_age=3600,
                   same_site='strict', https_only=COOKIE_SECURE)
login_attempts = {}

TEXT = {
    'ru': {
        'server_instances':'Серверы и интерфейсы', 'new_server':'Создать сервер',
        'new_server_hint':'Каждый сервер использует отдельные ключи, подсеть, UDP-порт и список клиентов.',
        'server_name':'Интерфейс (например awg1)', 'server_subnet':'Подсеть IPv4',
        'server_uplink':'Внешний интерфейс', 'server_mode':'Маршрутизация',
        'server_switch':'Перейти', 'server_stop':'Остановить', 'server_start':'Запустить', 'server_remove':'Удалить сервер', 'server_remove_confirm':'Удалить сервер и всех клиентов? Конфигурация и база клиентов будут сохранены в резервной копии.',
        'advanced':'Параметры обфускации AWG 3.1', 'generate':'Сгенерировать параметры',
        'advanced_hint':'Изменение S/H и HeaderProtectionKey потребует переимпорта конфигураций всех клиентов этого сервера.',
        'new_server_note':'Создание второго сервера не изменяет awg0. Подсети и UDP-порты не должны пересекаться.',
        'server_create_failed':'Не удалось создать сервер',
        'dashboard': 'Управление сервером', 'clients': 'Клиенты', 'settings': 'Настройки сервера',
        'version_notes': 'Что нового в этой версии (GitHub)', 'version_available': 'Доступна {version}',
        'version_update_hint': 'Обновление: sudo awg31 update',
        'documentation': 'Документация', 'logout': 'Выход', 'sign_in': 'Вход администратора',
        'login': 'Войти', 'password': 'Пароль администратора', 'login_error': 'Неверный пароль',
        'login_intro':'Управляйте VPN-серверами, клиентами и безопасными подключениями в одной консоли.',
        'login_feature_servers':'Несколько независимых VPN-серверов',
        'login_feature_monitor':'Мониторинг подключений и трафика',
        'login_feature_backup':'Резервные копии и обслуживание',
        'login_card_title':'Доступ к консоли',
        'login_card_hint':'Введите пароль администратора, заданный при установке.',
        'login_limited': 'Слишком много попыток. Повторите позже.',
        'vpn_running': 'VPN запущен', 'vpn_stopped': 'VPN остановлен',
        'interface': 'Интерфейс', 'subnet': 'Подсеть', 'udp_port': 'UDP-порт',
        'mode': 'Режим', 'full': 'Весь IPv4 через VPN', 'split': 'Только VPN-подсеть',
        'endpoint': 'Endpoint', 'dns': 'DNS', 'ipv4_only': 'Только IPv4',
        'overview': 'Состояние VPN', 'vpn_ip': 'VPN-IP', 'name': 'Имя', 'status': 'Состояние',
        'traffic': 'Трафик', 'actions': 'Действия', 'active': 'Активен',
        'disabled': 'Отключён', 'never': 'Нет соединений', 'received': 'Получено',
        'sent': 'Отправлено', 'client_details': 'Конфигурация', 'disable': 'Отключить',
        'enable': 'Включить', 'delete': 'Удалить', 'no_clients': 'Пока нет клиентов',
        'no_clients_hint': 'Добавьте клиента, чтобы получить конфигурацию и QR-код.',
        'add_client': 'Добавить клиента', 'add_client_submit':'Добавить клиента', 'create': 'Создать',
        'client_name': 'Имя латиницей (до 32 символов)', 'client_placeholder': 'Например, laptop',
        'settings_hint': 'Изменение параметров может прервать подключения. Затем скачайте новые конфигурации клиентов.',
        'public_endpoint': 'Публичный IPv4 или DNS-имя', 'server_port': 'UDP-порт сервера',
        'mtu_label': 'MTU (576–1420)', 'client_dns': 'DNS клиентов (IPv4)',
        'save_restart': 'Сохранить и перезапустить VPN',
        'settings_note': 'Подсеть и режим маршрутизации не редактируются из веб-панели.',
        'back': 'На главную', 'download': 'Скачать .conf', 'qr': 'QR-код',
        'client': 'Клиент', 'config_notice': 'Конфигурация содержит приватный ключ. Не передавайте её посторонним.',
        'settings_saved': 'Настройки сохранены',
        'settings_saved_hint': 'VPN перезапущен. Экспортируйте клиентские конфигурации повторно.',
        'settings_error': 'Ошибка изменения', 'create_error': 'Ошибка создания',
        'not_available': 'Конфигурация недоступна', 'error': 'Ошибка',
        'auth_required': 'Требуется вход', 'csrf_error': 'CSRF: некорректный токен',
        'controller_error': 'Ошибка контроллера', 'controller_log': 'Ошибка контроллера: см. журнал службы',
        'confirm_delete': 'Удалить клиента? Действие нельзя отменить.', 'language': 'Язык интерфейса',
        'nav_overview': 'Обзор', 'nav_monitoring': 'Мониторинг',
        'top_subtitle': 'Подключение и состояние системы',
        'quick_stats': 'Сводка сервера', 'live_traffic': 'Трафик в реальном времени',
        'traffic_wait': 'Накопление измерений…', 'traffic_rx': 'Входящий', 'traffic_tx': 'Исходящий',
        'traffic_live': 'LIVE', 'connected': 'Подключено', 'total_clients': 'Всего клиентов',
        'total_transfer': 'Общий трафик', 'last_seen': 'Последний handshake',
        'no_recent': 'Нет подключений', 'search_clients': 'Поиск по имени или адресу…',
        'active_only': 'Активные', 'all_clients': 'Все клиенты', 'refresh': 'Обновить',
        'module_info': 'Модуль ядра', 'module_active': 'AWG 3.1 · IPv4',
        'client_help': 'Управляйте доступом и экспортируйте конфигурации',
        'settings_explain': 'Изменения сервера требуют перезапуска интерфейса',
        'refresh_time': 'Обновление каждые 4 секунды',
        'traffic_unavailable': 'Данные временно недоступны',
        'no_matching_clients': 'Клиенты не найдены',
        'confirm_restart': 'Применить настройки и перезапустить VPN? Активные соединения могут прерваться.',
        'cancel_action':'Отмена', 'confirm_action':'Подтвердить', 'select_all':'Выбрать всех', 'bulk_delete':'Удалить выбранных', 'selected_count':'Выбрано', 'bulk_delete_confirm':'Удалить выбранных клиентов? Действие нельзя отменить.',
    },
    'en': {
        'server_instances':'Servers and interfaces', 'new_server':'Create server',
        'new_server_hint':'Each server has independent keys, subnet, UDP port and clients.',
        'server_name':'Interface (e.g. awg1)', 'server_subnet':'IPv4 subnet',
        'server_uplink':'Uplink interface', 'server_mode':'Routing',
        'server_switch':'Open', 'server_stop':'Stop', 'server_start':'Start', 'server_remove':'Delete server', 'server_remove_confirm':'Delete server and all clients? Configuration and client database will be backed up.',
        'advanced':'AWG 3.1 obfuscation parameters', 'generate':'Generate parameters',
        'advanced_hint':'Changing S/H and HeaderProtectionKey requires clients on this server to re-import their configurations.',
        'new_server_note':'Creating another server does not change awg0. Subnets and UDP ports must be unique.',
        'server_create_failed':'Could not create server',
        'dashboard': 'Server overview', 'clients': 'Clients', 'settings': 'Server settings',
        'version_notes': 'What is new in this version (GitHub)', 'version_available': '{version} is available',
        'version_update_hint': 'To update: sudo awg31 update',
        'documentation': 'Documentation', 'logout': 'Log out', 'sign_in': 'Administrator sign in',
        'login': 'Sign in', 'password': 'Administrator password', 'login_error': 'Incorrect password',
        'login_intro':'Manage VPN servers, clients and secure connections from one console.',
        'login_feature_servers':'Multiple independent VPN servers',
        'login_feature_monitor':'Connections and traffic monitoring',
        'login_feature_backup':'Backups and maintenance',
        'login_card_title':'Console access',
        'login_card_hint':'Enter the administrator password set during installation.',
        'login_limited': 'Too many attempts. Try again later.',
        'vpn_running': 'VPN running', 'vpn_stopped': 'VPN stopped',
        'interface': 'Interface', 'subnet': 'Subnet', 'udp_port': 'UDP port',
        'mode': 'Mode', 'full': 'Route all IPv4 through VPN', 'split': 'VPN subnet only',
        'endpoint': 'Endpoint', 'dns': 'DNS', 'ipv4_only': 'IPv4 only',
        'overview': 'VPN overview', 'vpn_ip': 'VPN IP', 'name': 'Name', 'status': 'Status',
        'traffic': 'Traffic', 'actions': 'Actions', 'active': 'Enabled',
        'disabled': 'Disabled', 'never': 'No handshake yet', 'received': 'Received',
        'sent': 'Sent', 'client_details': 'Configuration', 'disable': 'Disable',
        'enable': 'Enable', 'delete': 'Delete', 'no_clients': 'No clients yet',
        'no_clients_hint': 'Add a client to create its configuration and QR code.',
        'add_client': 'Add client', 'add_client_submit':'Add client', 'create': 'Create',
        'client_name': 'Client name (Latin letters, max. 32)', 'client_placeholder': 'For example, laptop',
        'settings_hint': 'Changes may interrupt connections. Download updated client configurations afterwards.',
        'public_endpoint': 'Public IPv4 address or DNS name', 'server_port': 'Server UDP port',
        'mtu_label': 'MTU (576–1420)', 'client_dns': 'Client DNS (IPv4)',
        'save_restart': 'Save and restart VPN',
        'settings_note': 'Subnet and routing mode cannot be changed in the web panel.',
        'back': 'Back to overview', 'download': 'Download .conf', 'qr': 'QR code',
        'client': 'Client', 'config_notice': 'This configuration contains a private key. Keep it confidential.',
        'settings_saved': 'Settings saved',
        'settings_saved_hint': 'VPN restarted. Export updated client configurations.',
        'settings_error': 'Settings update failed', 'create_error': 'Client creation failed',
        'not_available': 'Configuration unavailable', 'error': 'Error',
        'auth_required': 'Sign-in required', 'csrf_error': 'CSRF: invalid token',
        'controller_error': 'Controller error', 'controller_log': 'Controller error: check service logs',
        'confirm_delete': 'Delete client? This cannot be undone.', 'language': 'Interface language',
        'nav_overview': 'Overview', 'nav_monitoring': 'Monitoring',
        'top_subtitle': 'Connection and system status',
        'quick_stats': 'Server summary', 'live_traffic': 'Live traffic',
        'traffic_wait': 'Collecting samples…', 'traffic_rx': 'Inbound', 'traffic_tx': 'Outbound',
        'traffic_live': 'LIVE', 'connected': 'Connected', 'total_clients': 'Total clients',
        'total_transfer': 'Total traffic', 'last_seen': 'Last handshake',
        'no_recent': 'No connections yet', 'search_clients': 'Search name or IP…',
        'active_only': 'Enabled', 'all_clients': 'All clients', 'refresh': 'Refresh',
        'module_info': 'Kernel module', 'module_active': 'AWG 3.1 · IPv4',
        'client_help': 'Manage access and export configurations',
        'settings_explain': 'Changing server settings requires an interface restart',
        'refresh_time': 'Updates every 4 seconds',
        'traffic_unavailable': 'Traffic data temporarily unavailable',
        'no_matching_clients': 'No matching clients',
        'confirm_restart': 'Apply settings and restart VPN? Active connections may be interrupted.',
        'cancel_action':'Cancel', 'confirm_action':'Confirm', 'select_all':'Select all', 'bulk_delete':'Delete selected', 'selected_count':'Selected', 'bulk_delete_confirm':'Permanently delete selected clients?',
    },
}


# Dedicated server-aware navigation and backup administration.
TEXT['ru'].update({
    'all_servers':'Все серверы', 'server_context':'Текущий экземпляр',
    'selected_server':'Сервер', 'server_home':'Информация о сервере',
    'server_clients':'Клиенты сервера', 'server_settings':'Настройки сервера',
    'server_monitor':'Трафик и история', 'open_server':'Открыть сервер',
    'global_overview':'Обзор инфраструктуры', 'global_description':'Все экземпляры VPN, состояние системы и общие показатели.',
    'total_servers':'Всего серверов', 'running_servers':'Работают', 'kernel_status':'Ядро Linux',
    'kernel_awg':'Модуль AWG', 'system_status':'Состояние системы',
    'backup_delete':'Удалить', 'backup_delete_confirm':'Удалить эту резервную копию без возможности восстановления?',
    'backup_select':'Выберите архив', 'backup_check':'Проверить архив',
    'backup_policy_title':'Автоматическое резервное копирование',
    'backup_frequency':'Расписание', 'backup_off':'Выключено', 'backup_daily':'Каждый день',
    'backup_weekly':'Раз в неделю', 'backup_hour':'Час (UTC)', 'backup_minute':'Минуты (UTC)',
    'backup_weekday':'День недели', 'backup_keep_days':'Срок хранения (дней)',
    'backup_keep_count':'Максимальное количество архивов', 'backup_policy_save':'Сохранить расписание',
    'backup_policy_note':'Архивы создаёт системный таймер, даже если панель закрыта. Время — UTC. Устаревшие копии автоматически удаляются после успешного создания.',
    'backup_global_note':'Резервная копия включает ВСЕ AWG-серверы, их конфигурации и пользователей панели.',
    'backup_age':'Дата создания (UTC)', 'backup_check_good':'Целостность архива подтверждена',
    'global_maintenance':'Обслуживание всей системы', 'server_picker':'Выбор экземпляра',
    'nav_scope_global':'ИНФРАСТРУКТУРА', 'nav_scope_server':'ТЕКУЩИЙ СЕРВЕР',
})
TEXT['en'].update({
    'all_servers':'All servers', 'server_context':'Current instance',
    'selected_server':'Server', 'server_home':'Server overview',
    'server_clients':'Server clients', 'server_settings':'Server settings',
    'server_monitor':'Traffic & history', 'open_server':'Open server',
    'global_overview':'Infrastructure overview', 'global_description':'All VPN instances, system health and key indicators.',
    'total_servers':'Servers', 'running_servers':'Running', 'kernel_status':'Linux kernel',
    'kernel_awg':'AWG module', 'system_status':'System health',
    'backup_delete':'Delete', 'backup_delete_confirm':'Permanently delete this backup?',
    'backup_select':'Choose an archive', 'backup_check':'Verify backup',
    'backup_policy_title':'Automatic backups',
    'backup_frequency':'Schedule', 'backup_off':'Disabled', 'backup_daily':'Daily',
    'backup_weekly':'Weekly', 'backup_hour':'Hour (UTC)', 'backup_minute':'Minute (UTC)',
    'backup_weekday':'Day of week', 'backup_keep_days':'Retention (days)',
    'backup_keep_count':'Maximum backup count', 'backup_policy_save':'Save schedule',
    'backup_policy_note':'A systemd timer creates backups even when the browser is closed. Times use UTC. Old backups are pruned after successful backup.',
    'backup_global_note':'A full archive includes ALL AWG servers, their configs and panel credentials.',
    'backup_age':'Created (UTC)', 'backup_check_good':'Backup checksum validation passed',
    'global_maintenance':'System-wide maintenance', 'server_picker':'Select server',
    'nav_scope_global':'INFRASTRUCTURE', 'nav_scope_server':'SELECTED SERVER',
})

# Operations/maintenance translations; all UI strings remain self-hosted.
TEXT['ru'].update({
    'policy':'Политика доступа', 'comment':'Комментарий', 'expires':'Дата отключения (UTC)',
    'quota':'Лимит трафика (ГиБ; 0 = без лимита)', 'usage':'Использовано',
    'telegram_id':'Telegram ID владельца', 'telegram_id_hint':'Числовой ID. Этот человек увидит состояние клиента в Telegram-боте (только просмотр). Пусто — никто.',
    'owner_export':'Владелец может получить конфигурацию и QR-код в Telegram-боте',
    'save_policy':'Сохранить ограничения', 'history':'История трафика',
    'history_note':'Данные собираются системным таймером раз в минуту, даже когда панель закрыта.',
    'maintenance':'Обслуживание и безопасность', 'diagnostics':'Диагностика системы',
    'kernel_check':'Проверка модуля DKMS после обновления ядра',
    'backup':'Резервные копии', 'backup_make':'Создать полную резервную копию',
    'backup_secret':'Архив содержит приватные ключи и данные администратора. Храните его в безопасном месте.',
    'backup_download':'Скачать архив', 'backup_restore':'Восстановить', 'restore_warn':'Восстановление заменит настройки, клиентов и ключи из резервной копии, перезапустит VPN и панель. Текущий пароль администратора сохранится. Текущие данные будут сохранены в аварийной копии.', 'restore_confirm':'Введите ВОССТАНОВИТЬ для подтверждения', 'restore_sent':'Восстановление запланировано. Соединение с панелью временно прервётся. Следите за журналом systemd.', 'profile':'Профиль сервера',
    'profile_download':'Экспорт профиля JSON', 'profile_import':'Импортировать профиль',
    'profile_note':'Импорт изменит параметры сервера и перезапустит интерфейс. Приватные ключи не заменяются.',
    'profile_content':'JSON-профиль', 'password_change':'Сменить пароль администратора',
    'password_old':'Текущий пароль', 'password_new':'Новый пароль (от 12 символов)',
    'password_confirm':'Повторите новый пароль', 'password_mismatch':'Пароли не совпадают',
    'audit':'Журнал действий', 'audit_empty':'Записей пока нет',
    'policy_note':'Ограничения проверяются каждую минуту. Лимит учитывает трафик RX+TX, накопленный после обновления.',
    'history_empty':'Нет сохранённой истории; проверьте awg31-sampler.timer.',
    'confirm_import':'Импортировать профиль и перезапустить этот VPN-сервер?',
    'backup_ready':'Резервная копия создана', 'maintenance_error':'Ошибка обслуживания',
})
TEXT['en'].update({
    'policy':'Access policy', 'comment':'Comment', 'expires':'Expiry date (UTC)',
    'quota':'Traffic quota (GiB; 0 = unlimited)', 'usage':'Used',
    'telegram_id':'Owner’s Telegram ID', 'telegram_id_hint':'Numeric ID. This person sees the state of the client in the Telegram bot (read only). Empty: nobody.',
    'owner_export':'The owner may get the configuration and QR code from the Telegram bot',
    'save_policy':'Save access limits', 'history':'Traffic history',
    'history_note':'Samples are collected by a systemd timer each minute, even when the panel is closed.',
    'maintenance':'Maintenance and security', 'diagnostics':'System diagnostics',
    'kernel_check':'DKMS module check after a kernel update',
    'backup':'Backups', 'backup_make':'Create full backup',
    'backup_secret':'Backups contain private keys and administrator credentials. Store them securely.',
    'backup_download':'Download archive', 'backup_restore':'Restore', 'restore_warn':'Restoration replaces settings, clients and keys from the backup and restarts the VPN and panel. The current administrator password is kept. Current data will be snapshotted first.', 'restore_confirm':'Type RESTORE to confirm', 'restore_sent':'Restore job scheduled. The panel may disconnect temporarily. Monitor systemd logs.', 'profile':'Server profile',
    'profile_download':'Export JSON profile', 'profile_import':'Import profile',
    'profile_note':'Importing restarts the selected VPN interface. Private keys are not replaced.',
    'profile_content':'JSON profile', 'password_change':'Change administrator password',
    'password_old':'Current password', 'password_new':'New password (12+ characters)',
    'password_confirm':'Repeat new password', 'password_mismatch':'Passwords do not match',
    'audit':'Audit log', 'audit_empty':'No audit entries yet',
    'policy_note':'Policies are checked every minute. RX+TX quota counts traffic since upgrading.',
    'history_empty':'No historical samples yet; check awg31-sampler.timer.',
    'confirm_import':'Import this profile and restart the selected VPN interface?',
    'backup_ready':'Backup created', 'maintenance_error':'Maintenance error',
})

# New peer routing / CPS labels. Kept in both locales and without CDN resources.
TEXT['ru'].update({
    'peer_routes':'Подсети и адреса за клиентом (IPv4/CIDR)',
    'peer_routes_hint':'По одной сети на строку или через запятую. Сети прописываются на СЕРВЕРЕ (AllowedIPs этого клиента и маршрут), в конфигурации самого клиента их нет и быть не должно: это его собственные сети. В режиме split они добавляются в конфигурации остальных клиентов — их нужно скачать заново. Например: 192.168.50.0/24 и 172.20.10.5/32.',
    'c2c_label':'Связь клиентов между собой', 'c2c_on':'Разрешена: клиенты видят друг друга по VPN-адресам',
    'c2c_off':'Запрещена: клиенты изолированы друг от друга',
    'c2c_hint':'«Запрещена» изолирует клиентов этого сервера друг от друга и от клиентов других серверов awgN. Сети за клиентом (site-to-site) работают в обоих случаях.',
    'private_label':'Доступ клиентов к частным сетям сервера',
    'private_on':'Разрешён: клиенты видят локальную сеть, в которой стоит сервер',
    'private_off':'Запрещён: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 за сервером закрыты',
    'private_hint':'Сервис метаданных облака (169.254.0.0/16) закрыт для клиентов всегда.',
    'ipv6_label':'IPv6 у клиентов',
    'ipv6_off':'Не трогать: IPv6 клиента идёт мимо VPN',
    'ipv6_on':'Блокировать: ::/0 направляется в туннель и отбрасывается',
    'ipv6_hint':'После изменения клиентам нужна новая конфигурация. Проверьте на своих приложениях: некоторые клиенты требуют IPv6-адрес.',
    'config_stale':'Нужна новая конфигурация',
    'config_stale_hint':'Настройки изменились после того, как этому клиенту выдали файл, QR или ссылку.',
    'peer_routes_short':'Сети за клиентом',
    'cps_enabled':'Использовать I1–I5 для этого клиента',
    'cps_hint':'Опциональные CPS-пакеты, отправляемые клиентом перед handshake. По умолчанию выключены для совместимости QR и приложений. Если включить и оставить поля пустыми, I1 будет создан автоматически (случайные байты).',
    'cps_preset':'Готовый шаблон для I1', 'cps_preset_apply':'Подставить в I1',
    'cps_generate':'Сгенерировать', 'cps_generate_failed':'Не удалось сгенерировать значение.',
    'cps_preset_random':'Случайные байты (нейтрально)',
    'cps_preset_dns':'DNS-запрос (A-запись популярного домена)',
    'cps_preset_stun':'STUN Binding Request (как у звонков WebRTC)',
    'cps_preset_quictls':'QUIC Initial с настоящим ClientHello и SNI (1200 байт)',
    'cps_preset_quic':'QUIC Initial — только форма, случайное содержимое (короткая запись)',
    'cps_host':'Домен для SNI (шаблон QUIC с ClientHello)',
    'cps_host_hint':'Выберите сайт, который в вашей сети открывается по HTTP/3 и не блокируется.',
    'cps_preset_note':'Короткая запись не значит маленький пакет: <r 1000> — это 1000 случайных байт в сети. Шаблон «QUIC с ClientHello» даёт пакет, который расшифровывается как настоящий QUIC и содержит выбранный SNI; он записывается длинной hex-строкой, одинаков при каждом подключении и не помещается в QR — передавайте клиенту файл .conf. Шаблоны не гарантируют обход блокировок: проверяйте на своей сети. Кнопка у поля подставляет случайные байты.',
    'server_remove_type':'Введите имя сервера для удаления',
    'obf_static_warning':'У этого сервера стоят статические параметры H1–H4 = 1, 2, 3, 4 — такие же заголовки, как у обычного WireGuard, и одинаковые на всех установках. Нажмите «Сгенерировать параметры», сохраните и заново раздайте конфигурации клиентам.',
    'cps_label':'Дополнительные пакеты I1–I5 (опционально)',
    'cps_example':'Например: <r 48>',
    'peer_network_settings':'Маршруты и имитация трафика клиента',
    'save_client_network':'Сохранить параметры клиента',
    'client_network_saved':'Параметры клиента сохранены',
    'client_network_changed':'После изменения VPN-адреса, I1–I5 или дополнительных строк заново импортируйте .conf на клиенте. Дополнительные маршруты требуют IPv4 forwarding и корректных обратных маршрутов на самом клиенте и за ним.',
    'routes_apply_warning':'Будут применены изменения адреса клиента и маршрутов на сервере. Активное VPN-соединение может прерваться.',
    'qr_warning':'Большой I-профиль может создать слишком плотный QR; используйте .conf при необходимости.',
})
TEXT['en'].update({
    'peer_routes':'Networks or hosts behind this client (IPv4 CIDR)',
    'peer_routes_hint':'One CIDR per line or comma-separated. The networks are set on the SERVER (this client’s AllowedIPs and a route); they are not in this client’s own configuration and should not be: they are its own networks. In split mode they are added to the other clients’ configurations, which must be downloaded again. Examples: 192.168.50.0/24 and 172.20.10.5/32.',
    'c2c_label':'Traffic between clients', 'c2c_on':'Allowed: clients reach each other by VPN address',
    'c2c_off':'Blocked: clients are isolated from each other',
    'c2c_hint':'“Blocked” isolates this server’s clients from each other and from clients of the other awgN servers. Networks behind a client (site-to-site) work either way.',
    'private_label':'Client access to the server’s private networks',
    'private_on':'Allowed: clients reach the local network the server sits in',
    'private_off':'Blocked: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 behind the server are closed',
    'private_hint':'The cloud metadata service (169.254.0.0/16) is always closed to clients.',
    'ipv6_label':'Client IPv6',
    'ipv6_off':'Leave alone: client IPv6 bypasses the VPN',
    'ipv6_on':'Block: ::/0 is routed into the tunnel and dropped',
    'ipv6_hint':'Clients need a new configuration after a change. Test with your apps: some clients require an IPv6 address.',
    'config_stale':'Needs a new configuration',
    'config_stale_hint':'Settings changed after this client was given the file, QR code or link.',
    'peer_routes_short':'Behind-client networks',
    'cps_enabled':'Enable I1–I5 for this client',
    'cps_hint':'Optional client-originated CPS packets sent before handshake. Disabled by default for easier QR/app compatibility. If you enable this and leave the fields empty, I1 is created automatically (random bytes).',
    'cps_preset':'Ready-made template for I1', 'cps_preset_apply':'Fill I1',
    'cps_generate':'Generate', 'cps_generate_failed':'Unable to generate a value.',
    'cps_preset_random':'Random bytes (neutral)',
    'cps_preset_dns':'DNS query (A record of a popular domain)',
    'cps_preset_stun':'STUN Binding Request (as used by WebRTC calls)',
    'cps_preset_quictls':'QUIC Initial with a genuine ClientHello and SNI (1200 bytes)',
    'cps_preset_quic':'QUIC Initial — shape only, random payload (short notation)',
    'cps_host':'Server name for SNI (QUIC template with ClientHello)',
    'cps_host_hint':'Pick a site that opens over HTTP/3 on your network and is not blocked.',
    'cps_preset_note':'Short notation does not mean a small packet: <r 1000> is 1000 random bytes on the wire. The “QUIC with ClientHello” template produces a packet that decrypts as genuine QUIC and carries the chosen SNI; it is written as a long hex string, is identical on every connection and does not fit into a QR code, so hand the client the .conf file. Templates do not guarantee that blocking is bypassed: test on your own network. The button next to a field inserts random bytes.',
    'server_remove_type':'Type the server name to delete it',
    'obf_static_warning':'This server uses the static values H1–H4 = 1, 2, 3, 4: the same headers as plain WireGuard and identical on every installation. Press “Generate parameters”, save, and hand out the client configurations again.',
    'cps_label':'Additional I1–I5 packets (optional)',
    'cps_example':'For example: <r 48>',
    'peer_network_settings':'Client routing and traffic imitation',
    'save_client_network':'Save client settings',
    'client_network_saved':'Client settings saved',
    'client_network_changed':'Re-import the client .conf after changing its VPN address, I1–I5 or the extra lines. Behind-client networks also require IPv4 forwarding and return routes on the client and its LAN.',
    'routes_apply_warning':'The client address and server routes will be updated. Active VPN connections may be interrupted.',
    'qr_warning':'Long I1–I5 settings can make QR codes too dense; use .conf if scanning fails.',
})

TEXT['ru'].update({
    'share_config': 'Экспорт конфигурации', 'share_conf_tab': 'Файл .conf',
    'share_link_tab': 'AmneziaVPN Link', 'copy': 'Скопировать',
    'copy_ok': 'Скопировано', 'copy_failed': 'Не удалось скопировать. Выделите текст вручную.',
    'save_qr': 'Сохранить QR', 'save_vpn': 'Скачать .vpn',
    'vpn_link_note': 'Нативная ссылка vpn:// для приложения AmneziaVPN. Совместимость с разными версиями приложения проверяется отдельно.',
    'conf_qr_note': 'Отсканируйте QR в совместимом клиенте AmneziaWG. Для AmneziaVPN используйте соседнюю вкладку.',
    'link_unavailable': 'AmneziaVPN Link недоступна для этой конфигурации. Используйте .conf.',
    'sensitive_data': 'В конфигурации и ссылке содержится приватный ключ. Не передавайте их посторонним.',
    'client_options': 'Адреса и дополнительные параметры клиента', 'close_window': 'Закрыть',
    'qr_overflow': 'QR слишком велик. Содержимое .conf доступно ниже для просмотра и копирования.',
    'conf_contents':'Содержимое файла .conf',
    'show_conf_contents':'Показывать конфигурацию',
    'peer_address':'Основной VPN-адрес клиента',
    'peer_address_hint':'Укажите свободный IPv4-адрес внутри VPN-подсети. После сохранения выдайте клиенту новый .conf.',
})
TEXT['en'].update({
    'share_config': 'Export configuration', 'share_conf_tab': '.conf file',
    'share_link_tab': 'AmneziaVPN Link', 'copy': 'Copy',
    'copy_ok': 'Copied', 'copy_failed': 'Unable to copy. Select the text manually.',
    'save_qr': 'Save QR', 'save_vpn': 'Download .vpn',
    'vpn_link_note': 'Native vpn:// URI for the AmneziaVPN app. Compatibility with individual app releases still needs to be tested.',
    'conf_qr_note': 'Scan the QR with a compatible AmneziaWG client. Use the other tab for AmneziaVPN.',
    'link_unavailable': 'AmneziaVPN Link unavailable for this configuration. Use .conf.',
    'sensitive_data': 'The config and link contain a private key. Keep them confidential.',
    'client_options': 'Client addresses and advanced options', 'close_window': 'Close',
    'qr_overflow': 'The QR is too large. The .conf contents are available below to view and copy.',
    'conf_contents':'Contents of the .conf file',
    'show_conf_contents':'Show configuration',
    'peer_address':'Client VPN address',
    'peer_address_hint':'Enter an unused IPv4 address inside the VPN subnet. Give the client a new .conf after saving.',
})


# Layout and maintenance navigation labels.
TEXT['ru'].update({
    'nav_group_workspace':'РАБОЧЕЕ ПРОСТРАНСТВО',
    'nav_group_config':'КОНФИГУРАЦИЯ',
    'nav_group_system':'СИСТЕМА',
    'nav_servers_short':'Серверы',
    'nav_maintenance_short':'Обслуживание',
    'nav_vpn_settings':'Настройки VPN',
    'nav_toggle':'Открыть меню',
    'nav_close':'Закрыть меню',
    'nav_collapse':'Свернуть меню',
    'nav_expand':'Развернуть меню',
    'maint_diagnostics':'Диагностика',
    'maint_backups':'Резервные копии',
    'maint_restore':'Восстановление',
    'maint_profiles':'Профили сервера',
    'maint_security':'Безопасность',
    'maint_audit':'Журнал действий',
    'maint_system':'Система',
    'maint_choose':'Разделы обслуживания',
    'maint_diagnostics_hint':'Состояние ядра, модуля и служб VPN. Результаты получены непосредственно с сервера.',
    'maint_healthy':'В порядке',
    'maint_attention':'Требует внимания',
    'maint_checks_passed':'Проверок пройдено',
    'maint_checked_at':'Проверено',
    'maint_details':'Технические сведения',
    'maint_refresh':'Проверить ещё раз',
    'maint_backup_count':'Доступные архивы',
    'maint_no_backups':'Резервных копий пока нет',
    'maint_backups_hint':'Архив содержит конфигурации, базы и приватные ключи. Скачивайте его только в доверенном окружении.',
    'maint_restore_hint':'Выберите сохранённый архив. Перед восстановлением содержимое проверяется, а текущее состояние сохраняется в аварийной копии.',
    'maint_restore_empty':'Сначала создайте резервную копию во вкладке «Резервные копии».',
    'maint_profile_hint':'Переносите параметры выбранного VPN-сервера без замены его приватного ключа.',
    'maint_security_hint':'Обновите пароль администратора. После смены пароля действующие сессии станут недействительными.',
    'maint_audit_hint':'История административных действий. Приватные ключи и пароли в журнал не записываются.',
    'maint_system_hint':'Техническое обслуживание выполняется из локального терминала с правами администратора.',
    'maint_system_kernel':'Проверка модуля после обновления ядра',
    'maint_system_cmds':'Команды обслуживания',
    'maint_system_hint_vpn':'Команды не перезапускают VPN-интерфейс без отдельного действия.',
    'maint_backup_name':'Архив',
    'maint_backup_size':'Размер',
    'maint_backup_actions':'Действия',
    'maint_restore_warning_short':'Восстановление прервёт VPN-подключения. Предварительная проверка выполняется автоматически.',
    'maint_missing':'Нет данных',
    'maint_kern':'Ядро Linux',
    'maint_mod_installed':'Модуль AWG · установлен',
    'maint_mod_loaded':'Модуль AWG · загружен',
    'maint_dkms':'DKMS',
    'maint_device':'VPN-интерфейс',
    'maint_forward':'IPv4 Forwarding',
    'maint_service':'VPN-служба',
    'maint_secureboot':'Secure Boot',
    'maint_panel':'Веб-панель',
    'maint_conn':'Сервис',
    'maint_status_enabled':'Включено',
    'maint_status_disabled':'Отключено',
    'maint_status_active':'Активен',
    'maint_diag_summary':'Состояние компонентов',
    'maint_unknown':'Неизвестно',
    'maint_page_subtitle':'Диагностика, резервные копии и управление доступом'
})
TEXT['en'].update({
    'nav_group_workspace':'WORKSPACE',
    'nav_group_config':'CONFIGURATION',
    'nav_group_system':'SYSTEM',
    'nav_servers_short':'Servers',
    'nav_maintenance_short':'Maintenance',
    'nav_vpn_settings':'VPN settings',
    'nav_toggle':'Open menu',
    'nav_close':'Close menu',
    'nav_collapse':'Collapse menu',
    'nav_expand':'Expand menu',
    'maint_diagnostics':'Diagnostics',
    'maint_backups':'Backups',
    'maint_restore':'Restore',
    'maint_profiles':'Server profiles',
    'maint_security':'Security',
    'maint_audit':'Audit log',
    'maint_system':'System',
    'maint_choose':'Maintenance sections',
    'maint_diagnostics_hint':'Kernel, module and VPN service health. Results are read directly from the server.',
    'maint_healthy':'Healthy',
    'maint_attention':'Needs attention',
    'maint_checks_passed':'Checks passed',
    'maint_checked_at':'Checked',
    'maint_details':'Technical details',
    'maint_refresh':'Run checks again',
    'maint_backup_count':'Available archives',
    'maint_no_backups':'No backups yet',
    'maint_backups_hint':'Archives contain configuration, databases and private keys. Download only to a trusted environment.',
    'maint_restore_hint':'Select an existing backup. Its contents are verified and a safety snapshot is created before restoration.',
    'maint_restore_empty':'Create a backup first in the Backups section.',
    'maint_profile_hint':'Transfer settings of the selected VPN server without replacing its private key.',
    'maint_security_hint':'Change the administrator password. Existing sessions will be invalidated.',
    'maint_audit_hint':'Administrative activity history. Private keys and passwords are not written to the log.',
    'maint_system_hint':'Maintenance commands run from the local terminal as an administrator.',
    'maint_system_kernel':'Kernel module check after an update',
    'maint_system_cmds':'Maintenance commands',
    'maint_system_hint_vpn':'These commands do not restart the VPN interface without an explicit action.',
    'maint_backup_name':'Backup',
    'maint_backup_size':'Size',
    'maint_backup_actions':'Actions',
    'maint_restore_warning_short':'Restoration interrupts VPN connections. Archive validation runs automatically.',
    'maint_missing':'No data',
    'maint_kern':'Linux kernel',
    'maint_mod_installed':'AWG module · installed',
    'maint_mod_loaded':'AWG module · loaded',
    'maint_dkms':'DKMS',
    'maint_device':'VPN interface',
    'maint_forward':'IPv4 forwarding',
    'maint_service':'VPN service',
    'maint_secureboot':'Secure Boot',
    'maint_panel':'Web panel',
    'maint_conn':'Service',
    'maint_status_enabled':'Enabled',
    'maint_status_disabled':'Disabled',
    'maint_status_active':'Active',
    'maint_diag_summary':'Component health',
    'maint_unknown':'Unknown',
    'maint_page_subtitle':'Diagnostics, backups and access controls'
})

# Translate expected validation errors from the privileged controller; unfamiliar errors
# remain escaped and visible for debugging (no controller functionality is changed).
KNOWN_ERRORS = {
    'en': {
        'Поддерживаются IPv4-сети с маской /24…/29': 'Only IPv4 subnets /24 through /29 are supported',
        'Недопустимая VPN-сеть': 'Invalid VPN subnet',
        'IPv6 endpoint не поддерживается': 'IPv6 endpoints are not supported',
        'Нужен IPv4 или DNS-имя (без порта)': 'Enter an IPv4 address or a DNS name (without port)',
        'DNS должен быть IPv4': 'DNS must be an IPv4 address',
        'Порт 1…65535': 'Port must be 1–65535',
        'MTU должен быть 576…1420': 'MTU must be 576–1420',
        'Пустой JSON запрос': 'Empty JSON request',
        'Нужен JSON объект': 'A JSON object is required',
        'Имя: латиница, цифры, -, _; до 32 символов': 'Name: Latin letters, numbers, - and _, up to 32 characters',
        'Свободных адресов нет': 'No available IP addresses',
        'Неверное имя клиента': 'Invalid client name',
        'Адрес клиента должен быть IPv4': 'Client address must be IPv4',
        'Адрес должен быть свободным хостом в VPN-подсети': 'Address must be an unused host inside the VPN subnet',
        'Адрес зарезервирован сервером': 'Address is reserved for the server',
        'Адрес уже назначен другому клиенту': 'Address is already assigned to another client',
        'Клиент не найден': 'Client not found',
        'Клиент отключён': 'Client is disabled',
        'Сервер не инициализирован': 'Server is not initialized',
        'Неподдерживаемая команда': 'Unsupported command',
    }
}

ICONS = {
    'home': '<path d="m3 10 9-7 9 7v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1z"/>',
    'users': '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
    'settings': '<path d="M4 7h9m4 0h3M4 17h3m4 0h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    'server': '<rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
    'network': '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v6M5 17v-4h14v4"/>',
    'radio': '<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4m-8.4 0a6 6 0 0 1 0-8.4m11.2-2.8a10 10 0 0 1 0 14M5 19a10 10 0 0 1 0-14"/>',
    'layers': '<path d="m12 2 9 5-9 5-9-5 9-5Zm-9 10 9 5 9-5M3 17l9 5 9-5"/>',
    'shield': '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z"/><path d="m9 12 2 2 4-4"/>',
    'globe': '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
    'plus': '<path d="M12 5v14M5 12h14"/>',
    'file': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h8"/>',
    'pause': '<path d="M9 5v14M15 5v14"/>',
    'play': '<path d="m8 5 11 7-11 7z"/>',
    'trash': '<path d="M3 6h18m-2 0-1 14H6L5 6m4 0V4h6v2M10 10v6M14 10v6"/>',
    'restart': '<path d="M20 7v5h-5"/><path d="M20 12a8 8 0 1 0-2.3 5.7"/>',
    'logout': '<path d="M10 17l5-5-5-5M15 12H3"/><path d="M12 3h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7"/>',
    'lock': '<rect x="4" y="10" width="16" height="12" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    'activity': '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
    'search': '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    'clock': '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    'calendar': '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18"/>',
    'info': '<circle cx="12" cy="12" r="10"/><path d="M12 11v6M12 7h.01"/>',
    'check': '<path d="m5 12 4 4L19 6"/>',
    'arrow': '<path d="M5 12h14m-6-6 6 6-6 6"/>',
    'menu': '<path d="M4 7h16M4 12h16M4 17h16"/>',
    'chevron-left': '<path d="m15 18-6-6 6-6"/>',
    'chevron-right': '<path d="m9 18 6-6-6-6"/>',
    'download': '<path d="M12 3v12m-4-4 4 4 4-4M4 17v4h16v-4"/>',
    'logs': '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/>',
    'tag': '<path d="M3 12V4a1 1 0 0 1 1-1h8l9 9-9 9z"/><circle cx="7.5" cy="7.5" r="1.5"/>',
    'arrow-up': '<path d="M12 19V5M5 12l7-7 7 7"/>',
    'archive': '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v12h14V9M10 14h4"/>',
    'alert': '<path d="M12 3 2 21h20L12 3zM12 9v5M12 18h.01"/>',
    'more': '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
    'terminal': '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 4 3-4 3m6 0h4"/>',
    'key': '<circle cx="8" cy="15" r="4"/><path d="m11 12 10-10m-5 5 3 3"/>',
    'list': '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    'bell': '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
    'send': '<path d="M22 2 11 13M22 2l-7 20-4-9-9-4z"/>',
    'eye': '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    'cpu': '<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6v6H9zM9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4"/>',
    'hard-drive': '<rect x="2" y="7" width="20" height="11" rx="2"/><path d="M6 14h.01M10 14h.01"/>',
    'route': '<circle cx="5" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><path d="M5 8v7a3 3 0 0 0 3 3h9M19 16V9a3 3 0 0 0-3-3H9"/>',
    'x': '<path d="M18 6L6 18M6 6l12 12"/>',

}


def icon(name, size=20):
    path = ICONS.get(name, ICONS['info'])
    return (f'<svg class="icon" width="{size}" height="{size}" viewBox="0 0 24 24" '
            'fill="none" stroke="currentColor" stroke-width="1.8" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            f'{path}</svg>')


def h(value):
    return html.escape(str(value), quote=True)


def lang_of(request):
    value = request.cookies.get('awg31_lang', 'ru')
    return value if value in TEXT else 'ru'


def tr(lang, key):
    return TEXT[lang].get(key, key)


def controller_message(lang, message):
    return KNOWN_ERRORS.get(lang, {}).get(str(message), str(message))


# Operations that only read. Within one request their answers are reused: a page
# that needs the server list three times asks the controller once. A change made
# in the same request forgets everything read so far.
NOTIFY_GROUPS = ('server', 'clients', 'security', 'backups')
# The Telegram notification cards: (group, icon, events). Same keys as awg31bot.EVENTS.
TG_EVENT_GROUPS = (
    ('server', 'server', ('server_state', 'module', 'kernel', 'panel')),
    ('clients', 'users', ('client_auto', 'client_expiring', 'client_quota')),
    ('security', 'shield', ('login', 'login_failed', 'password', 'owner_export')),
    ('backups', 'archive', ('backup_created', 'backup_failed', 'upload_failed')),
    ('system', 'cpu', ('cpu', 'memory', 'disk')),
)
TG_THRESHOLD_EVENTS = ('cpu', 'memory', 'disk')
TG_SCHEDULES = (('0 * * * *', 'tg_s_hourly'), ('0 */6 * * *', 'tg_s_6h'), ('0 */12 * * *', 'tg_s_12h'),
                ('0 9 * * *', 'tg_s_daily9'), ('0 21 * * *', 'tg_s_daily21'), ('0 9 * * 1', 'tg_s_weekly'))
READ_ONLY_OPS = frozenset({'servers', 'list', 'status', 'diagnostics', 'history', 'host-history', 'backup-list',
                           'backup-policy', 'backup-encryption', 'backup-remote', 'telegram-status', 'audit-list',
                           'audit-search', 'logging-status', 'logs-read', 'sessions'})
_REQUEST_CACHE = contextvars.ContextVar('awg31_ctl_cache', default=None)


def ctl(command, data=None):
    cache = _REQUEST_CACHE.get()
    key = None
    if cache is not None:
        if command in READ_ONLY_OPS:
            key = (command, json.dumps(data, sort_keys=True))
            if key in cache:
                return copy.deepcopy(cache[key])
        else:
            cache.clear()
    result = _ctl_call(command, data)
    if key is not None:
        cache[key] = copy.deepcopy(result)
    return result


def _ctl_call(command, data=None):
    timeout = 200 if command == 'telegram-connect' else \
        90 if command in ('server-create','backup-create','backup-export','backup-restore','backup-check') else 35
    try:
        code, stdout, stderr = awg31client.call(command, json.dumps(data) if data is not None else None, timeout)
    except (OSError, ConnectionError) as exc:
        print(f'awg31mgr {command}: control helper failed: {exc}', file=sys.stderr, flush=True)
        raise RuntimeError('Ошибка контроллера: см. журнал службы') from None
    if code:
        try:
            msg = json.loads(stderr).get('error', 'Ошибка контроллера')
        except ValueError:
            msg = 'Ошибка контроллера: см. журнал службы'
            # The message points at the journal, so the reason has to be there.
            print(f'awg31mgr {command} failed ({code}): {stderr.strip()[-600:]}', file=sys.stderr, flush=True)
        raise RuntimeError(str(msg)[:300])
    return json.loads(stdout)


class ControllerCache:
    """ASGI middleware: one fresh cache of read-only controller answers per HTTP request."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        token = _REQUEST_CACHE.set({})
        try:
            await self.app(scope, receive, send)
        finally:
            _REQUEST_CACHE.reset(token)


app.add_middleware(ControllerCache)


SERVER_RE = re.compile(r'^awg(?:0|[1-9][0-9]?)$')
OBF_EDIT_FIELDS = ('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4',
                   'HeaderProtectionKey','ContentPaddingAddition','RandomTrailers',
                   'DisableCookies','RekeyAfterTime','RekeyTimeout','RejectAfterTime',
                   'KeepaliveTimeout','MaxHandshakeAttempts')


def selected_server(request):
    # URL path takes priority over legacy cookie, preventing cross-tab confusion.
    explicit = request.path_params.get('interface')
    if explicit is not None:
        if not SERVER_RE.fullmatch(explicit): raise HTTPException(404)
        return explicit
    value = request.cookies.get('awg31_server','awg0')
    # awg0 can be deleted; a stale cookie must never hide remaining servers.
    available = [item['interface'] for item in server_list()
                 if SERVER_RE.fullmatch(item.get('interface',''))]
    return value if SERVER_RE.fullmatch(value) and value in available else (available[0] if available else 'awg0')


def scoped_prefix(request):
    interface = request.path_params.get('interface')
    if interface is not None:
        if not SERVER_RE.fullmatch(interface): raise HTTPException(404)
        return f'/servers/{interface}'
    return ''


def scoped_client(request, name):
    prefix = scoped_prefix(request)
    return f'{prefix}/clients/{quote(name, safe="")}' if prefix else f'/client/{quote(name, safe="")}'


def scope_content(request, content):
    prefix = scoped_prefix(request)
    if not prefix: return content
    # Only rewrite URLs in HTML attributes, never textareas containing private
    # client configs, user-supplied comments or other literal configuration.
    def route_attr(match):
        attr, path = match.groups()
        if path.startswith('/client/'):
            path = prefix + '/clients/' + path[len('/client/'):]
        elif path == '/client':
            path = prefix + '/clients'
        elif path == '/settings':
            path = prefix + '/settings'
        elif path == '/#clients':
            path = prefix + '/clients'
        return attr + path + '"'
    return re.sub(r'((?:href|src|action)=")(/(?:client(?:/[^" ]*)?|settings|#clients))"', route_attr, content)


def control(request, command, data=None):
    payload = dict(data or {})
    payload['interface'] = selected_server(request)
    return ctl(command, payload)


def server_list():
    return ctl('servers',{}).get('servers', [])


def read_auth():
    return json.loads(AUTH_FILE.read_text())


def logged(request):
    try:
        current=read_auth()
        return request.session.get('authenticated') is True and request.session.get('auth_version','') == current.get('auth_version','')
    except (OSError,ValueError):
        return False


def audit_event(event,target=''):
    # Audit errors must not undo an already-applied VPN operation.
    try: ctl('audit',{'event':event,'target':target})
    except (RuntimeError,ValueError): pass


def require_auth(request):
    if not logged(request):
        raise HTTPException(status_code=401, detail=tr(lang_of(request), 'auth_required'))


def safe_next(value, fallback='/'):
    value = str(value or '')
    parsed = urlsplit(value)
    if (parsed.scheme or parsed.netloc or not parsed.path.startswith('/') or
            parsed.path.startswith('//') or any(ord(char) < 32 for char in value)):
        return fallback
    return parsed.path + (f'?{parsed.query}' if parsed.query else '')


def login_redirect(request, next_path=''):
    if not next_path and request.method in ('GET', 'HEAD'):
        next_path = request.url.path + (f'?{request.url.query}' if request.url.query else '')
    return '/login?next=' + quote(safe_next(next_path), safe='')


@app.exception_handler(HTTPException)
async def panel_http_exception(request: Request, exc: HTTPException):
    path = request.url.path
    is_api = path.startswith('/api/') or '/api/' in path
    if exc.status_code == 401 and not is_api:
        next_path = ''
        if request.method not in ('GET', 'HEAD'):
            try:
                next_path = (await request.form()).get('next', '')
            except (RuntimeError, ValueError):
                pass
        return RedirectResponse(login_redirect(request, next_path), status_code=303)
    return await http_exception_handler(request, exc)


def require_csrf(request, token):
    require_auth(request)
    if not hmac.compare_digest(str(token), str(request.session.get('csrf', ''))):
        raise HTTPException(status_code=403, detail=tr(lang_of(request), 'csrf_error'))


def csrf(request):
    next_path = request.url.path + (f'?{request.url.query}' if request.url.query else '')
    return (f'<input type="hidden" name="csrf" value="{h(request.session.get("csrf", ""))}">'
            f'<input type="hidden" name="next" value="{h(next_path)}">')


def language_picker(request):
    selected = lang_of(request)
    current = request.url.path
    if not current.startswith('/') or current.startswith('//'):
        current = '/'
    return (f'<nav class="language-picker" aria-label="{h(tr(selected,"language"))}">'
            + ''.join(f'<a class="{"selected" if selected == lang else ""}" '
                      f'href="/lang/{lang}?next={quote(current, safe="")}" '
                      f'aria-current="{"true" if selected == lang else "false"}">{lang.upper()}</a>'
                      for lang in ('ru', 'en')) + '</nav>')


def page(title, content, request):
    lang = lang_of(request)
    authenticated = logged(request)
    path = request.url.path
    is_maintenance = path.startswith('/maintenance')

    scoped = scoped_prefix(request) if authenticated else ''
    context = selected_server(request) if authenticated else 'awg0'
    section = request.path_params.get('section', 'overview')
    if '/clients/' in path: section = 'clients'
    if '/settings/' in path: section = 'settings'
    if path.startswith('/maintenance'): section = 'maintenance'
    if path == '/servers': section = 'servers'
    if path == '/': section = 'overview'

    def version_block():
        # Shown to signed-in administrators only, at the foot of the sidebar (as in 3x-ui).
        version = panel_version()
        if not version:
            return ''
        newer = newer_release()
        update = (f'<a class="sidebar-update" href="https://github.com/{REPOSITORY}/releases/tag/{h(newer)}" target="_blank" '
                  f'rel="noopener noreferrer" title="{h(t("version_update_hint"))}">{icon("arrow-up",14)}'
                  f'<span>{h(t("version_available").format(version=newer))}</span></a>') if newer else ''
        return (f'<div class="sidebar-version{" has-update" if newer else ""}">{update}'
                f'<a class="sidebar-version-link" href="https://github.com/{REPOSITORY}/releases/tag/v{h(version)}" target="_blank" '
                f'rel="noopener noreferrer" title="{h(t("version_notes"))}">{icon("tag",15)}<span>v{h(version)}</span></a></div>')
    def nav_link(label, href, icon_name, nav_key):
        active = ((href == '/' and path == '/') or (href == '/servers' and path == '/servers')
                  or (nav_key == 'maintenance' and path.startswith('/maintenance')))
        return (f'<a class="side-link{" side-active" if active else ""}" href="{h(href)}" '
                f'data-nav-key="{h(nav_key)}" title="{h(label)}"'
                f'{" aria-current=page" if active else ""}>'
                f'{icon(icon_name,19)}<span class="side-link-label">{h(label)}</span></a>')

    sidebar = ''
    nav_overlay = ''
    nav_toggle = ''
    server_tabs = ''
    active_metadata = None
    if authenticated:
        t = lambda key: tr(lang,key)
        nav_toggle = (f'<button type="button" id="mobile-nav-toggle" class="icon-btn mobile-menu-toggle" '
                      f'aria-label="{h(t("nav_toggle"))}" aria-expanded="false" '
                      f'aria-controls="app-sidebar">{icon("menu",22)}</button>')
        available = server_list()
        for server in available:
            if server.get('interface') == context:
                active_metadata = server
                break
        top_links=(nav_link(t('nav_overview'), '/', 'home','overview')+
                   nav_link(t('all_servers'), '/servers', 'server', 'servers'))
        server_links=''.join(
            f'<a class="instance-nav-link{" instance-current" if scoped.startswith("/servers/"+item["interface"]) else ""}" '
            f'href="/servers/{h(item["interface"])}/overview" '
            f'aria-label="{h(item["interface"])} — {h(item.get("subnet",""))}" '
            f'{"aria-current=location" if scoped.startswith("/servers/"+item["interface"]) else ""}>'
            f'<span class="instance-nav-status {"is-up" if item.get("running") else "is-down"}"></span>'
            f'<span class="instance-nav-text"><strong>{h(item["interface"])}</strong>'
            f'<small>{h(item.get("subnet",""))}</small></span>'
            f'<span class="instance-nav-chevron">{icon("chevron-right",16)}</span></a>'
            for item in available if SERVER_RE.fullmatch(item.get('interface','')))
        sidebar = f'''<aside class="sidebar" id="app-sidebar" aria-label="{h(t('dashboard'))}">
          <div class="sidebar-header"><span class="sidebar-nav-caption">AWG CONSOLE</span>
          <button type="button" id="sidebar-collapse" class="sidebar-collapse" aria-expanded="true"
            aria-label="{h(t('nav_collapse'))}" title="{h(t('nav_collapse'))}">{icon('chevron-left',18)}</button>
          <button type="button" class="sidebar-mobile-close" id="sidebar-mobile-close"
            aria-label="{h(t('nav_close'))}">{icon('chevron-left',18)}</button></div>
          <nav class="sidebar-navigation" aria-label="{h(t('dashboard'))}">
            <div class="nav-group"><div class="nav-group-label">{h(t('nav_scope_global'))}</div>{top_links}</div>
            <div class="nav-group nav-server-group"><div class="nav-group-label">{h('ЭКЗЕМПЛЯРЫ' if lang=='ru' else 'INSTANCES')}
              <span class="instance-count">{len(available)}</span></div>
              <div class="instance-nav-list">{server_links}</div></div>
            <div class="nav-group"><div class="nav-group-label">{h(t('nav_group_system'))}</div>
              {nav_link(t('nav_maintenance_short'),'/maintenance?tab=diagnostics','settings','maintenance')}</div>
          </nav>{version_block()}</aside>'''
        nav_overlay = '<button type="button" class="nav-scrim" id="nav-scrim" aria-label="'+h(t('nav_close'))+'" tabindex="-1"></button>'
        if scoped and active_metadata:
            active_section = section if section in ('overview','clients','monitoring','settings') else 'clients'
            section_labels = [('overview','Обзор','Overview'),('clients','Клиенты','Clients'),
                              ('monitoring','Трафик','Traffic'),('settings','Настройки','Settings')]
            server_tabs = '<nav class="server-tabs" aria-label="'+h(t('nav_scope_server'))+'">'+''.join(
                f'<a class="server-tab{" active" if key==active_section else ""}" '
                f'href="/servers/{h(context)}/{key}" '
                f'{"aria-current=page" if key==active_section else ""}>'
                f'{h(ru if lang=="ru" else en)}</a>' for key,ru,en in section_labels)+'</nav>'
    subtitle = (f'{active_metadata.get("subnet","")}  ·  UDP {active_metadata.get("port","")}'
                if scoped and active_metadata else
                (tr(lang,'maint_page_subtitle') if is_maintenance else ''))
    status_link = (f'<a class="top-link" href="/logout" title="{h(tr(lang,"logout"))}">{icon("logout",18)}<span>{h(tr(lang,"logout"))}</span></a>'
                   if authenticated else '')
    refresh_button = (f'<button class="icon-btn" id="refresh-page" type="button" aria-label="{h(tr(lang,"refresh"))}" title="{h(tr(lang,"refresh"))}">{icon("restart",18)}</button>'
                      if authenticated else '')
    login_intro = '' if authenticated else f'''<div class="login-overview">
      <p class="login-lede">{h(tr(lang,'login_intro'))}</p>
      <div class="login-features">
        <div>{icon('server',18)}<span>{h(tr(lang,'login_feature_servers'))}</span></div>
        <div>{icon('activity',18)}<span>{h(tr(lang,'login_feature_monitor'))}</span></div>
        <div>{icon('shield',18)}<span>{h(tr(lang,'login_feature_backup'))}</span></div>
      </div></div>'''
    body = f'''<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <link rel="icon" href="data:,">
    <title>{h(title)} — AmneziaWG 3.1</title>
    <link rel="stylesheet" href="/assets/panel.css?v={asset_version('panel.css')}">
    <link rel="stylesheet" href="/assets/md3.css?v={asset_version('md3.css')}">
    <script defer src="/assets/panel.js?v={asset_version('panel.js')}"></script>
    </head><body data-server-scope="{h(scoped)}">
    <header class="topbar"><div class="topbar-left">{nav_toggle}<a href="/" class="brand"><span class="brand-emblem">{icon('shield',18)}</span><span>AmneziaWG <b>3.1</b></span></a></div>
    <div class="topbar-right">{language_picker(request)}{refresh_button}{status_link}</div></header>
    {nav_overlay}<div class="shell {'shell-auth' if not authenticated else ''}">{sidebar}<main class="main {'main-login' if not authenticated else ''}">
    <div class="page-heading"><div><div class="eyebrow">{h((('СЕРВЕРЫ / ' if lang=='ru' else 'SERVERS / ')+context.upper()) if scoped else ('AWG CONSOLE / SYSTEM' if is_maintenance else 'AWG CONSOLE'))}</div>
    <h1>{h(title)}</h1>{f'<p class="heading-subtitle">{h(subtitle)}</p>' if subtitle else ''}{login_intro}</div></div>
    {server_tabs}{scope_content(request, content)}</main></div></body></html>'''
    return HTMLResponse(body, headers={
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; style-src 'self'; script-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        'Referrer-Policy': 'no-referrer',
        'X-Frame-Options': 'DENY',
    })


@app.get('/assets/panel.css')
def stylesheet():
    return Response(STYLESHEET.read_text(encoding='utf-8'), media_type='text/css',
                    headers={'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff'})


@app.get('/assets/md3.css')
def material_theme():
    return Response((Path(__file__).with_name('md3.css')).read_text(encoding='utf-8'),
                    media_type='text/css', headers={'Cache-Control':'public, max-age=3600',
                                                     'X-Content-Type-Options':'nosniff'})


@app.get('/assets/fonts/{name}')
def font_file(name: str):
    # Self-hosted OFL fonts only; the name is matched against real files, never joined blindly.
    if not re.fullmatch(r'[a-z0-9-]{1,64}\.woff2', name):
        raise HTTPException(404)
    path = FONT_DIR / name
    if path.is_symlink() or not path.is_file():
        raise HTTPException(404)
    return Response(path.read_bytes(), media_type='font/woff2',
                    headers={'Cache-Control': 'public, max-age=2592000', 'X-Content-Type-Options': 'nosniff'})


@app.get('/assets/panel.js')
def javascript():
    return Response(SCRIPT.read_text(encoding='utf-8'), media_type='text/javascript',
                    headers={'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff'})


@app.get('/api/traffic')
@app.get('/servers/{interface}/api/traffic')
def traffic(request: Request, interface: str = ''):
    require_auth(request)
    # Only aggregate counters and enabled/connected client counts. Never send
    # private keys, PSKs, configs or privileged controller metadata to JS.
    try:
        state = control(request,'list')
    except RuntimeError:
        raise HTTPException(status_code=503, detail=tr(lang_of(request), 'traffic_unavailable'))
    clients = state.get('clients', [])
    rx = sum(int(c.get('stats', {}).get('received', 0)) for c in clients)
    tx = sum(int(c.get('stats', {}).get('sent', 0)) for c in clients)
    recent = sum(1 for c in clients if c.get('enabled') and
                 int(c.get('stats', {}).get('handshake', 0)) > time.time() - 180)
    return Response(json.dumps({'rx': rx, 'tx': tx, 'connected': recent,
                                'clients': len(clients), 'running': bool(state.get('running'))}),
                    media_type='application/json', headers={'Cache-Control': 'no-store'})


def _linux_socket_counts():
    """Count active TCP connections and UDP sockets without using netstat/ss."""
    tcp = udp = 0
    for protocol in ('tcp', 'tcp6', 'udp', 'udp6'):
        try:
            lines = (Path('/proc/net') / protocol).read_text().splitlines()[1:]
        except OSError:
            continue  # IPv6 may be disabled in this kernel.
        for line in lines:
            fields = line.split()
            if len(fields) < 4: continue
            if protocol.startswith('tcp'):
                tcp += int(fields[3] == '01')  # ESTABLISHED, not LISTEN.
            else:
                udp += 1  # UDP is connectionless; report sockets, not connections.
    return {'tcp_established':tcp,'udp_sockets':udp}


def _default_uplink():
    """Select the lowest-metric IPv4 default route; never double-count awgN."""
    try:
        rows = Path('/proc/net/route').read_text().splitlines()[1:]
        candidates = []
        for row in rows:
            cols=row.split()
            if len(cols)<8: continue
            iface,dest,flags=cols[0],cols[1],int(cols[3],16)
            if dest=='00000000' and flags & 1 and not iface.startswith(('awg','tun','wg','lo')):
                candidates.append((int(cols[6]),iface))
        return min(candidates)[1] if candidates else None
    except (OSError,ValueError,IndexError):
        return None


def _proc_telemetry():
    """Host-only resource counters. Each unavailable metric remains null."""
    result = {'cpu_total':None,'cpu_idle':None,'cpu_count':os.cpu_count(),
              'mem_total':None,'mem_available':None,'swap_total':None,'swap_free':None,
              'disk_total':None,'disk_free':None,'uptime':None,'panel_rss':None,
              'uplink':None,'wan_rx':None,'wan_tx':None,'tcp_established':None,'udp_sockets':None}
    try:
        cpu = Path('/proc/stat').read_text().splitlines()[0].split()
        counters = [int(v) for v in cpu[1:]]
        result['cpu_total'] = sum(counters)
        result['cpu_idle'] = counters[3] + counters[4]
    except (OSError, ValueError, IndexError): pass
    try:
        memory = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, _, raw = line.partition(':')
            if key in ('MemTotal','MemAvailable','SwapTotal','SwapFree'):
                memory[key] = int(raw.strip().split()[0])*1024
        for target,key in (('mem_total','MemTotal'),('mem_available','MemAvailable'),
                           ('swap_total','SwapTotal'),('swap_free','SwapFree')):
            result[target]=memory.get(key)
    except (OSError, ValueError, IndexError): pass
    try:
        fs=os.statvfs('/')
        result['disk_total']=fs.f_blocks*fs.f_frsize
        result['disk_free']=fs.f_bavail*fs.f_frsize
    except OSError: pass
    try: result['uptime'] = int(float(Path('/proc/uptime').read_text().split()[0]))
    except (OSError, ValueError, IndexError): pass
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                result['panel_rss']=int(line.split()[1])*1024
                break
    except (OSError,ValueError,IndexError): pass
    result.update(_linux_socket_counts())
    uplink=_default_uplink()
    if uplink and re.fullmatch(r'[a-zA-Z0-9_.:-]{1,32}',uplink):
        stats=Path('/sys/class/net')/uplink/'statistics'
        try:
            result['wan_rx']=int((stats/'rx_bytes').read_text())
            result['wan_tx']=int((stats/'tx_bytes').read_text())
            result['uplink']=uplink
        except (OSError,ValueError): pass
    return result


def _interface_uptime(name):
    """Read systemd activation time; no extra privileges, do not guess."""
    if not SERVER_RE.fullmatch(name):return None
    try:
        proc=subprocess.run(['systemctl','show',f'awg-quick@{name}.service',
                             '--property=ActiveEnterTimestampMonotonic','--value'],
                             capture_output=True,text=True,timeout=2,check=False)
        microseconds=int(proc.stdout.strip()) if proc.returncode==0 else 0
        elapsed=time.monotonic()-microseconds/1_000_000
        return int(elapsed) if microseconds>0 and elapsed>=0 else None
    except (ValueError,OSError,subprocess.TimeoutExpired):return None


@app.get('/api/overview/telemetry')
def fleet_telemetry(request: Request):
    require_auth(request)
    instances=[]
    total_rx=total_tx=total_connected=0
    for server in server_list():
        name=server.get('interface','')
        if not SERVER_RE.fullmatch(name):continue
        stats={'interface':name,'running':bool(server.get('running')),
               'clients':int(server.get('clients',0)),'rx':None,'tx':None,
               'connected':None,'recorded_bytes':None,'uptime':None}
        try:
            detail=ctl('list',{'interface':name})
            clients=detail.get('clients',[])
            stats['rx']=sum(max(0,int((c.get('stats') or {}).get('received') or 0)) for c in clients)
            stats['tx']=sum(max(0,int((c.get('stats') or {}).get('sent') or 0)) for c in clients)
            stats['recorded_bytes']=sum(max(0,int(c.get('used_bytes') or 0)) for c in clients)
            stats['connected']=sum(int(bool(c.get('enabled') and
                int((c.get('stats') or {}).get('handshake') or 0)>time.time()-180)) for c in clients)
            stats['clients']=len(clients)
            total_rx+=stats['rx'];total_tx+=stats['tx'];total_connected+=stats['connected']
        except (RuntimeError,ValueError,TypeError,KeyError):
            # A stopped/unavailable peer must not blank all other servers.
            pass
        if stats['running']:stats['uptime']=_interface_uptime(name)
        instances.append(stats)
    return Response(json.dumps({'rx':total_rx,'tx':total_tx,'connected':total_connected,
                                'instances':instances,**_proc_telemetry()}),
                    media_type='application/json',headers={'Cache-Control':'no-store'})


@app.get('/api/overview/series')
def overview_series(request:Request,window:str='15m'):
    require_auth(request)
    if window not in ('5m','15m','1h'):raise HTTPException(422,'Invalid window')
    series=[]
    for server in server_list():
        name=server.get('interface','')
        if not SERVER_RE.fullmatch(name):continue
        try:
            history=ctl('history',{'interface':name,'window':window})
            points=[{'ts':int(p['ts']),'rx':max(0,int(p['rx'])),
                     'tx':max(0,int(p['tx']))} for p in history.get('points',[]) if isinstance(p,dict)]
            series.append({'interface':name,'points':points})
        except (ValueError,KeyError,TypeError,RuntimeError):
            series.append({'interface':name,'points':[]})
    try: host=ctl('host-history',{'window':window}).get('points',[])
    except (RuntimeError,KeyError,ValueError,TypeError):host=[]
    return Response(json.dumps({'window':window,'bucket_seconds':60,'series':series,'host':host}),
                    media_type='application/json',headers={'Cache-Control':'no-store'})


@app.get('/api/obfuscation/generate')
@app.get('/servers/{interface}/api/obfuscation/generate')
def obfuscation_generate(request: Request, interface: str = '', timing_ranges: bool = False):
    require_auth(request)
    try:
        params = ctl('obfuscation-generate', {})
    except RuntimeError:
        raise HTTPException(status_code=503, detail='Generator unavailable') from None
    params = {key: value for key, value in params.items() if value != ''}
    if timing_ranges:
        params.update({'RekeyAfterTime':'112-118', 'RekeyTimeout':'4-6',
                       'RejectAfterTime':'176-184', 'KeepaliveTimeout':'9-11',
                       'MaxHandshakeAttempts':'8-12'})
    return Response(json.dumps(params),media_type='application/json',
                    headers={'Cache-Control':'no-store'})

CPS_PRESETS = ('random', 'dns', 'stun', 'quictls', 'quic')
CPS_SNI_SUGGESTIONS = ('www.google.com', 'www.cloudflare.com', 'www.youtube.com', 'yandex.ru', 'vk.com')
CPS_DNS_NAMES = ('www.google.com', 'www.cloudflare.com', 'www.microsoft.com', 'www.apple.com',
                 'www.wikipedia.org', 'www.github.com')


def cps_value(preset='random', host=''):
    """Build one I-packet expression accepted by awg31ctl.validate_i_fields.

    Only the framing is fixed; identifiers and payload stay random on every send.
    """
    if preset == 'dns':
        # RFC 1035 query: random ID, RD flag, one question, QTYPE=A, QCLASS=IN.
        labels = secrets.choice(CPS_DNS_NAMES).split('.')
        qname = b''.join(bytes([len(part)]) + part.encode('ascii') for part in labels) + b'\x00'
        return '<r 2><b 0x01000001000000000000' + qname.hex() + '00010001>'
    if preset == 'stun':
        # RFC 5389 Binding Request: type, zero length, magic cookie, 96-bit transaction ID.
        return '<b 0x000100002112a442><r 12>'
    if preset == 'quictls':
        # A complete QUIC v1 Initial with a TLS 1.3 ClientHello for `host`: unlike
        # the shape-only template below, it survives decryption by a middlebox.
        return '<b 0x' + quicinitial.build_initial(host or CPS_SNI_SUGGESTIONS[0]).hex() + '>'
    if preset == 'quic':
        # RFC 9000 long header of an Initial packet padded to 1200 bytes:
        # flags, version 1, 8-byte DCID, empty SCID and token, 2-byte length.
        return '<b 0xc30000000108><r 8><b 0x0000449e><r 1000><r 182>'
    return f'<r {secrets.randbelow(80) + 40}>'


@app.get('/api/cps/generate')
def cps_generate(request: Request, preset: str = 'random', host: str = ''):
    require_auth(request)
    if preset not in CPS_PRESETS:
        raise HTTPException(422, 'Invalid preset')
    try:
        value = cps_value(preset, host)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return Response(json.dumps({'preset': preset, 'value': value}),
                    media_type='application/json', headers={'Cache-Control': 'no-store'})


# Extra [Interface] lines: awg-quick on a router, a container or a Linux gateway.
# The templates stay generic: the LAN interface is found when the tunnel comes up.
EXTRA_TEMPLATES = (
    # awg-quick runs every hook as (eval "$hook") under set -e -o pipefail: any
    # failing step, even an expected one, tears the whole tunnel down again.
    ('gateway', (
        'PostUp = iptables -t nat -A POSTROUTING -o %i -j MASQUERADE',
        'PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE || true',
        'PostUp = iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu',
        'PostDown = iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true',
        'Table = 200',
        'PostUp = dev=$(ip -o -4 route show default | awk \'{print $5; exit}\' || true); '
        '[ -n "$dev" ] || dev=$(ip -o link show | awk -F\': \' \'$2 != "lo" && $2 !~ /^%i/ {sub(/@.*/, "", $2); print $2; exit}\' || true); '
        'ip rule del priority 300 2>/dev/null || true; ip rule add priority 300 iif "$dev" lookup 200 || true',
        'PostDown = ip rule del priority 300 2>/dev/null || true',
    )),
    ('mss', (
        'PostUp = iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu',
        'PostDown = iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true',
    )),
    ('nat', (
        'PostUp = iptables -t nat -A POSTROUTING -o %i -j MASQUERADE',
        'PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE || true',
    )),
)


def extra_template_text(key, t):
    lines = dict(EXTRA_TEMPLATES)[key]
    return '\n'.join((f'# {t("extra_tpl_" + key + "_comment")}', *lines))


def extra_lines_block(prefix, value, t):
    """Textarea with the «Insert a template ▾» menu (variant B chosen by the author)."""
    field = f'{prefix}-extra-lines'
    items = ''.join(
        f'<button type="button" class="extra-menu-item" role="menuitem" data-extra-target="{field}" '
        f'data-extra-text="{h(extra_template_text(key, t))}"><strong>{h(t("extra_tpl_" + key))}</strong>'
        f'<small>{h(t("extra_tpl_" + key + "_hint"))}</small></button>'
        for key, _ in EXTRA_TEMPLATES)
    return (f'<div class="extra-lines" data-extra-lines>'
            f'<div class="extra-lines-head"><label for="{field}"><strong>{h(t("extra_title"))}</strong></label>'
            f'<details class="extra-menu"><summary class="btn btn-secondary btn-small">{icon("plus",15)}{h(t("extra_insert"))}'
            f'<span class="extra-caret" aria-hidden="true">▾</span></summary>'
            f'<div class="extra-menu-list" role="menu">{items}</div></details></div>'
            f'<textarea id="{field}" name="extra_lines" class="extra-text" rows="{min(14, value.count(chr(10)) + 2) if value else 3}" spellcheck="false" '
            f'autocomplete="off" maxlength="4096" placeholder="PostUp = …">{h(value)}</textarea>'
            f'<small>{h(t("extra_hint"))}</small></div>')


TEXT['ru'].update({
    'extra_title': 'Дополнительные строки [Interface]',
    'extra_insert': 'Вставить шаблон',
    'extra_hint': 'Для клиентов, которые сами поднимают туннель через awg-quick: роутер, контейнер, Linux-шлюз. '
                  'Допустимы PreUp, PostUp, PreDown, PostDown, Table и комментарии с #. Строки попадают в .conf, его QR и в бота, '
                  'но не в ссылку vpn:// — приложения AmneziaVPN команды не выполняют. Команды выполняются на клиенте, не на сервере.',
    'extra_tpl_gateway': 'Шлюз для локальной сети',
    'extra_tpl_gateway_hint': 'NAT, clamp MSS и маршрут из LAN в туннель. Интерфейс LAN находится сам — подходит для MikroTik, OpenWrt, Docker, Linux.',
    'extra_tpl_gateway_comment': 'Шлюз для локальной сети: трафик из LAN уходит в туннель',
    'extra_tpl_mss': 'Только clamp MSS',
    'extra_tpl_mss_hint': 'Подгонка размера TCP-пакетов под MTU туннеля, если сайты открываются не полностью. Уже входит в «Шлюз».',
    'extra_tpl_mss_comment': 'Clamp MSS: TCP-пакеты подгоняются под MTU туннеля',
    'extra_tpl_nat': 'Только NAT',
    'extra_tpl_nat_hint': 'Маскарадинг трафика, который уходит в туннель. Уже входит в «Шлюз».',
    'extra_tpl_nat_comment': 'NAT: трафик за клиентом выходит с его адреса в туннеле',
    'extra_badge': 'доп. строки', 'extra_badge_hint': 'В конфигурации есть дополнительные строки [Interface]',
    'extra_bulk': 'Доп. строки', 'extra_bulk_title': 'Дополнительные строки для выбранных',
    'extra_bulk_hint': 'Одни и те же строки [Interface] для всех отмеченных клиентов. После сохранения им нужно заново скачать .conf.',
    'extra_mode_replace': 'Заменить строки клиентов', 'extra_mode_append': 'Добавить к уже заданным',
    'extra_mode_hint': 'Пустое поле с «Заменить» удаляет дополнительные строки у выбранных.',
    'extra_bulk_save': 'Применить к выбранным',
})
TEXT['en'].update({
    'extra_title': 'Extra [Interface] lines',
    'extra_insert': 'Insert a template',
    'extra_hint': 'For clients that bring the tunnel up with awg-quick themselves: a router, a container, a Linux gateway. '
                  'PreUp, PostUp, PreDown, PostDown, Table and # comments are allowed. The lines go into the .conf, its QR code and the bot, '
                  'but not into the vpn:// link: AmneziaVPN apps do not run commands. Commands run on the client, never on the server.',
    'extra_tpl_gateway': 'Gateway for a local network',
    'extra_tpl_gateway_hint': 'NAT, MSS clamping and a route from the LAN into the tunnel. Finds the LAN interface itself: MikroTik, OpenWrt, Docker, Linux.',
    'extra_tpl_gateway_comment': 'Gateway for a local network: LAN traffic goes into the tunnel',
    'extra_tpl_mss': 'MSS clamping only',
    'extra_tpl_mss_hint': 'Fits TCP packets to the tunnel MTU when pages load only partly. Already part of the gateway.',
    'extra_tpl_mss_comment': 'MSS clamping: TCP packets fit the tunnel MTU',
    'extra_tpl_nat': 'NAT only',
    'extra_tpl_nat_hint': 'Masquerades the traffic that goes into the tunnel. Already part of the gateway.',
    'extra_tpl_nat_comment': 'NAT: traffic behind the client leaves with its tunnel address',
    'extra_badge': 'extra lines', 'extra_badge_hint': 'The configuration has extra [Interface] lines',
    'extra_bulk': 'Extra lines', 'extra_bulk_title': 'Extra lines for the selected clients',
    'extra_bulk_hint': 'The same [Interface] lines for every selected client. They need to download the .conf again afterwards.',
    'extra_mode_replace': 'Replace the clients’ lines', 'extra_mode_append': 'Add to the lines they have',
    'extra_mode_hint': 'An empty field with “Replace” removes the extra lines from the selected clients.',
    'extra_bulk_save': 'Apply to the selected',
})


def cps_block(prefix, values, checked, lang, extra=''):
    """I1–I5 editor shared by the new-client and client-detail forms."""
    t = lambda key: tr(lang, key)
    fields = ''.join(
        f'<div class="field cps-field"><div class="cps-field-head"><label for="{prefix}-i{x}">I{x}</label>'
        f'<button type="button" class="btn btn-secondary btn-small" data-cps-generate="{prefix}-i{x}">'
        f'{icon("restart",14)}{h(t("cps_generate"))}</button></div>'
        f'<textarea id="{prefix}-i{x}" name="i{x}" rows="{3 if x==1 else 2}" maxlength="16384" '
        f'spellcheck="false" autocapitalize="off" autocomplete="off" '
        f'placeholder="&lt;r 48&gt;">{h(values.get(f"i{x}",""))}</textarea></div>'
        for x in range(1, 6))
    options = ''.join(f'<option value="{name}">{h(t("cps_preset_"+name))}</option>' for name in CPS_PRESETS)
    return f'''<details class="cps-box" data-cps data-cps-error="{h(t('cps_generate_failed'))}"><summary>{h(t('cps_label'))}</summary>
          <label class="check-field"><input type="checkbox" name="i_enabled" value="1"{' checked' if checked else ''} data-cps-enabled><span>{h(t('cps_enabled'))}</span></label>
          <p class="info-line">{h(t('cps_hint'))}</p>{extra}
          <div class="cps-preset"><label class="field" for="{prefix}-cps-preset"><span>{h(t('cps_preset'))}</span>
          <select id="{prefix}-cps-preset" data-cps-preset>{options}</select></label>
          <label class="field" for="{prefix}-cps-host"><span>{h(t('cps_host'))}</span>
          <input id="{prefix}-cps-host" type="text" data-cps-host list="{prefix}-cps-hosts" value="{CPS_SNI_SUGGESTIONS[0]}"
                 maxlength="100" spellcheck="false" autocapitalize="off" autocomplete="off" title="{h(t('cps_host_hint'))}">
          <datalist id="{prefix}-cps-hosts">{''.join(f'<option value="{name}">' for name in CPS_SNI_SUGGESTIONS)}</datalist></label>
          <button type="button" class="btn btn-secondary" data-cps-apply="{prefix}-i1">{h(t('cps_preset_apply'))}</button></div>
          <p class="cps-warning">{h(t('cps_preset_note'))}</p>
          <div class="cps-fields">{fields}</div></details>'''


@app.get('/server/{interface}')
def server_switch(request:Request, interface:str):
    require_auth(request)
    if not SERVER_RE.fullmatch(interface) or interface not in [x['interface'] for x in server_list()]:
        raise HTTPException(404)
    response = RedirectResponse(f'/servers/{interface}/overview', status_code=303)
    response.set_cookie('awg31_server',interface,secure=COOKIE_SECURE,httponly=True,
                        samesite='strict',path='/',max_age=365*86400)
    return response

@app.post('/server/create')
async def server_create(request:Request):
    body = await request.form()
    require_csrf(request,body.get('csrf',''))
    lang=lang_of(request)
    data = {k:str(body.get(k,'')) for k in
            ('interface','subnet','port','mtu','endpoint','dns','mode','uplink')}
    try:
        iface=data['interface']
        if not SERVER_RE.fullmatch(iface):
            raise RuntimeError('Use an interface name such as awg1')
        ctl('server-create',data)
        audit_event('server_created',iface)
    except RuntimeError as exc:
        return error_page(request,tr(lang,'server_create_failed'),exc)
    response=RedirectResponse(f'/servers/{iface}/overview',status_code=303)
    response.set_cookie('awg31_server',iface,secure=COOKIE_SECURE,httponly=True,
                        samesite='strict',path='/',max_age=365*86400)
    return response

@app.post('/server/{interface}/{action}')
async def server_service_action(request:Request,interface:str,action:str):
    body=await request.form()
    require_csrf(request,body.get('csrf',''))
    if not SERVER_RE.fullmatch(interface) or action not in ('start','stop','restart','delete'):
        raise HTTPException(404)
    if interface not in {entry['interface'] for entry in server_list()}:
        raise HTTPException(404)
    try:
        payload={'interface':interface}
        if action=='delete':
            payload['confirm']=str(body.get('confirm',''))
        ctl('server-'+action, payload)
        audit_event('server_'+{'start':'started','stop':'stopped','restart':'restarted','delete':'deleted'}[action],interface)
    except RuntimeError as exc:
        return error_page(request,tr(lang_of(request),'error'),exc)
    if action == 'delete':
        response=RedirectResponse('/servers',status_code=303)
        response.delete_cookie('awg31_server')
        return response
    return RedirectResponse(f'/servers/{interface}/overview',status_code=303)


@app.get('/lang/{language}')
def change_language(request: Request, language: str, next: str = '/'):
    if language not in TEXT:
        raise HTTPException(status_code=404)
    # No external redirects or hidden control characters in redirect target.
    if not next.startswith('/') or next.startswith('//') or any(ord(c) < 32 for c in next):
        next = '/'
    response = RedirectResponse(next, status_code=303)
    response.set_cookie('awg31_lang', language, max_age=365 * 24 * 60 * 60,
                        httponly=True, secure=COOKIE_SECURE, samesite='strict', path='/')
    return response


def login_form(request, error='', next_path='/'):
    lang = lang_of(request)
    msg = f'<p class="error-message" role="alert">{h(error)}</p>' if error else ''
    try: second = bool(read_auth().get('totp_secret'))
    except (OSError, ValueError): second = False
    totp_field = (f'<label class="field" for="code"><span>{h(tr(lang,"totp_code"))}</span>'
                  '<input id="code" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required autocomplete="one-time-code"></label>') if second else ''
    return page(tr(lang, 'sign_in'), f'''<section class="card login-card">
        <div class="login-mark">{icon('lock',28)}</div>
        <div class="login-card-kicker">AMNEZIAWG 3.1 / ACCESS</div>
        <h2>{h(tr(lang,'login_card_title'))}</h2>
        <p class="login-card-hint">{h(tr(lang,'login_card_hint'))}</p>
        {msg}<form method="post" action="/login">
        <input type="hidden" name="next" value="{h(safe_next(next_path))}">
        <label class="field" for="password"><span>{h(tr(lang,'password'))}</span>
        <input id="password" type="password" name="password" required autocomplete="current-password" autofocus></label>
        {totp_field}
        <button class="btn btn-primary full-width" type="submit">{h(tr(lang,'login'))}{icon('arrow',18)}</button>
        </form></section>''', request)


@app.get('/health')
def health():
    return {'ok': True, 'service': 'awg31-panel'}


@app.get('/login')
def login_get(request: Request, next: str = '/'):
    target = safe_next(next)
    return RedirectResponse(target, status_code=303) if logged(request) else login_form(request, next_path=target)


@app.post('/login')
def login_post(request: Request, password: str = Form(...), next: str = Form('/'), code: str = Form('')):
    lang = lang_of(request)
    target = safe_next(next)
    now = time.monotonic()
    address = str(request.client.host if request.client else 'unknown')[:80]
    attempts = [t for t in login_attempts.get(address,[]) if now-t<300]
    # Cap the dictionary size and avoid unlimited entries from varied addresses.
    if len(login_attempts)>4096:
        # Drop idle addresses first; never wipe the counters of active attackers.
        for stale in [a for a, times in login_attempts.items() if not any(now-t<300 for t in times)]:
            login_attempts.pop(stale, None)
        while len(login_attempts)>4096:
            login_attempts.pop(min(login_attempts, key=lambda a: max(login_attempts[a], default=0)))
    login_attempts[address]=attempts
    if len(attempts) >= 5:
        return page(tr(lang, 'sign_in'),
                    '<section class="card"><p role="alert">'+h(tr(lang,'login_limited'))+'</p></section>',request)
    try:
        auth=read_auth()
        candidate=hashlib.scrypt(password.encode('utf-8'),salt=bytes.fromhex(auth['salt']),
                                 n=2**14,r=8,p=1,dklen=32)
        valid=hmac.compare_digest(candidate.hex(),auth['password_hash'])
        if valid and auth.get('totp_secret'):
            # Second factor; a code is accepted once, so a watched code cannot be replayed.
            step=totp_step(auth['totp_secret'],code)
            valid=step is not None and step>LAST_TOTP_STEP[0]
            if valid: LAST_TOTP_STEP[0]=step
    except (ValueError,OverflowError,OSError): valid=False
    if not valid:
        attempts.append(now)
        audit_event('login_failed',address)
        return login_form(request, tr(lang,'login_error'), target)
    login_attempts.pop(address,None)
    audit_event('login_success',address)
    request.session.clear()
    request.session['authenticated']=True
    request.session['auth_version']=auth.get('auth_version','')
    request.session['csrf']=secrets.token_urlsafe(32)
    return RedirectResponse(target, status_code=303)


@app.get('/logout')
def logout(request: Request):
    if logged(request):
        # Signed cookies cannot be recalled one by one: invalidate all of them.
        try: ctl('session-revoke', {})
        except (RuntimeError, ValueError): pass
    request.session.clear()
    return RedirectResponse('/login', status_code=303)


def human_size(value):
    """Bytes as B / KiB / MiB / GiB / TiB for tables (exact values stay in the API)."""
    try: n = float(value)
    except (TypeError, ValueError): return '—'
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if n < 1024 or unit == 'TiB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


# Texts of the features added in 0.10.
TEXT['ru'].update({
    'host_label':'Доступ клиентов к службам самого сервера',
    'host_on':'Разрешён: клиенты достают до SSH, панели и других служб по VPN-адресу сервера',
    'host_off':'Запрещён: с VPN-адресов до сервера проходят только ответы, ping и DNS',
    'host_hint':'«Запрещён» закрывает от клиентов всё, что слушает сам сервер. Панель по VPN-адресу тоже перестанет открываться.',
    'speed':'Ограничение скорости (Мбит/с; 0 = без ограничения)',
    'quota_monthly':'Сбрасывать счётчик трафика каждый месяц (UTC)',
    'batch_title':'Добавить несколько клиентов', 'batch_prefix':'Префикс имени', 'batch_count':'Сколько (1–50)',
    'batch_start':'Начать с номера', 'batch_create':'Добавить клиентов и скачать ZIP',
    'batch_hint':'Имена вида префикс-01, префикс-02… Срок, лимит и скорость общие. В ответ придёт ZIP с конфигурациями, после чего список клиентов обновится.',
    'panel_password':'Пароль панели', 'totp_code_current':'Код текущего ключа', 'totp_code_new':'Код нового ключа',
    'tg_password_when':'Нужен, если меняются администраторы или наблюдатели.',
    'enc_change':'Сменить пароль шифрования', 'enc_passphrase_new':'Новый пароль шифрования (16+ символов)',
    'enc_change_hint':'Архивы на сервере, которые открывает текущий пароль, будут перешифрованы новым. Копии, уже отправленные в Telegram или во внешнее хранилище, останутся со старым паролем.',
    'enc_reencrypted':'Пароль сменён, перешифровано архивов: {count}.',
    'enc_skipped':'Не перешифрованы (зашифрованы ещё более старым паролем, ему они и нужны):',
    'totp_code':'Код из приложения-аутентификатора', 'totp_title':'Двухфакторный вход (TOTP)',
    'totp_on':'Включён: при входе нужен пароль и код из приложения.',
    'totp_off_hint':'Отсканируйте QR-код приложением-аутентификатором (Aegis, Google Authenticator, 2FAS и т. п.) или введите ключ вручную, затем подтвердите паролем и кодом.',
    'totp_secret':'Ключ', 'totp_enable':'Включить двухфакторный вход', 'totp_disable':'Отключить двухфакторный вход',
    'totp_lost':'Потеряли телефон: на сервере выполните sudo awg31 totp-off',
    'maint_telegram':'Telegram-бот',
    'maint_telegram_hint':'Кому отвечает бот и о чём сообщает. Токен хранится отдельно от панели и никогда здесь не показывается.',
    'tg_missing':'Бот не подключён. На сервере выполните:', 'tg_state':'Служба бота',
    'tg_admins':'Администраторы (Telegram ID)', 'tg_viewers':'Наблюдатели: только просмотр',
    'tg_ids_hint':'Числовые Telegram ID через запятую. Наблюдатели видят состояние и получают уведомления, но ничего не меняют.',
    'tg_lang':'Язык бота', 'tg_notify':'Уведомления', 'tg_digest':'Сводка',
    'tg_n_server':'Сервер, модуль ядра, панель', 'tg_n_clients':'Клиенты: срок и лимит', 'tg_n_security':'Входы в панель, пароль, выдача конфигураций',
    'tg_n_backups':'Резервные копии (зашифрованная копия приходит файлом)',
    'tg_d_off':'Не присылать', 'tg_d_daily':'Каждый день', 'tg_d_weekly':'По понедельникам', 'tg_save':'Сохранить настройки бота',
    'remote_on':'Каждая новая зашифрованная копия отправляется во внешнее хранилище:',
    'remote_off':'Внешнее хранилище не настроено. Настроить: sudo awg31 backup-remote s3 (или sftp)',
    'next_kernel_bad':'Установлено новое ядро {version}, но модуль AmneziaWG для него не собран: после перезагрузки VPN не запустится. До перезагрузки выполните на сервере: sudo awg31 update',
    'enc_on':'Шифрование копий включено: архивы .gpg защищены паролем и могут приходить в Telegram.',
    'enc_off':'Копии не шифруются и содержат все ключи открытым текстом.',
    'enc_restore_note':'Старые архивы .tar.gz остаются доступны. Для восстановления .gpg после смены или отключения пароля его нужно указать заново через sudo awg31 backup-encryption on.',
    'enc_enable':'Включить шифрование', 'enc_disable':'Отключить шифрование',
    'enc_passphrase':'Пароль для шифрования', 'enc_passphrase_repeat':'Повторите пароль',
    'enc_passphrase_hint':'От 16 до 200 символов. Сохраните пароль отдельно: он понадобится при восстановлении на новом сервере. Пароль не отображается в панели.',
    'enc_disable_confirm':'Отключить шифрование новых резервных копий? Старые .gpg-архивы останутся зашифрованными.',
    'tg_token_hint':'Формат токена Telegram: цифры:строка',
    'tg_title':'Telegram-бот', 'tg_tab_panel':'Панель', 'tg_tab_notify':'Уведомления',
    'tg_running':'Работает', 'tg_stopped':'Остановлен', 'tg_not_connected':'Не подключён',
    'tg_enable':'Включить Telegram-бота', 'tg_enable_hint':'Управление серверами и клиентами через бота. Выключение останавливает службу, настройки и токен сохраняются.',
    'tg_token':'Telegram-токен', 'tg_token_set':'Настроен; оставьте пустым, чтобы сохранить текущий токен.',
    'tg_token_placeholder':'Настроен — введите новый токен для замены',
    'tg_reveal':'Показать или скрыть', 'tg_clear':'Очистить',
    'tg_clear_confirm':'Отключить бота? Служба остановится, токен будет удалён с сервера. Нужен пароль панели.',
    'tg_admins_hint':'Один или несколько числовых ID через запятую. Свой ID человек узнает командой /id в этом боте или у @userinfobot.',
    'tg_viewers_hint':'Видят состояние и получают уведомления, но ничего не меняют.',
    'tg_api':'Сервер Telegram API', 'tg_api_hint':'Оставьте пустым для api.telegram.org. Свой сервер Bot API: https://… (http:// только для 127.0.0.1).',
    'tg_password_row':'Пароль панели', 'tg_password_row_hint':'Нужен при смене токена, администраторов, наблюдателей или сервера API, и для «Очистить».',
    'tg_test':'Отправить тестовое сообщение', 'tg_saved':'Настройки бота сохранены.', 'tg_tested':'Тестовое сообщение отправлено администраторам.',
    'tg_schedule':'Частота отчётов', 'tg_schedule_hint':'Сводка администраторам: клиенты на связи, трафик за период, самые активные, у кого скоро истекает срок. Время сервера.',
    'tg_custom':'Своё расписание (crontab)', 'tg_custom_hint':'Пять полей: минута, час, день, месяц, день недели. Например 30 8 * * 1-5 — по будням в 08:30.',
    'tg_s_off':'Не присылать', 'tg_s_hourly':'каждый час', 'tg_s_6h':'каждые 6 часов', 'tg_s_12h':'каждые 12 часов',
    'tg_s_daily9':'каждый день в 09:00', 'tg_s_daily21':'каждый день в 21:00', 'tg_s_weekly':'по понедельникам в 09:00',
    'tg_backup_file':'Резервные копии файлом', 'tg_backup_file_on':'Каждая новая зашифрованная копия приходит администраторам файлом.',
    'tg_backup_file_off':'Сейчас шифрование копий выключено: незашифрованная копия содержит ключи и в Telegram не отправляется. Включите шифрование в разделе «Резервные копии».',
    'tg_events':'Уведомления о событиях', 'tg_events_hint':'Что бот сообщает администраторам и наблюдателям. Владельцы клиентов получают свои предупреждения всегда.',
    'tg_all':'Все в группе',
    'tg_g_server':'Серверы', 'tg_g_clients':'Клиенты', 'tg_g_security':'Безопасность', 'tg_g_backups':'Резервные копии', 'tg_g_system':'Система',
    'tg_e_server_state':'Сервер остановлен или снова работает', 'tg_e_module':'Модуль ядра недоступен', 'tg_e_kernel':'Новое ядро без модуля',
    'tg_e_panel':'Веб-панель не работает', 'tg_e_client_auto':'Отключён или включён автоматически', 'tg_e_client_expiring':'Срок истекает в течение 3 дней',
    'tg_e_client_quota':'Израсходовано 80% лимита', 'tg_e_login':'Вход в панель', 'tg_e_login_failed':'Неудачные попытки входа',
    'tg_e_password':'Смена пароля панели', 'tg_e_owner_export':'Владелец получил конфигурацию', 'tg_e_backup_created':'Копия создана',
    'tg_e_backup_failed':'Копия не создана', 'tg_e_upload_failed':'Не отправлена во внешнее хранилище',
    'tg_e_cpu':'Загрузка CPU выше', 'tg_e_memory':'Занятая память выше', 'tg_e_disk':'Заполнение диска выше',
    'tg_connect':'Проверить токен и найти администратора', 'tg_connect_hint':'Создайте бота у @BotFather, вставьте токен и заранее отправьте новому боту /start в личном чате. Найденный отправитель потребует отдельного подтверждения.',
    'tg_confirm_title':'Подтвердите администратора Telegram',
    'tg_confirm_hint':'Отправьте /start новому боту в личном чате и повторите проверку, если список пуст. Выберите свою учётную запись: только она станет первым администратором.',
    'tg_no_candidates':'Сообщение /start пока не найдено. Отправьте его в личном чате с новым ботом и попробуйте снова.',
    'tg_confirm':'Сохранить и подключить бота',
})
TEXT['en'].update({
    'host_label':'Client access to services of the server itself',
    'host_on':'Allowed: clients reach SSH, the panel and other services on the VPN address of the server',
    'host_off':'Denied: only replies, ping and DNS pass from VPN addresses to the server',
    'host_hint':'“Denied” closes everything the server itself listens on to clients. The panel stops opening on the VPN address too.',
    'speed':'Speed limit (Mbit/s; 0 = unlimited)',
    'quota_monthly':'Reset the traffic counter every month (UTC)',
    'batch_title':'Add several clients', 'batch_prefix':'Name prefix', 'batch_count':'How many (1–50)',
    'batch_start':'First number', 'batch_create':'Add clients and download ZIP',
    'batch_hint':'Names look like prefix-01, prefix-02… Expiry, quota and speed are shared. The reply is a ZIP with the configurations, after which the client list refreshes.',
    'panel_password':'Panel password', 'totp_code_current':'Code of the current key', 'totp_code_new':'Code of the new key',
    'tg_password_when':'Needed when administrators or viewers change.',
    'enc_change':'Change the encryption passphrase', 'enc_passphrase_new':'New encryption passphrase (16+ characters)',
    'enc_change_hint':'Archives on the server that the current passphrase opens are re-encrypted with the new one. Copies already sent to Telegram or a remote storage keep the old passphrase.',
    'enc_reencrypted':'Passphrase changed, archives re-encrypted: {count}.',
    'enc_skipped':'Not re-encrypted (sealed with an even older passphrase, they need that one):',
    'totp_code':'Code from the authenticator app', 'totp_title':'Two-factor sign-in (TOTP)',
    'totp_on':'Enabled: signing in needs the password and a code from the app.',
    'totp_off_hint':'Scan the QR code with an authenticator app (Aegis, Google Authenticator, 2FAS…) or type the key by hand, then confirm with the password and a code.',
    'totp_secret':'Key', 'totp_enable':'Enable two-factor sign-in', 'totp_disable':'Disable two-factor sign-in',
    'totp_lost':'Lost the phone: run sudo awg31 totp-off on the server',
    'maint_telegram':'Telegram bot',
    'maint_telegram_hint':'Whom the bot answers and what it reports. The token stays on the server and is not shown here.',
    'tg_missing':'The bot is not connected. On the server run:', 'tg_state':'Bot service',
    'tg_admins':'Administrators (Telegram IDs)', 'tg_viewers':'Viewers: read-only',
    'tg_ids_hint':'Numeric Telegram IDs separated by commas. Viewers see the state and get notifications but cannot change anything.',
    'tg_lang':'Bot language', 'tg_notify':'Notifications', 'tg_digest':'Digest',
    'tg_n_server':'Server, kernel module, panel', 'tg_n_clients':'Clients: expiry and quota', 'tg_n_security':'Panel sign-ins, password, configuration downloads',
    'tg_n_backups':'Backups (an encrypted backup arrives as a file)',
    'tg_d_off':'Do not send', 'tg_d_daily':'Every day', 'tg_d_weekly':'On Mondays', 'tg_save':'Save bot settings',
    'remote_on':'Every new encrypted backup is uploaded to the remote storage:',
    'remote_off':'No remote storage is set up. Set up: sudo awg31 backup-remote s3 (or sftp)',
    'next_kernel_bad':'A new kernel {version} is installed, but the AmneziaWG module is not built for it: after a reboot the VPN will not start. Before rebooting run on the server: sudo awg31 update',
    'enc_on':'Backup encryption is on: .gpg archives are protected by a passphrase and may be sent to Telegram.',
    'enc_off':'Backups are not encrypted and contain every key in plain text.',
    'enc_restore_note':'Existing .tar.gz archives remain available. If the passphrase was changed or encryption disabled, restore .gpg access with sudo awg31 backup-encryption on.',
    'enc_enable':'Enable encryption', 'enc_disable':'Disable encryption',
    'enc_passphrase':'Encryption passphrase', 'enc_passphrase_repeat':'Repeat passphrase',
    'enc_passphrase_hint':'16–200 characters. Store this passphrase separately: it is needed to restore on a new server. The panel does not display it.',
    'enc_disable_confirm':'Disable encryption of new backups? Existing .gpg archives will remain encrypted.',
    'tg_token_hint':'Telegram token format: digits:string',
    'tg_title':'Telegram bot', 'tg_tab_panel':'Panel', 'tg_tab_notify':'Notifications',
    'tg_running':'Running', 'tg_stopped':'Stopped', 'tg_not_connected':'Not connected',
    'tg_enable':'Enable the Telegram bot', 'tg_enable_hint':'Manage servers and clients through the bot. Switching it off stops the service; settings and token are kept.',
    'tg_token':'Telegram token', 'tg_token_set':'Set; leave empty to keep the current token.',
    'tg_token_placeholder':'Set — enter a new token to replace it',
    'tg_reveal':'Show or hide', 'tg_clear':'Clear',
    'tg_clear_confirm':'Disconnect the bot? The service stops and the token is removed from the server. The panel password is needed.',
    'tg_admins_hint':'One or more numeric IDs separated by commas. A person learns their ID with /id in this bot or from @userinfobot.',
    'tg_viewers_hint':'See the state and get notifications but cannot change anything.',
    'tg_api':'Telegram API server', 'tg_api_hint':'Leave empty for api.telegram.org. Your own Bot API server: https://… (http:// only for 127.0.0.1).',
    'tg_password_row':'Panel password', 'tg_password_row_hint':'Needed to change the token, administrators, viewers or API server, and for “Clear”.',
    'tg_test':'Send a test message', 'tg_saved':'Bot settings saved.', 'tg_tested':'The test message was sent to the administrators.',
    'tg_schedule':'Report frequency', 'tg_schedule_hint':'A summary for administrators: clients online, traffic for the period, the most active, who expires soon. Server time.',
    'tg_custom':'Custom schedule (crontab)', 'tg_custom_hint':'Five fields: minute, hour, day, month, weekday. For example 30 8 * * 1-5 is weekdays at 08:30.',
    'tg_s_off':'Do not send', 'tg_s_hourly':'every hour', 'tg_s_6h':'every 6 hours', 'tg_s_12h':'every 12 hours',
    'tg_s_daily9':'every day at 09:00', 'tg_s_daily21':'every day at 21:00', 'tg_s_weekly':'Mondays at 09:00',
    'tg_backup_file':'Backups as files', 'tg_backup_file_on':'Every new encrypted backup is sent to the administrators as a file.',
    'tg_backup_file_off':'Backup encryption is off now: an unencrypted backup holds keys and is never sent to Telegram. Turn encryption on under Backups.',
    'tg_events':'Event notifications', 'tg_events_hint':'What the bot reports to administrators and viewers. Client owners always get their own warnings.',
    'tg_all':'All in the group',
    'tg_g_server':'Servers', 'tg_g_clients':'Clients', 'tg_g_security':'Security', 'tg_g_backups':'Backups', 'tg_g_system':'System',
    'tg_e_server_state':'Server stopped or running again', 'tg_e_module':'Kernel module unavailable', 'tg_e_kernel':'New kernel without the module',
    'tg_e_panel':'Web panel is down', 'tg_e_client_auto':'Disabled or enabled automatically', 'tg_e_client_expiring':'Expires within 3 days',
    'tg_e_client_quota':'80% of the quota used', 'tg_e_login':'Sign-in to the panel', 'tg_e_login_failed':'Failed sign-in attempts',
    'tg_e_password':'Panel password changed', 'tg_e_owner_export':'Owner fetched the configuration', 'tg_e_backup_created':'Backup created',
    'tg_e_backup_failed':'Backup not created', 'tg_e_upload_failed':'Not sent to the remote storage',
    'tg_e_cpu':'CPU load above', 'tg_e_memory':'Memory use above', 'tg_e_disk':'Disk use above',
    'tg_connect':'Check token and find administrator', 'tg_connect_hint':'Create a bot with @BotFather, paste its token, then send /start to the new bot in a private chat. You will separately confirm the sender.',
    'tg_confirm_title':'Confirm the Telegram administrator',
    'tg_confirm_hint':'Send /start to the new bot in a private chat and retry if the list is empty. Select your own account: it will become the first administrator.',
    'tg_no_candidates':'No /start message was found. Send it in a private chat with the new bot and try again.',
    'tg_confirm':'Save and connect bot',
})


LAST_TOTP_STEP = [0]


def totp_step(secret, code):
    """RFC 6238 check with one step of clock drift; returns the matching time step or None."""
    code = str(code).strip().replace(' ', '')
    if not re.fullmatch(r'[0-9]{6}', code): return None
    try: key = base64.b32decode(secret, casefold=True)
    except ValueError: return None
    now = int(time.time() // 30)
    for step in (now, now - 1, now + 1):
        digest = hmac.new(key, step.to_bytes(8, 'big'), hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = (int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff) % 1000000
        if hmac.compare_digest(f'{value:06d}', code): return step
    return None


def policy_extras(form):
    try: speed = int(str(form.get('speed_limit_mbit', '0')).strip() or 0)
    except ValueError: raise HTTPException(422, detail='Invalid speed limit') from None
    if not 0 <= speed <= 10000: raise HTTPException(422, detail='Invalid speed limit')
    return {'speed_limit_mbit': speed, 'quota_period': 'monthly' if form.get('quota_monthly') == '1' else ''}


def policy_extra_fields(obj, prefix):
    return (form_field('speed_limit_mbit', str(int(obj.get('speed_limit_mbit') or 0)), tr(obj['_lang'], 'speed'), required=False, field_id=prefix + '-speed')
            + f'<label class="check-field"><input type="checkbox" name="quota_monthly" value="1"'
              f'{" checked" if obj.get("quota_period") == "monthly" else ""}><span>{h(tr(obj["_lang"], "quota_monthly"))}</span></label>')


def switch_field(field_id, name, text_prefix, state, lang, order=('on', 'off')):
    """An on/off server switch as a labelled select with a one-line explanation."""
    current = state.get(name, order[0])
    options = ''.join(f'<option value="{value}"{" selected" if current == value else ""}>'
                      f'{h(tr(lang, text_prefix + "_" + value))}</option>' for value in order)
    return (f'<label class="field" for="{field_id}"><span>{h(tr(lang, text_prefix + "_label"))}</span>'
            f'<select id="{field_id}" name="{name}">{options}</select>'
            f'<small>{h(tr(lang, text_prefix + "_hint"))}</small></label>')


def form_field(name, val, label, help='', required=True, field_id=None):
    extra = ' inputmode="numeric"' if name in ('port', 'mtu', 'telegram_id', 'speed_limit_mbit', 'count', 'start') else ''
    field_id = field_id or name
    req = " required" if required else ""
    return (f'<label class="field" for="{field_id}"><span>{h(label)}</span>'
            f'<input id="{field_id}" name="{name}" value="{h(val)}"{extra}{req}>'
            f'{"<small>"+h(help)+"</small>" if help else ""}</label>')


def expiry_field(value, field_id, lang):
    russian = lang == 'ru'
    date_format = '%d.%m.%Y' if russian else '%Y-%m-%d'
    if value.endswith('T23:59:59+00:00'):
        value = datetime.fromisoformat(value).strftime(date_format)
    calendar = 'Календарь' if russian else 'Calendar'
    hint = ('ДД.ММ.ГГГГ или ГГГГ-ММ-ДД. Доступ действует до конца указанного дня по UTC.'
            if russian else 'DD.MM.YYYY or YYYY-MM-DD. Access lasts through the selected day in UTC.')
    return f'''<div class="field">
      <label for="{field_id}"><span>{h(tr(lang, 'expires'))}</span></label>
      <div class="expiry-input">
        <input id="{field_id}" name="expires_at" value="{h(value)}"
               placeholder="{'ДД.ММ.ГГГГ' if russian else 'YYYY-MM-DD'}" aria-describedby="{field_id}-hint">
        <button type="button" class="expiry-calendar-button" data-expiry-open="{field_id}"
                aria-label="{h(calendar)}" title="{h(calendar)}" aria-expanded="false"
                aria-controls="{field_id}-calendar" aria-haspopup="dialog" hidden>{icon('calendar',20)}</button>
        <div id="{field_id}-calendar" class="expiry-calendar" role="dialog"
             aria-label="{h(calendar)}" lang="{lang}" hidden></div>
      </div>
      <small id="{field_id}-hint">{h(hint)}</small>
    </div>'''


def stat(icon_name, label, value, *, mono=True, detail=''):
    klass = 'mono' if mono else ''
    return (f'<div class="stat"> <span class="stat-icon">{icon(icon_name,22)}</span>'
            f'<div class="stat-body"><span class="stat-label">{h(label)}</span>'
            f'<span class="stat-value {klass}">{h(value)}</span>'
            + ('<span class="stat-caption">' + h(detail) + '</span>' if detail else '')
            + '</div></div>')


def error_page(request, heading, exc, status_code=400):
    lang = lang_of(request)
    response = page(heading, f'<section class="card message-card"><p class="error-message" role="alert">'
                + h(controller_message(lang, exc)) + '</p>'
                + f'<a class="btn btn-secondary" href="/">{icon("arrow",18)}{h(tr(lang,"back"))}</a></section>', request)
    response.status_code = status_code
    return response


def client_export(request, name):
    """Fetch one client's export data and note that it was handed out.

    An unknown or invalid name is a 404. Only real exports (file, QR, link) come
    through here; merely opening the client page does not count.
    """
    try:
        return control(request, 'download', {'name': name, 'mark': True})
    except RuntimeError:
        raise HTTPException(status_code=404, detail=tr(lang_of(request), 'not_available')) from None


def server_content(request: Request, section: str = 'overview'):
    if not logged(request):
        return RedirectResponse('/login')
    lang = lang_of(request)
    t = lambda key: tr(lang, key)
    try:
        state = control(request,'list')
    except RuntimeError as exc:
        if section != 'servers' or server_list():
            return error_page(request, t('error'), exc)
        # The last server was deleted: keep the creation page usable.
        state = {'interface':'awg0','subnet':'10.77.10.0/24','port':51820,
                 'running':False,'clients':[],'mtu':1280,'dns':'1.1.1.1',
                 'endpoint':'vpn.example.com','mode':'full','uplink':'ens3',
                 'obfuscation':{}}

    try:
        instances=server_list()
    except (RuntimeError,AttributeError):
        instances=[]
    if not isinstance(instances,list) or not instances or 'interface' not in instances[0]:
        instances=[{'interface':state['interface'],'subnet':state['subnet'],
                    'port':state['port'],'running':state['running'],'clients':len(state.get('clients',[]))}]
    running = bool(state['running'])
    state_pill = ('running' if running else 'stopped')
    clients_all = state.get('clients', [])
    now = time.time()
    connected_count = sum(1 for c in clients_all if c.get('enabled') and
                          int(c.get('stats', {}).get('handshake', 0)) > now - 180)
    total_rx = sum(int(c.get('stats', {}).get('received', 0)) for c in clients_all)
    total_tx = sum(int(c.get('stats', {}).get('sent', 0)) for c in clients_all)
    def friendly_size(n):
        n = float(n)
        for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
            if n < 1024 or unit == 'TiB':
                return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
            n /= 1024
    head = f'''<div class="overview-layout" id="overview">
        <section class="card summary-card" aria-label="{h(t('overview'))}">
        <div class="section-title compact-title"><div><span class="section-overline">SYSTEM / STATUS</span>
        <h2>{h(t('quick_stats'))}</h2></div>
        <span class="pill pill-{state_pill}"><span class="dot"></span>{h(t('vpn_running' if running else 'vpn_stopped'))}</span></div>
        <div class="headline-metrics">
            <div class="headline-metric"><span>{h(t('connected'))}</span><strong id="live-connected">{connected_count}</strong><small>{h(t('last_seen'))} &lt; 3m</small></div>
            <div class="headline-metric"><span>{h(t('total_clients'))}</span><strong>{len(clients_all)}</strong><small>IPv4 / AWG</small></div>
            <div class="headline-metric"><span>{h(t('total_transfer'))}</span><strong>{h(friendly_size(total_rx+total_tx))}</strong><small>RX + TX</small></div>
        </div>
        <div class="stats-grid">
        {stat('server', t('interface'), state['interface'])}
        {stat('network', t('subnet'), state['subnet'])}
        {stat('radio', t('udp_port'), state['port'])}
        {stat('layers', 'MTU', state['mtu'])}
        {stat('shield', t('mode'), t('full' if state['mode']=='full' else 'split'), mono=False)}
        {stat('globe', t('endpoint'), state['endpoint'])}
        {stat('server', t('dns'), state['dns'])}
        {stat('shield', 'IPv4', t('ipv4_only'), mono=False)}
        </div></section>
        <section class="card graph-card" id="monitoring" aria-label="{h(t('live_traffic'))}">
        <div class="section-title compact-title"><div><span class="section-overline">AWG / MONITORING</span>
        <h2>{icon('activity',18)}{h(t('live_traffic'))}</h2></div><span class="tiny-live"><span class="live-beacon"></span>{h(t('traffic_live'))}</span></div>
        <div class="graph-live-values"><div><small>RX</small><strong class="mono" id="rx-rate">—</strong></div><div><small>TX</small><strong class="mono" id="tx-rate">—</strong></div></div>
        <div class="graph-area"><div class="graph-rules"><span></span><span></span><span></span></div>
        <svg id="traffic-chart" viewBox="0 0 620 190" preserveAspectRatio="none" role="img" aria-label="{h(t('live_traffic'))}">
        <path id="chart-rx" fill="none" stroke="#f3a51e" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round"/>
        <path id="chart-tx" fill="none" stroke="#94a9c2" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
        <div class="graph-legend"><span><i class="legend-rx"></i>{h(t('traffic_rx'))}</span><span><i class="legend-tx"></i>{h(t('traffic_tx'))}</span></div>
        <p id="traffic-chart-message" class="muted micro">{h(t('traffic_wait'))}</p>
        <div class="graph-footnote">{h(t('refresh_time'))} · <span class="mono">0.0.0.0/0</span></div>
        </section></div>'''

    history_html = f'''<section class="card history-card" id="history">
        <div class="section-title"><h2>{icon('activity',20)}{h(t('history'))}</h2>
        <select id="history-window" aria-label="{h(t('history'))}">
          <option value="24h">24h</option><option value="7d">7d</option><option value="30d">30d</option>
        </select></div><p class="info-line">{h(t('history_note'))}</p>
        <svg id="history-chart" viewBox="0 0 620 190" preserveAspectRatio="none" role="img" aria-label="{h(t('history'))}">
        <path id="history-rx" fill="none" stroke="#f3a51e" stroke-width="2.7"/>
        <path id="history-tx" fill="none" stroke="#94a9c2" stroke-width="2.4"/></svg>
        <p id="history-info" class="muted micro">{h(t('history_empty'))}</p>
        </section>'''
    def sort_head(key, label):
        # A button in each header: click sorts, a second click reverses; panel.js remembers the choice.
        return (f'<th aria-sort="none" data-sort-column="{key}"><button type="button" class="sort-button" data-sort-key="{key}">'
                f'<span>{h(label)}</span><svg class="sort-arrow" viewBox="0 0 12 12" aria-hidden="true"><path class="sort-up" d="M3 4.5 6 1.5l3 3"/><path class="sort-down" d="M3 7.5l3 3 3-3"/></svg></button></th>')
    rows = ''
    for c in state['clients']:
        st = c.get('stats', {})
        seen = (time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(st['handshake']))
                if st.get('handshake') else t('never'))
        name = h(c['name'])
        encoded_name = quote(c['name'], safe='')
        active = bool(c['enabled'])
        status_class = 'running' if active else 'stopped'
        # One panel of icon buttons (variant B chosen by the author): configuration, download, on/off, delete.
        base = f'/servers/{quote(state["interface"], safe="")}/clients/{encoded_name}'
        toggle = 'disable' if active else 'enable'
        def action_label(key):
            return f'aria-label="{h(t(key))}: {name}" data-tip="{h(t(key))}"'
        actions = (f'<div class="action-group" role="group" aria-label="{h(t("actions"))}: {name}">'
                   f'<a class="action-icon" href="{base}" {action_label("client_details")}>{icon("file",18)}</a>'
                   f'<a class="action-icon" href="{base}/download" download {action_label("download")}>{icon("download",18)}</a>'
                   f'<form method="post" action="{base}/{toggle}" class="inline">{csrf(request)}'
                   f'<button class="action-icon" type="submit" {action_label("disable" if active else "enable")}>'
                   f'{icon("pause" if active else "play",18)}</button></form>'
                   f'<form method="post" action="{base}/delete" class="inline" data-confirm="{h(t("confirm_delete"))}">{csrf(request)}'
                   f'<button class="action-icon is-danger" type="submit" {action_label("delete")}>{icon("trash",18)}</button></form>'
                   '</div>')
        traffic_total = int(st.get('received', 0) or 0) + int(st.get('sent', 0) or 0)
        rows += (f'<tr class="client-row" data-name="{h(c["name"].lower())}" data-ip="{h(c["ip"])}" data-enabled="{int(active)}" '
                 f'data-handshake="{int(st.get("handshake") or 0)}" data-traffic="{traffic_total}"><td><input class="peer-select" type="checkbox" form="bulk-delete-form" name="names" value="{name}" aria-label="{name}"></td><td class="client-name">'
                 # A dot on the client icon marks extra [Interface] lines (variant B chosen by the author).
                 + (f'<span class="client-icon has-extra" title="{h(t("extra_badge_hint"))}">{icon("server",16)}'
                    f'<span class="extra-dot" aria-hidden="true"></span><span class="sr-only">{h(t("extra_badge_hint"))}</span></span>'
                    if c.get('extra_lines') is True else icon("server",16))
                 + f'<span>{h(c["name"])}</span></td>'
                 f'<td><code class="ip-pill">{h(c["ip"])}</code>'
                 f'<small class="peer-routes-compact">{h(c.get("routed_subnets", ""))}</small></td>'
                 f'<td><span class="pill pill-{status_class}"><span class="dot"></span>'
                 f'{h(t("active" if active else "disabled"))}</span><small class="handshake">{h(seen)}</small>'
                 + (f'<small class="config-stale" title="{h(t("config_stale_hint"))}">{icon("info",12)}{h(t("config_stale"))}</small>'
                    if c.get('config_stale') else '') + '</td>'
                 f'<td><span class="traffic mono">↓ {h(human_size(st.get("received",0)))} <span class="traffic-divider"></span> '
                 f'↑ {h(human_size(st.get("sent",0)))}</span></td>'
                 f'<td class="actions-cell">{actions}</td></tr>')

    if not rows:
        rows = (f'<tr><td colspan="6"><div class="empty-state">{icon("users",26)}'
                f'<strong>{h(t("no_clients"))}</strong><span>{h(t("no_clients_hint"))}</span>'
                '</div></td></tr>')
    clients = f'''<section class="card clients-card" id="clients">
        <div class="section-title"><div><span class="section-overline">PEERS / ACCESS</span>
        <h2>{icon('users',20)}{h(t('clients'))}</h2>
        <p class="section-subtitle">{h(t('client_help'))}</p></div>
        <div class="clients-actions">
        <button type="button" class="btn btn-secondary" data-modal-open="batch-client-modal">{icon('users',16)}{h(t('batch_title'))}</button>
        <button type="button" class="btn btn-primary" data-modal-open="add-client-modal">{icon('plus',16)}{h(t('add_client'))}</button>
        </div></div>
        <div class="table-tools"><label class="table-search">{icon('search',16)}<input id="client-search" type="search" placeholder="{h(t('search_clients'))}" aria-label="{h(t('search_clients'))}"></label>
        <div class="client-status-filters" role="group" aria-label="{h(t('status'))}">
          <label><input type="checkbox" data-client-status="1" checked><span>{h(t('active_only'))}</span></label>
          <label><input type="checkbox" data-client-status="0" checked><span>{'Отключённые' if lang=='ru' else 'Disabled'}</span></label>
        </div>
        <span class="table-count mono">{len(clients_all)} {h('клиентов' if lang=='ru' else 'peers')}</span></div>
        <form id="bulk-delete-form" method="post" action="/servers/{h(state['interface'])}/clients/bulk-delete" data-confirm="{h(t('bulk_delete_confirm'))}">{csrf(request)}
        <div class="bulk-toolbar"><span id="bulk-selection-count">{h(t('selected_count'))}: 0</span>
        <button id="bulk-extra-button" type="button" class="btn btn-secondary btn-small" data-modal-open="bulk-extra-modal" disabled>{icon('file',16)}{h(t('extra_bulk'))}</button>
        <button id="bulk-delete-button" type="submit" class="btn btn-danger btn-small" disabled>{icon('trash',16)}{h(t('bulk_delete'))}</button></div></form>
        <div class="table-scroll"><table><thead><tr>
        <th><input type="checkbox" id="select-all-peers" aria-label="{h(t('select_all'))}"></th>{sort_head('name',t('name'))}{sort_head('ip',t('vpn_ip'))}{sort_head('status',t('status'))}
        {sort_head('traffic',t('traffic'))}<th class="actions-head">{h(t('actions'))}</th></tr></thead><tbody data-sortable-clients>{rows}</tbody></table></div>
        </section>

        <!-- Add client modal -->
        <dialog id="add-client-modal" class="awg-modal">
          <div class="modal-header"><h2>{icon('plus',20)}{h(t('add_client'))}</h2>
          <button type="button" class="icon-btn modal-close" aria-label="{h(t('close_window'))}">{icon('x',20)}</button></div>
          <div class="modal-body">
          <form class="add-client-form" method="post" action="/client">{csrf(request)}
          <label class="field" for="client-name"><span>{h(t('client_name'))}</span>
          <input id="client-name" name="name" placeholder="{h(t('client_placeholder'))}"
          pattern="[A-Za-z0-9][A-Za-z0-9_\\-]*" maxlength="32" required autofocus></label>
          <div class="peer-network-options">
            <label class="field" for="routed-subnets-new"><span>{h(t('peer_routes'))}</span>
            <textarea id="routed-subnets-new" name="routed_subnets" rows="2" placeholder="192.168.50.0/24"></textarea>
            <small>{h(t('peer_routes_hint'))}</small></label>
            <div class="fields-grid">
              {form_field('comment','',t('comment'),required=False,field_id='new-comment')}
              {expiry_field('', 'new-expires', lang)}
              {form_field('quota_gib','0',t('quota'),required=False,field_id='new-quota')}
              {form_field('telegram_id','',t('telegram_id'),t('telegram_id_hint'),required=False,field_id='new-telegram')}
              {policy_extra_fields({'_lang':lang}, 'new')}
            </div>
            <label class="check-field"><input type="checkbox" name="owner_export" value="1"><span>{h(t('owner_export'))}</span></label>
            {cps_block('new', {}, False, lang)}
          </div>
          <div class="modal-footer"><button class="btn btn-primary" type="submit">{icon('plus',16)}{h(t('add_client_submit'))}</button></div>
          </form>
          </div>
        </dialog>

        <!-- Extra [Interface] lines for the selected clients -->
        <dialog id="bulk-extra-modal" class="awg-modal">
          <div class="modal-header"><h2>{icon('file',20)}{h(t('extra_bulk_title'))}</h2>
          <button type="button" class="icon-btn modal-close" aria-label="{h(t('close_window'))}">{icon('x',20)}</button></div>
          <div class="modal-body">
          <form id="bulk-extra-form" class="add-client-form" method="post" action="/servers/{h(state['interface'])}/clients/bulk-extra" data-bulk-names>{csrf(request)}
          <p class="info-line">{h(t('extra_bulk_hint'))}</p>
          <p class="bulk-extra-count mono" data-bulk-names-count></p>
          {extra_lines_block('bulk', '', t)}
          <fieldset class="extra-mode"><legend class="sr-only">{h(t('extra_bulk'))}</legend>
          <label class="check-field"><input type="radio" name="mode" value="replace" checked><span>{h(t('extra_mode_replace'))}</span></label>
          <label class="check-field"><input type="radio" name="mode" value="append"><span>{h(t('extra_mode_append'))}</span></label>
          <small>{h(t('extra_mode_hint'))}</small></fieldset>
          <div class="modal-footer"><button class="btn btn-primary" type="submit">{icon('check',16)}{h(t('extra_bulk_save'))}</button></div>
          </form>
          </div>
        </dialog>

        <!-- Batch create modal -->
        <dialog id="batch-client-modal" class="awg-modal">
          <div class="modal-header"><h2>{icon('users',20)}{h(t('batch_title'))}</h2>
          <button type="button" class="icon-btn modal-close" aria-label="{h(t('close_window'))}">{icon('x',20)}</button></div>
          <div class="modal-body">
          <form class="add-client-form" data-batch-download method="post" action="/servers/{h(state['interface'])}/clients/batch">{csrf(request)}
          <p class="info-line">{h(t('batch_hint'))}</p>
          <div class="fields-grid">
            <label class="field" for="batch-prefix"><span>{h(t('batch_prefix'))}</span>
            <input id="batch-prefix" name="prefix" pattern="[A-Za-z0-9][A-Za-z0-9_\\-]*" maxlength="27" required></label>
            {form_field('count','5',t('batch_count'),field_id='batch-count')}
            {form_field('start','1',t('batch_start'),field_id='batch-start')}
            {expiry_field('', 'batch-expires', lang)}
            {form_field('quota_gib','0',t('quota'),required=False,field_id='batch-quota')}
            {policy_extra_fields({'_lang':lang}, 'batch')}
          </div>
          <div class="modal-footer"><button class="btn btn-primary" type="submit">{icon('download',16)}{h(t('batch_create'))}</button></div>
          </form>
          </div>
        </dialog>'''
    current=selected_server(request)
    options=''.join(f'<div class="instance-item {"instance-active" if x["interface"]==current else ""}">'
        f'<div><strong>{h(x["interface"])}</strong><small class="mono">{h(x["subnet"])} · UDP {h(x["port"])}'
        f' · {h(x.get("clients",0))} peers</small></div>'
        f'<span class="pill pill-{ "running" if x["running"] else "stopped"}">{h(t("vpn_running" if x["running"] else "vpn_stopped"))}</span>'
        f'<a class="btn btn-secondary btn-small" href="/server/{h(x["interface"])}">{h(t("server_switch"))}</a>'
        + (f'<form method="post" action="/server/{h(x["interface"])}/{"stop" if x["running"] else "start"}">'
           f'{csrf(request)}<button class="btn btn-secondary btn-small" type="submit">'
           f'{h(t("server_stop" if x["running"] else "server_start"))}</button></form>'
           if 'clients' in x and len(instances)>0 else '')
        + (f'<form method="post" action="/server/{h(x["interface"])}/delete" '
           f'data-confirm="{h(t("server_remove_confirm"))}">{csrf(request)}'
           f'<input class="confirm-name" type="text" name="confirm" required autocomplete="off" spellcheck="false" '
           f'pattern="{h(x["interface"])}" placeholder="{h(x["interface"])}" '
           f'aria-label="{h(t("server_remove_type"))}" title="{h(t("server_remove_type"))}">'
           f'<button class="btn btn-danger btn-small" type="submit">{h(t("server_remove"))}</button></form>'
           if True else '')
        + '</div>' for x in instances)
    servers_html=f'''<section class="card instances-card" id="servers"><div class="section-title"><div>
        <span class="section-overline">SERVERS / INSTANCES</span><h2>{icon('server',20)}{h(t('server_instances'))}</h2>
        <p class="section-subtitle">{h(t('new_server_hint'))}</p></div></div>
        <div class="instance-list">{options}</div>
        <details class="new-instance"><summary class="btn btn-primary">{icon('plus',16)}{h(t('new_server'))}</summary>
        <p class="info-line">{h(t('new_server_note'))}</p>
        <form method="post" action="/server/create">{csrf(request)}<div class="fields-grid">
          {form_field('interface','awg1',t('server_name'),field_id='create-interface')}
          {form_field('subnet','10.77.20.0/24',t('server_subnet'),field_id='create-subnet')}
          {form_field('endpoint',state['endpoint'],t('public_endpoint'),field_id='create-endpoint')}
          {form_field('port','51821',t('server_port'),field_id='create-port')}
          {form_field('mtu','1280',t('mtu_label'),field_id='create-mtu')}
          {form_field('dns',state['dns'],t('client_dns'),field_id='create-dns')}
          {form_field('uplink',state.get('uplink','ens33'),t('server_uplink'),field_id='create-uplink')}
          <label class="field"><span>{h(t('server_mode'))}</span><select name="mode">
          <option value="full">{h(t('full'))}</option><option value="split">{h(t('split'))}</option>
          </select></label></div>
          <button class="btn btn-primary" type="submit">{icon('plus',16)}{h(t('new_server'))}</button></form></details></section>'''

    fields = ''.join([
        form_field('endpoint', state['endpoint'], t('public_endpoint')),
        form_field('port', state['port'], t('server_port')),
        form_field('mtu', state['mtu'], t('mtu_label')),
        form_field('dns', state['dns'], t('client_dns')),
        switch_field('client-to-client', 'client_to_client', 'c2c', state, lang),
        switch_field('host-access', 'host_access', 'host', state, lang),
        *([switch_field('private-access', 'private_access', 'private', state, lang),
           switch_field('ipv6-block', 'ipv6_block', 'ipv6', state, lang, order=('off', 'on'))]
          if state.get('mode') == 'full' else []),
    ])
    obf=state.get('obfuscation') or {}
    obf_labels={key:key for key in OBF_EDIT_FIELDS}
    obf_inputs=''.join(form_field(key, obf.get(key,''), obf_labels[key], required=(key not in ('RekeyAfterTime','RekeyTimeout','RejectAfterTime','KeepaliveTimeout','MaxHandshakeAttempts')))
                       for key in OBF_EDIT_FIELDS if key not in ('RandomTrailers','DisableCookies'))
    obf_inputs+=''.join('<label class="field"><span>'+h(key)+'</span><select name="'+key+'">'
             +''.join('<option value="'+val+'" '+('selected' if obf.get(key,'on')==val else '')+'>'
             +val+'</option>' for val in ('on','off'))+'</select></label>'
             for key in ('RandomTrailers','DisableCookies'))
    static_headers = [str(obf.get(f'H{n}','')) for n in range(1,5)] == ['1','2','3','4']
    static_warning = (f'<p class="obf-static-warning" role="alert">{icon("info",16)}{h(t("obf_static_warning"))}</p>'
                      if static_headers else '')
    advanced=f'''<section class="advanced-box" id="obfuscation"><h3>{icon('settings',16)}{h(t('advanced'))}</h3>
          <p class="info-line">{h(t('advanced_hint'))}</p>{static_warning}
          <div class="obf-generate-controls"><button class="btn btn-secondary" id="generate-obf" type="button">{icon('restart',16)}{h(t('generate'))}</button>
          <label class="obf-timing-switch"><input type="checkbox" id="generate-timings"><span>{'Генерировать тайминги AWG 3.1' if lang=='ru' else 'Generate AWG 3.1 timing ranges'}</span></label></div>
          <p class="obf-help">{'По умолчанию тайминги остаются пустыми; включайте только при необходимости. Изменения применятся после сохранения сервера.' if lang=='ru' else 'Timings remain unset by default. Enable only when needed; save the server to apply changes.'}</p>
          <div class="fields-grid" id="obfuscation-fields">{obf_inputs}</div></section>'''
    saved_notice = (f'<div class="settings-success" role="status">{icon("check",20)}'
                    f'<div><strong>{h(t("settings_saved"))}</strong><p>{h(t("settings_saved_hint"))}</p></div>'
                    f'<a class="btn btn-secondary btn-small" href="/servers/{h(state["interface"])}/clients">{h(t("clients"))}</a></div>'
                    if request.query_params.get('saved') == '1' else '')
    settings = f'''{saved_notice}<section class="card settings-card" id="settings">
        <form method="post" action="/settings" data-confirm="{h(t('confirm_restart'))}">{csrf(request)}
        <div class="config-group-header"><div><h2>{h('Подключение' if lang=='ru' else 'Connection')}</h2>
        <p>{h('Параметры только этого VPN-интерфейса' if lang=='ru' else 'Settings for this VPN instance only')}</p></div></div>
        <div class="fields-grid config-fields">{fields}</div>{advanced}
        <div class="config-savebar"><span>{icon('info',16)}{h(t('settings_hint'))}</span>
        <button class="btn btn-primary" type="submit">{icon('check',18)}{h(t('save_restart'))}</button></div>
        </form></section>'''
    section_titles={'overview':t('server_home'), 'clients':t('server_clients'),
                    'monitoring':t('server_monitor'), 'settings':t('server_settings'),
                    'servers':t('all_servers')}
    if section not in section_titles: raise HTTPException(404)
    # Each route renders only its own section, never an anchor in a giant dashboard.
    section_html={'overview':head.split('<section class="card graph-card"')[0]+'</div>',
                  'clients':clients, 'monitoring':head[head.index('<section class="card graph-card"'):]+history_html,
                  'settings':settings, 'servers':servers_html}[section]
    if section=='overview':
        details = [
            (t('subnet'),state['subnet']),
            (t('udp_port'),str(state['port'])),
            (t('public_endpoint'),state['endpoint']),
            ('MTU',str(state['mtu'])),
            (t('client_dns'),state['dns']),
            (t('mode'),t('full' if state['mode']=='full' else 'split')),
        ]
        details_html=''.join(f'<div class="server-detail"><dt>{h(label)}</dt><dd>{h(value)}</dd></div>' for label,value in details)
        section_html=f'''<div class="server-home-grid">
          <section class="card server-home-card"><div class="server-home-top">
            <div><h2>{h('Состояние' if lang=='ru' else 'Status')}</h2>
              <span class="pill pill-{state_pill}"><span class="dot"></span>{h(t('vpn_running' if running else 'vpn_stopped'))}</span></div>
            <div class="server-state-actions"><a class="btn btn-secondary btn-small" href="/servers/{h(state['interface'])}/monitoring">{h(t('server_monitor'))}</a>
             <form method="post" action="/server/{h(state['interface'])}/{'stop' if running else 'start'}" {'data-confirm="'+h(t('confirm_restart'))+'"' if running else ''}>{csrf(request)}
             <button class="btn {'btn-danger' if running else 'btn-primary'} btn-small" type="submit">{h(t('server_stop' if running else 'server_start'))}</button></form></div></div>
            <div class="server-home-numbers"><div><strong>{len(clients_all)}</strong><span>{h(t('total_clients'))}</span></div>
              <div><strong>{connected_count}</strong><span>{h(t('connected'))}</span></div>
              <div><strong>{h(friendly_size(total_rx+total_tx))}</strong><span>{h(t('total_transfer'))}</span></div></div>
          </section>
          <section class="card server-connection-card"><div class="server-home-top"><h2>{h('Подключение' if lang=='ru' else 'Connection')}</h2>
            <a class="quiet-link" href="/servers/{h(state['interface'])}/settings">{h(t('server_settings'))}{icon('chevron-right',15)}</a></div>
            <dl class="server-details">{details_html}</dl>
          </section></div>'''
    if section=='monitoring':
        section_html = '<div class="server-monitor-stack">' + head[head.index('<section class="card graph-card"'):head.rfind('</section></div>')+10] + history_html + '</div>'
    return page(section_titles[section], section_html, request)


@app.get('/servers')
def servers_page(request: Request):
    require_auth(request)
    return server_content(request, 'servers')


@app.get('/servers/{interface}')
def server_shortcut(request: Request, interface: str):
    require_auth(request)
    if not SERVER_RE.fullmatch(interface): raise HTTPException(404)
    return RedirectResponse(f'/servers/{interface}/overview', status_code=303)


@app.get('/servers/{interface}/{section}')
def server_page(request: Request, interface: str, section: str):
    require_auth(request)
    if section not in ('overview','clients','monitoring','settings') or not SERVER_RE.fullmatch(interface):
        raise HTTPException(404)
    if interface not in [x['interface'] for x in server_list()]: raise HTTPException(404)
    return server_content(request, section)


def _dashboard_plot(name, title, subtitle='', height=144, ru=True):
    'Accessible inline SVG with real series populated by panel.js.'
    # name is either validated awgN or the fixed prefix 'wan'.
    assert name=='wan' or SERVER_RE.fullmatch(name)
    gid='dash-fill-'+name
    return f'''<div class="dash-plot" data-plot="{name}">
      <div class="dash-plot-toolbar"><div><strong>{h(title)}</strong>
      <small>{h(subtitle)}</small></div>
      <div class="dash-periods" role="group" aria-label="{'Период' if ru else 'Period'}">
        <button type="button" data-period="5m">{'5м' if ru else '5m'}</button>
        <button type="button" data-period="15m" class="is-active" aria-pressed="true">{'15м' if ru else '15m'}</button>
        <button type="button" data-period="1h">{'1ч' if ru else '1h'}</button>
      </div></div>
      <div class="dash-plot-area">
        <svg viewBox="0 0 680 {height}" preserveAspectRatio="none" role="img" aria-label="{h(title)}">
          <defs><linearGradient id="{gid}-rx" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#f8b444" stop-opacity=".30"/><stop offset="100%" stop-color="#f8b444" stop-opacity="0"/></linearGradient>
          <linearGradient id="{gid}-tx" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#80a8dc" stop-opacity=".22"/><stop offset="100%" stop-color="#80a8dc" stop-opacity="0"/></linearGradient></defs>
          <path class="dash-grid" d="M0 28H680 M0 67H680 M0 106H680"/>
          <path data-area="rx" fill="url(#{gid}-rx)"/>
          <path data-area="tx" fill="url(#{gid}-tx)"/>
          <path data-line="rx" class="dash-line dash-line-rx"/>
          <path data-line="tx" class="dash-line dash-line-tx"/>
          <line data-cursor x1="0" x2="0" y1="8" y2="{height-12}" class="dash-cursor" visibility="hidden"/>
        </svg>
        <div class="dash-chart-empty" data-chart-empty>{'Сбор данных…' if subtitle!='Traffic history' else 'Collecting data…'}</div>
        <div class="dash-chart-tip" data-chart-tip hidden></div>
      </div>
      <div class="dash-chart-foot"><span data-time-left>{'−15м' if ru else '−15m'}</span><span data-chart-peak>{'Пик' if ru else 'Peak'}: —</span><span data-time-right>{'Сейчас' if ru else 'Now'}</span></div>
    </div>'''


@app.get('/')
def infrastructure_overview(request: Request):
    if not logged(request): return RedirectResponse('/login')
    lang=lang_of(request);t=lambda k:tr(lang,k)
    ru=lang=='ru'
    servers=[x for x in server_list() if SERVER_RE.fullmatch(x.get('interface',''))]
    online=sum(bool(x.get('running')) for x in servers)
    total_clients=sum(int(x.get('clients',0)) for x in servers)
    tx_label='Отправлено' if ru else 'Sent'
    rx_label='Получено' if ru else 'Received'
    dash_metric=lambda key,title,value_title,detail: f'''<article class="host-kpi" data-kpi="{key}">
      <div class="host-kpi-heading"><span>{h(title)}</span><span class="host-kpi-indicator"></span></div>
      <div class="host-kpi-value" id="host-{key}">—</div>
      <div class="host-kpi-detail" id="host-{key}-detail">{h(detail)}</div>
      <svg viewBox="0 0 280 100" preserveAspectRatio="none" class="host-kpi-chart" aria-hidden="true">
        <path d="M0 50H280" class="host-kpi-half"/><path data-kpi-area="{key}"/><path data-kpi-line="{key}"/></svg></article>'''
    cards=''.join(dash_metric(key,title,title,detail) for key,title,detail in [
       ('cpu','Процессор' if ru else 'CPU','Логические ядра' if ru else 'Logical cores'),
       ('ram','Память' if ru else 'RAM','Оперативная память' if ru else 'System memory'),
       ('swap','Подкачка' if ru else 'SWAP','Использование подкачки' if ru else 'Swap usage'),
       ('disk','Диск' if ru else 'DISK','Корневая файловая система' if ru else 'Root filesystem')])
    traffic=_dashboard_plot('wan','Трафик внешнего интерфейса' if ru else 'Uplink traffic',
                            'WAN · RX / TX',174,ru=ru)
    host=f'''<div class="infra-section-head"><h2>{'Система' if ru else 'System'}</h2>
      <span class="infra-pulse"><i></i>{'Автообновление 5 с' if ru else 'Live · 5 s'}</span></div>
      <div class="host-kpi-grid">{cards}</div>
      <div class="host-chart-grid"><section class="host-traffic-panel">
        <div class="host-panel-head"><div><span class="host-panel-eyebrow">{'СЕТЬ / ВНЕШНИЙ ИНТЕРФЕЙС' if ru else 'NETWORK / WAN'}</span>
          <h3>{'Скорость трафика хоста' if ru else 'Host traffic speed'}</h3></div>
          <div class="dash-live-legend"><span><i class="dash-dot rx"></i>{'Получение' if ru else 'Download'} <b id="wan-rx-rate">—</b></span>
          <span><i class="dash-dot tx"></i>{'Отправка' if ru else 'Upload'} <b id="wan-tx-rate">—</b></span></div></div>
        {traffic}
        <div class="host-network-totals"><div><small>{rx_label}</small><strong id="wan-rx-total">—</strong></div>
          <div><small>{tx_label}</small><strong id="wan-tx-total">—</strong></div>
          <div><small>{'Сетевой интерфейс' if ru else 'Uplink'}</small><strong id="wan-interface">—</strong></div></div>
      </section>
      <section class="host-connections-panel"><div class="host-panel-head"><div><span class="host-panel-eyebrow">{'СЕТЬ / СОЕДИНЕНИЯ' if ru else 'NETWORK / SOCKETS'}</span>
        <h3>{'Соединения' if ru else 'Connections'}</h3></div></div>
        <strong class="host-connections-number" id="host-sockets-total">—</strong>
        <span class="host-submetric">{'TCP + UDP сокеты' if ru else 'TCP + UDP sockets'}</span>
        <div class="host-socket-split"><div><i class="dash-dot tx"></i> TCP <b id="host-tcp">—</b></div>
        <div><i class="dash-dot rx"></i> UDP <b id="host-udp">—</b></div></div>
        <svg class="socket-trend" viewBox="0 0 280 116" preserveAspectRatio="none" role="img" aria-label="{'Количество сокетов' if ru else 'Socket count'}">
          <path d="M0 30H280 M0 67H280 M0 103H280" class="dash-grid"/>
          <path data-socket-area></path><path data-socket-line></path></svg>
        <div class="socket-panel-foot">{'TCP: установленные; UDP: сокеты' if ru else 'TCP: established; UDP: sockets'}</div>
      </section></div>
      <div class="host-summary-strip"><div><span>{'Время работы ОС' if ru else 'OS uptime'}</span><b id="host-uptime">—</b></div>
        <div><span>{'Панель · RAM' if ru else 'Panel · RAM'}</span><b id="host-panel-ram">—</b></div>
        <div><span>{'VPN активно' if ru else 'Active VPN servers'}</span><b>{online}/{len(servers)}</b></div>
        <div><span>{'Всего клиентов' if ru else 'Total clients'}</span><b>{total_clients}</b></div></div>'''
    instance_cards=[]
    for info in servers:
        iface=info['interface'];running=bool(info.get('running'))
        count=int(info.get('clients') or 0)
        graph=_dashboard_plot(iface,'Скорость RX / TX' if ru else 'RX / TX speed',
                               'Данные каждого экземпляра' if ru else 'Per-instance traffic',144,ru=ru)
        confirm=('Перезапустить '+iface+'? Клиенты временно отключатся.' if ru else 'Restart '+iface+'? Clients will disconnect briefly.')
        stop_confirm=('Остановить '+iface+'? Все его клиенты потеряют VPN-соединение.' if ru else 'Stop '+iface+'? Its clients will disconnect.')
        action=('stop' if running else 'start')
        action_label=('Остановить' if running else 'Запустить') if ru else ('Stop' if running else 'Start')
        card=f'''<article class="instance-dashboard" data-awg-instance="{h(iface)}">
          <header class="instance-dash-heading"><div class="instance-heading-main">
            <span class="instance-emblem">{icon('server',22)}</span>
            <div><h3>{h(iface)}</h3><p class="instance-dash-meta"><span>{h(info.get('subnet',''))}</span>
              <span>UDP {h(info.get('port',''))}</span></p></div></div>
            <span class="instance-state {'up' if running else 'down'}" data-instance-state><i></i>{'Запущен' if running and ru else 'Running' if running else 'Остановлен' if ru else 'Stopped'}</span></header>
          <div class="instance-speed-row">
            <div><small><i class="dash-dot rx"></i>{'Получение' if ru else 'Download'}</small><strong id="{iface}-rx-rate">—</strong></div>
            <div><small><i class="dash-dot tx"></i>{'Отправка' if ru else 'Upload'}</small><strong id="{iface}-tx-rate">—</strong></div>
            <div><small>{'Онлайн / всего' if ru else 'Online / total'}</small><strong id="{iface}-connected">— / {count}</strong></div>
          </div>{graph}
          <div class="instance-bottom-metrics"><div><span>{rx_label}</span><strong id="{iface}-rx-total">—</strong></div>
            <div><span>{tx_label}</span><strong id="{iface}-tx-total">—</strong></div>
            <div><span>{'Время работы' if ru else 'Uptime'}</span><strong id="{iface}-uptime">—</strong></div></div>
          <footer class="instance-dash-actions">
            <a class="btn btn-primary btn-small" href="/servers/{iface}/overview">{'Управление' if ru else 'Manage'}</a>
            <a class="btn btn-secondary btn-small" href="/servers/{iface}/clients">{'Клиенты' if ru else 'Clients'}</a>
            <a class="btn btn-secondary btn-small" href="/servers/{iface}/settings">{'Настройки' if ru else 'Settings'}</a>
            <details class="instance-action-menu"><summary aria-label="{'Операции с сервером' if ru else 'Server actions'}" title="{'Операции с сервером' if ru else 'Server actions'}">{icon('more',18)}</summary>
             <div class="instance-action-dropdown">'''
        if running:
            card+=f'''<form method="post" action="/server/{iface}/restart" data-confirm="{h(confirm)}">{csrf(request)}
                <button type="submit">{icon('restart',16)}{'Перезапустить' if ru else 'Restart'}</button></form>'''
        card+=f'''<form method="post" action="/server/{iface}/{action}" data-confirm="{h(stop_confirm if running else '')}">{csrf(request)}
                <button type="submit" class="{'danger-action' if running else ''}">{h(action_label)}</button></form></div></details>
          </footer></article>'''
        instance_cards.append(card)
    if not servers:instance_cards.append('<div class="infra-empty">'+h('Серверов пока нет' if ru else 'No servers yet')+'</div>')
    content=f'''<div class="infrastructure-dashboard" data-dashboard="host">
       {host}<div class="infra-section-head instances-title"><div><h2>{'Экземпляры AWG' if ru else 'AWG instances'}</h2>
         <span>{len(servers)} {'серверов' if ru else 'servers'}</span></div>
         <a class="quiet-link" href="/servers">{'Управление серверами' if ru else 'Manage servers'}{icon('chevron-right',16)}</a></div>
       <div class="instance-dash-grid">{''.join(instance_cards)}</div>
       </div>'''
    return page(t('global_overview'),content,request)


@app.post('/settings')
@app.post('/servers/{interface}/settings')
async def settings(request: Request, interface: str = ''):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    lang=lang_of(request)
    payload={k: str(form[k]) for k in ('endpoint','port','mtu','dns','client_to_client','private_access','ipv6_block','host_access') if k in form}
    payload.update({k: str(form[k]) for k in OBF_EDIT_FIELDS if k in form})
    try:
        control(request,'settings',payload)
        audit_event('server_settings_changed',selected_server(request))
    except RuntimeError as exc:
        return error_page(request,tr(lang,'settings_error'),exc)
    return RedirectResponse(f'/servers/{selected_server(request)}/settings?saved=1',status_code=303)

@app.post('/client')
@app.post('/servers/{interface}/clients')
async def create(request: Request, interface: str = ''):
    data = await request.form()
    require_csrf(request, data.get('csrf',''))
    payload = {'name':str(data.get('name','')),
               'comment':str(data.get('comment','')),
               'expires_at':str(data.get('expires_at','')),
               'traffic_limit_bytes':gib_bytes(data.get('quota_gib','0')),
               'telegram_id':str(data.get('telegram_id','')).strip(),
               'owner_export':data.get('owner_export')=='1',
               **policy_extras(data),
               'routed_subnets':str(data.get('routed_subnets','')),
               'i_enabled':'1' if data.get('i_enabled')=='1' else '0',
               **{f'i{n}':str(data.get(f'i{n}','')) for n in range(1,6)}}
    try:
        result = control(request, 'add', payload)
    except RuntimeError as exc:
        return error_page(request, tr(lang_of(request), 'create_error'), exc)
    audit_event('client_added',f"{selected_server(request)}/{result['name']}")
    return RedirectResponse(scoped_client(request, result['name']), status_code=303)


@app.post('/servers/{interface}/clients/batch')
async def create_batch(request: Request, interface: str = ''):
    data = await request.form()
    require_csrf(request, data.get('csrf',''))
    payload = {'prefix':str(data.get('prefix','')).strip(), 'count':str(data.get('count','')), 'start':str(data.get('start','1')),
               'expires_at':str(data.get('expires_at','')), 'traffic_limit_bytes':gib_bytes(data.get('quota_gib','0')),
               **policy_extras(data)}
    try: result = control(request, 'add-batch', payload)
    except RuntimeError as exc: return error_page(request, tr(lang_of(request), 'create_error'), exc)
    created = result['clients']
    audit_event('client_added', f"{selected_server(request)}/{created[0]['name']}..{created[-1]['name']} ({len(created)})")
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for item in created:
            archive.writestr(item['name'] + '.conf', item['config'])
    return Response(buffer.getvalue(), media_type='application/zip', headers={
        'Content-Disposition': f'attachment; filename="{payload["prefix"]}-{len(created)}-clients.zip"',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


def gib_bytes(raw):
    try:
        value=float(raw)
        if not 0<=value<=100000 or not (value < float('inf')):
            raise ValueError()
    except (ValueError,TypeError):
        raise HTTPException(422,detail='Invalid quota (GiB)') from None
    return int(value*1024**3)


def gib_format(value):
    return f'{int(value or 0)/1024**3:.3f}'.rstrip('0').rstrip('.') if value else '0'


def build_client_link(obj, name):
    # The controller supplies only the one requested peer's data after auth.
    # The link carries the configuration without the admin's awg-quick lines.
    return build_vpn_uri(obj.get('link_config') or obj['config'], name=name, server_ip=obj['server_ip'],
                         subnet=obj['subnet'], client_public_key=obj['client_public_key'])


@app.get('/client/{name}')
@app.get('/servers/{interface}/clients/{name}')
def detail(request: Request, name: str, interface: str = ''):
    require_auth(request)
    lang = lang_of(request)
    try:
        obj = control(request,'download', {'name': name})
    except RuntimeError as exc:
        return error_page(request, tr(lang, 'not_available'), exc, status_code=404)
    name_url = quote(name, safe='')
    t = lambda key: tr(lang,key)
    long_cps_warning = f'''<p class="cps-warning">{'Длинная сигнатура I1 может превышать размер QR или MTU. В таком случае используйте .conf или AmneziaVPN Link как текст и проверьте UDP-фрагментацию.' if lang=='ru' else 'Long I1 signatures may exceed QR capacity or UDP MTU. Use the .conf or a text link, and check UDP fragmentation.'}</p>'''
    try:
        share_uri = build_client_link(obj, name)
    except (ValueError, KeyError, TypeError):
        share_uri = None
    safe_name = h(name)
    config = obj['config']
    qr_conf = f'/client/{name_url}/qr?mode=conf'
    qr_vpn = f'/client/{name_url}/qr?mode=vpn'
    qr_conf_available = len(config.encode('utf-8')) <= 2400
    qr_vpn_available = bool(share_uri and len(share_uri.encode('utf-8')) <= 2400)
    # The tab is deliberately disabled rather than inventing a URI for old
    # controllers that do not return a client's public key.
    link_contents = (f'''<div class="cfgx-grid"><figure class="qr-frame">
          {f'<img alt="{h(t("share_link_tab"))} QR" loading="lazy" src="{qr_vpn}">' if qr_vpn_available else f'<p class="qr-too-large">{h(t("qr_overflow"))}</p>'}
          {f'<figcaption><a class="btn btn-secondary btn-small" href="{qr_vpn}&amp;download=1">{h(t("save_qr"))}</a></figcaption>' if qr_vpn_available else ''}
          </figure><div class="cfgx-text-col"><p class="info-line">{h(t('vpn_link_note'))}</p>
          <label class="sr-only" for="cfgx-vpn-text">{h(t('share_link_tab'))}</label>
          <textarea id="cfgx-vpn-text" class="cfgx-text" readonly spellcheck="false">{h(share_uri)}</textarea>
          <div class="cfgx-actions"><button type="button" class="btn btn-secondary" data-copy-target="cfgx-vpn-text">{h(t('copy'))}</button>
          <a class="btn btn-primary" href="/client/{name_url}/vpn-link?download=1">{h(t('save_vpn'))}</a></div></div></div>'''
          if share_uri else f'<p role="status" class="info-line">{h(t("link_unavailable"))}</p>')
    link_disabled = '' if share_uri else ' disabled aria-disabled="true"'
    qr_conf_display = (f'<img alt="{h(t("share_conf_tab"))} QR" loading="lazy" src="{qr_conf}">' if qr_conf_available
                       else f'<p class="qr-too-large">{h(t("qr_overflow"))}</p>')
    qr_conf_download = (f'<figcaption><a class="btn btn-secondary btn-small" href="{qr_conf}&amp;download=1">{h(t("save_qr"))}</a></figcaption>'
                       if qr_conf_available else '')
    contents = f'''<section class="card detail-card cfgx-dialog" aria-label="{h(t('share_config'))}">
        <div class="section-title cfgx-heading"><div><span class="section-overline">PEER / EXPORT</span>
        <h2>{icon('file',21)}{h(t('share_config'))}: <span class="mono">{safe_name}</span></h2></div>
        <a class="btn btn-secondary btn-small" href="/#clients">{icon('arrow',16)}{h(t('close_window'))}</a></div>
        <div class="cfgx-security">{icon('lock',16)}{h(t('sensitive_data'))}</div>
        <div class="cfgx-tabs" role="tablist" aria-label="{h(t('share_config'))}">
          <button class="cfgx-tab is-active" type="button" role="tab" id="cfgx-tab-conf" aria-controls="cfgx-panel-conf" aria-selected="true" data-tab-target="cfgx-panel-conf">{h(t('share_conf_tab'))}</button>
          <button class="cfgx-tab" type="button" role="tab" id="cfgx-tab-vpn" aria-controls="cfgx-panel-vpn" aria-selected="false" data-tab-target="cfgx-panel-vpn"{link_disabled}>{h(t('share_link_tab'))}</button>
        </div>
        <section class="cfgx-tab-panel" role="tabpanel" id="cfgx-panel-conf" aria-labelledby="cfgx-tab-conf">
          <div class="cfgx-grid"><figure class="qr-frame">
            {qr_conf_display}{qr_conf_download}</figure>
            <div class="cfgx-text-col"><p class="info-line">{h(t('conf_qr_note'))}</p></div></div>
          <div class="cfgx-config-content"><h3>{h(t('conf_contents'))}</h3>
            <details class="cfgx-config-details" id="cfgx-config-details" open>
              <summary>{h(t('show_conf_contents'))}</summary>
              <textarea id="cfgx-conf-text" class="cfgx-text" readonly spellcheck="false" aria-label="{h(t('conf_contents'))}">{h(config)}</textarea>
            </details>
            <div class="cfgx-actions"><button class="btn btn-secondary" type="button" data-copy-target="cfgx-conf-text">{h(t('copy'))}</button>
            <a class="btn btn-primary" href="/client/{name_url}/download">{icon('file',16)}{h(t('download'))}</a></div>
          </div></section>
        <section class="cfgx-tab-panel" role="tabpanel" id="cfgx-panel-vpn" aria-labelledby="cfgx-tab-vpn" hidden>{link_contents}</section>
        <p class="sr-only" aria-live="polite" id="copy-status" data-copy-ok="{h(t('copy_ok'))}" data-copy-failed="{h(t('copy_failed'))}"></p>
        </section>'''
    network_form = f'''<section class="card detail-card client-options">
        <div class="section-title"><h2>{icon('network',20)}{h(t('client_options'))}</h2></div>
        <form method="post" action="/client/{name_url}/network" data-confirm="{h(t('routes_apply_warning'))}">
          {csrf(request)}
          <label class="field" for="edit-client-ip"><span>{h(t('peer_address'))}</span>
          <input id="edit-client-ip" name="ip" type="text" inputmode="decimal" autocomplete="off" spellcheck="false" value="{h(obj.get('ip',''))}" required>
          <small>{h(t('peer_address_hint'))}</small></label>
          <label class="field" for="edit-routed-subnets"><span>{h(t('peer_routes'))}</span>
          <textarea id="edit-routed-subnets" name="routed_subnets" rows="3" placeholder="192.168.50.0/24">{h(obj.get('routed_subnets',''))}</textarea>
          <small>{h(t('peer_routes_hint'))}</small></label>
          {cps_block('detail', obj, obj.get('i_enabled'), lang, extra=long_cps_warning)}
          {extra_lines_block('detail', obj.get('extra_lines', ''), t)}
          <p class="info-line">{h(t('client_network_changed'))}</p>
          <button type="submit" class="btn btn-primary">{icon('check',16)}{h(t('save_client_network'))}</button>
        </form></section>'''
    policy_form=f'''<section class="card detail-card client-policy">
      <div class="section-title"><h2>{icon('clock',20)}{h(t('policy'))}</h2></div>
      <p class="info-line">{h(t('policy_note'))}</p>
      <p>{h(t('usage'))}: <strong>{h(gib_format(obj.get('used_bytes',0)))} GiB</strong></p>
      <form method="post" action="/client/{name_url}/policy">{csrf(request)}
      <div class="fields-grid">
        {form_field('comment',obj.get('comment',''),t('comment'),required=False,field_id='policy-comment')}
        {expiry_field(obj.get('expires_at') or '', 'policy-expires', lang)}
        {form_field('quota_gib',gib_format(obj.get('traffic_limit_bytes',0)),t('quota'),required=False,field_id='policy-quota')}
        {form_field('telegram_id',obj.get('telegram_id') or '',t('telegram_id'),t('telegram_id_hint'),required=False,field_id='policy-telegram')}
        {policy_extra_fields({**obj,'_lang':lang}, 'policy')}
      </div><label class="check-field"><input type="checkbox" name="owner_export" value="1"{' checked' if obj.get('owner_export') else ''}><span>{h(t('owner_export'))}</span></label><button class="btn btn-primary" type="submit">{h(t('save_policy'))}</button>
      </form></section>'''
    return page(t('client') + ' ' + name,
                '<div class="client-detail">' + contents + network_form + policy_form
                + sessions_section(request, name, t, lang) + '</div>', request)


@app.post('/client/{name}/network')
@app.post('/servers/{interface}/clients/{name}/network')
async def client_network(request: Request, name: str, interface: str = ''):
    data = await request.form()
    require_csrf(request, data.get('csrf', ''))
    payload = {'name':name, 'routed_subnets':str(data.get('routed_subnets','')),
               'i_enabled':'1' if data.get('i_enabled')=='1' else '0',
               **{f'i{n}':str(data.get(f'i{n}','')) for n in range(1,6)}}
    if 'extra_lines' in data:
        payload['extra_lines'] = str(data.get('extra_lines',''))
    address = str(data.get('ip','')).strip()
    if address:
        payload['ip'] = address
    try:
        control(request,'client-network',payload)
        audit_event('client_modified',f'{selected_server(request)}/{name}')
    except RuntimeError as exc:
        return error_page(request,tr(lang_of(request),'error'),exc)
    return RedirectResponse(scoped_client(request,name),status_code=303)


@app.post('/client/{name}/policy')
@app.post('/servers/{interface}/clients/{name}/policy')
async def policy_update(request: Request, name: str, interface: str = ''):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    payload={'name':name,'comment':str(form.get('comment','')),
             'expires_at':str(form.get('expires_at','')),
             'traffic_limit_bytes':gib_bytes(form.get('quota_gib','0')),
             'telegram_id':str(form.get('telegram_id','')).strip(),
             'owner_export':form.get('owner_export')=='1', **policy_extras(form)}
    try: control(request,'client-policy',payload)
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'error'),exc)
    audit_event('client_modified',f'{selected_server(request)}/{name}')
    return RedirectResponse(scoped_client(request,name),status_code=303)


@app.get('/api/history')
@app.get('/servers/{interface}/api/history')
def history_api(request: Request, window: str = '24h', interface: str = ''):
    require_auth(request)
    if window not in ('24h','7d','30d'): raise HTTPException(422)
    try: result=control(request,'history',{'window':window})
    except RuntimeError: raise HTTPException(503)
    return Response(json.dumps(result),media_type='application/json',
                    headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.get('/client/{name}/download')
@app.get('/servers/{interface}/clients/{name}/download')
def download(request: Request, name: str, interface: str = ''):
    require_auth(request)
    obj = client_export(request, name)
    return Response(obj['config'], media_type='application/octet-stream',
                    headers={'Content-Disposition': f'attachment; filename="{name}.conf"',
                             'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@app.get('/client/{name}/vpn-link')
@app.get('/servers/{interface}/clients/{name}/vpn-link')
def vpn_link(request: Request, name: str, download: bool = False, interface: str = ''):
    require_auth(request)
    obj = client_export(request, name)
    try:
        uri = build_client_link(obj, name)
    except (ValueError, KeyError, TypeError):
        raise HTTPException(422, detail=tr(lang_of(request), 'link_unavailable')) from None
    headers = {'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'}
    if download:
        headers['Content-Disposition'] = f'attachment; filename="{name}.vpn"'
    return Response(uri + '\n', media_type='text/plain; charset=utf-8', headers=headers)


@app.get('/client/{name}/qr')
@app.get('/servers/{interface}/clients/{name}/qr')
def qr(request: Request, name: str, mode: str = 'conf', download: bool = False, interface: str = ''):
    require_auth(request)
    if mode not in ('conf', 'vpn'):
        raise HTTPException(404)
    obj = client_export(request, name)
    if mode == 'vpn':
        try:
            payload = build_client_link(obj, name)
        except (ValueError, KeyError, TypeError):
            raise HTTPException(422, detail=tr(lang_of(request), 'link_unavailable')) from None
    else:
        payload = obj['config']
    try:
        pic = qrcode.make(payload, error_correction=qrcode.constants.ERROR_CORRECT_L)
    except (qrcode.exceptions.DataOverflowError, ValueError):
        raise HTTPException(status_code=422, detail=tr(lang_of(request), 'qr_overflow')) from None
    buffer = io.BytesIO()
    pic.save(buffer, format='PNG')
    headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options':'nosniff'}
    if download:
        headers['Content-Disposition'] = f'attachment; filename="{name}-{mode}-qr.png"'
    return Response(buffer.getvalue(), media_type='image/png', headers=headers)


@app.post('/clients/bulk-delete')
@app.post('/servers/{interface}/clients/bulk-delete')
async def clients_bulk_delete(request: Request, interface: str = ''):
    form = await request.form()
    require_csrf(request, form.get('csrf', ''))
    names = form.getlist('names')
    if (not 1 <= len(names) <= 256 or len(set(names)) != len(names)
            or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}', name) for name in names)):
        raise HTTPException(422, detail='Invalid client selection')
    try:
        control(request, 'delete-batch', {'names': names})
        for name in names:
            audit_event('client_deleted', f'{selected_server(request)}/{name}')
    except RuntimeError as exc:
        return error_page(request, tr(lang_of(request), 'error'), exc)
    return RedirectResponse(scoped_prefix(request)+'/clients' if scoped_prefix(request) else '/servers/'+selected_server(request)+'/clients', status_code=303)


@app.post('/servers/{interface}/clients/bulk-extra')
async def clients_bulk_extra(request: Request, interface: str = ''):
    form = await request.form()
    require_csrf(request, form.get('csrf', ''))
    names = form.getlist('names')
    mode = str(form.get('mode', 'replace'))
    if (not 1 <= len(names) <= 256 or len(set(names)) != len(names) or mode not in ('replace', 'append')
            or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}', name) for name in names)):
        raise HTTPException(422, detail='Invalid client selection')
    try:
        result = control(request, 'client-extra', {'names': names, 'mode': mode,
                                                   'extra_lines': str(form.get('extra_lines', ''))})
        for name in result.get('updated', []):
            audit_event('client_modified', f'{selected_server(request)}/{name}')
    except RuntimeError as exc:
        return error_page(request, tr(lang_of(request), 'error'), exc)
    return RedirectResponse(scoped_prefix(request)+'/clients' if scoped_prefix(request) else '/servers/'+selected_server(request)+'/clients', status_code=303)


@app.post('/client/{name}/{action}')
@app.post('/servers/{interface}/clients/{name}/{action}')
def client_operation(request: Request, name: str, action: str, csrf: str = Form(...), interface: str = ''):
    require_csrf(request, csrf)
    if action not in ('enable', 'disable', 'delete'):
        raise HTTPException(404)
    try:
        control(request,action, {'name': name})
        audit_event({'enable':'client_enabled','disable':'client_disabled','delete':'client_deleted'}[action],f'{selected_server(request)}/{name}')
    except RuntimeError as exc:
        return error_page(request, tr(lang_of(request), 'error'), exc)
    return RedirectResponse(scoped_prefix(request)+'/clients' if scoped_prefix(request) else '/', status_code=303)


# Maintenance panels are fetched/rendered independently. A failed backup/audit
# command must not make the diagnostics tab unavailable (or vice versa).
MAINTENANCE_TABS = (
    ('diagnostics', 'maint_diagnostics', 'activity'),
    ('backups', 'maint_backups', 'archive'),
    ('restore', 'maint_restore', 'restart'),
    ('profiles', 'maint_profiles', 'file'),
    ('security', 'maint_security', 'lock'),
    ('telegram', 'maint_telegram', 'radio'),
    ('logs', 'maint_logs', 'logs'),
    ('audit', 'maint_audit', 'list'),
    ('system', 'maint_system', 'terminal'),
)

DIAG_LABELS = {
    'kernel':('maint_kern','cpu'), 'installed_module':('maint_mod_installed','layers'),
    'loaded_module':('maint_mod_loaded','shield'), 'dkms':('maint_dkms','hard-drive'),
    'device':('maint_device','server'), 'forwarding':('maint_forward','route'),
    'service':('maint_service','activity'), 'secure_boot':('maint_secureboot','lock'),
    'panel':('maint_panel','globe'),
}


def diagnostic_card(lang, key, value):
    if not isinstance(value,dict): return ''
    t=lambda key:tr(lang,key)
    label_key,icon_name=DIAG_LABELS.get(key,(None,'info'))
    title=t(label_key) if label_key else key.replace('_',' ').title()
    ok=value.get('ok') is True
    raw=str(value.get('output') or '')
    short=raw.strip().splitlines()[0] if raw.strip() else t('maint_missing')
    if key=='device':
        match=re.search(r'awg(?:0|[1-9][0-9]?)',short)
        if match:short=f'{match.group(0)} · '+('UP' if ',UP,' in short else t('maint_unknown'))
    elif key=='dkms':
        short='installed' if 'installed' in short.lower() else short[:64]
    elif len(short)>80:short=short[:77]+'…'
    if key=='forwarding': short=t('maint_status_enabled') if short=='1' else t('maint_status_disabled') if short=='0' else short
    if key in ('service','panel') and short=='active':short=t('maint_status_active')
    return f'''<div class="diag-row {'diag-ok' if ok else 'diag-bad'}">
      <span class="diag-icon">{icon(icon_name,18)}</span>
      <div class="diag-entry"><strong>{h(title)}</strong><span>{h(short)}</span></div>
      <span class="diag-state"><span class="system-status-dot {'is-up' if ok else 'is-down'}"></span>
        {h(t('maint_healthy' if ok else 'maint_attention'))}</span>
      <details class="diag-details"><summary aria-label="{h(t('maint_details'))}">{icon('chevron-right',16)}</summary>
        <pre>{h(raw or t('maint_missing'))}</pre></details></div>'''


@app.get('/maintenance')
def maintenance(request: Request, tab: str = 'diagnostics'):
    require_auth(request)
    lang=lang_of(request);t=lambda k:tr(lang,k)
    known={key for key, _, _ in MAINTENANCE_TABS}
    if tab not in known: raise HTTPException(status_code=404,detail='Unknown maintenance section')

    nav=''.join(f'<a class="maint-nav-link{" is-active" if key==tab else ""}" '
                f'href="/maintenance?tab={key}" aria-current="{"page" if key==tab else "false"}">'
                f'{icon(glyph,19)}<span>{h(t(label))}</span></a>'
                for key,label,glyph in MAINTENANCE_TABS)
    info_key={
        'diagnostics':'maint_diagnostics_hint','backups':'maint_backups_hint','restore':'maint_restore_hint',
        'profiles':'maint_profile_hint','security':'maint_security_hint','audit':'maint_audit_hint',
        'telegram':'maint_telegram_hint','logs':'maint_logs_hint',
        'system':'maint_system_hint'}
    section_title=next(t(label) for key,label,_ in MAINTENANCE_TABS if key==tab)
    body=f'''<div class="maint-workspace"><nav class="maint-tabs" aria-label="{h(t('maint_choose'))}">
      {nav}</nav>
      <div class="maint-panel" id="maintenance-panel"><div class="maint-panel-heading">
      <div><h2>{h(section_title)}</h2><p>{h(t(info_key[tab]))}</p></div>
      </div>'''
    try:
        if tab in ('diagnostics','system'):
            diag=control(request,'diagnostics')
            if not isinstance(diag,dict): raise RuntimeError('Invalid diagnostics data')
            items=[(k,v) for k,v in diag.items() if isinstance(v,dict)]
            passed=sum(v.get('ok') is True for _,v in items)
            if tab=='diagnostics':
                core_keys=('kernel','installed_module','loaded_module','dkms','secure_boot')
                runtime_keys=('device','forwarding','service','panel')
                known_keys=set(core_keys+runtime_keys)
                def diag_group(title,keys):
                    rows=''.join(diagnostic_card(lang,k,diag[k]) for k in keys if k in diag)
                    return f'<section class="diag-group"><h3>{h(title)}</h3><div class="diag-list">{rows}</div></section>' if rows else ''
                checks=(diag_group('Платформа и модуль' if lang=='ru' else 'Platform and module',core_keys)+
                        diag_group('Сеть и службы' if lang=='ru' else 'Network and services',runtime_keys)+
                        diag_group('Прочее' if lang=='ru' else 'Other',tuple(k for k,_ in items if k not in known_keys)))
                checked=datetime.now(timezone.utc).strftime('%H:%M UTC')
                body+=f'''<div class="diagnostics-toolbar"><span class="system-status-dot {'is-up' if passed==len(items) else 'is-down'}"></span>
                    <strong>{passed} / {len(items)}</strong><span>{h(t('maint_checks_passed'))}</span>
                    <span class="diagnostics-checked">{h(checked)}</span>
                    <a class="quiet-link" href="/maintenance?tab=diagnostics">{icon('restart',15)}{h(t('maint_refresh'))}</a></div>
                    {checks}'''
            else:
                core=''.join(diagnostic_card(lang,k,diag[k]) for k in ('kernel','installed_module','loaded_module','dkms') if k in diag)
                upcoming=diag.get('next_kernel') or {}
                if upcoming.get('ok') is False:
                    body+=f'<p class="error-message" role="alert">{h(t("next_kernel_bad").format(version=upcoming.get("output") or "?"))}</p>'
                body+=f'''<div class="health-grid health-grid-compact">{core}</div>
                 <section class="maint-command-box"><h3>{icon('terminal',18)}{h(t('maint_system_cmds'))}</h3>
                 <p>{h(t('maint_system_hint_vpn'))}</p>
                 <code>sudo awg31 doctor</code><code>sudo awg31 status</code><code>sudo awg31 restart-panel</code>
                 </section>'''
        elif tab in ('backups','restore'):
            backups=ctl('backup-list',{}).get('backups',[])
            if tab=='backups':
                policy_reply=ctl('backup-policy',{})
                remote=ctl('backup-remote',{})
                policy=policy_reply.get('policy') or {'frequency':'off','hour':3,'minute':0,'weekday':0,
                       'retention_days':30,'max_copies':20}
                cards=''.join(f'''<article class="backup-item"><div class="backup-icon">{icon('archive',20)}</div>
                  <div class="backup-meta"><strong>{h(item['name'])}</strong><span>{h(item.get('created_at',''))} UTC · {h(human_size(item['size']))}</span></div>
                  <a class="btn btn-secondary btn-small" href="/maintenance/backup/{quote(item['name'],safe='')}">{icon('download',17)}{h(t('backup_download'))}</a>
                  <form class="inline" method="post" action="/maintenance/backup/delete" data-confirm="{h(t('backup_delete_confirm'))}">
                  {csrf(request)}<input type="hidden" name="name" value="{h(item['name'])}">
                  <button class="btn btn-danger btn-small" type="submit">{icon('trash',16)}{h(t('backup_delete'))}</button></form></article>'''
                  for item in backups)
                freq_options=''.join(f'<option value="{x}" {"selected" if policy["frequency"]==x else ""}>{h(t("backup_"+x))}</option>'
                     for x in ('off','daily','weekly'))
                weekdays = (('Пн','Вт','Ср','Чт','Пт','Сб','Вс') if lang=='ru'
                            else ('Mon','Tue','Wed','Thu','Fri','Sat','Sun'))
                weekday_opts=''.join(f'<option value="{i}" {"selected" if int(policy["weekday"])==i else ""}>{h(day)}</option>'
                                     for i,day in enumerate(weekdays))
                enc_enabled = ctl('backup-encryption',{}).get('enabled', False)
                enc_class = 'encryption-enabled' if enc_enabled else 'encryption-disabled'
                enc_icon = 'lock' if enc_enabled else 'info'
                enc_text = t('enc_on') if enc_enabled else t('enc_off')
                enc_change_form = '' if not enc_enabled else f'''<details class="cps-details"><summary>{h(t('enc_change'))}</summary>
                     <p class="info-line">{h(t('enc_change_hint'))}</p>
                     <form method="post" action="/maintenance/backup/encryption/change">{csrf(request)}
                     <div class="fields-grid"><label class="field"><span>{h(t('enc_passphrase_new'))}</span><input type="password" name="passphrase" required minlength="16" maxlength="200" autocomplete="new-password"></label>
                     <label class="field"><span>{h(t('enc_passphrase_repeat'))}</span><input type="password" name="confirm" required minlength="16" maxlength="200" autocomplete="new-password"></label>
                     <label class="field"><span>{h(t('panel_password'))}</span><input type="password" name="password" required autocomplete="current-password"></label></div>
                     <button class="btn btn-primary" type="submit">{icon('lock',16)}{h(t('enc_change'))}</button></form></details>'''
                enc_fields = '' if enc_enabled else f'''<div class="fields-grid"><label class="field"><span>{h(t('enc_passphrase'))}</span><input type="password" name="passphrase" required minlength="16" maxlength="200" autocomplete="new-password"></label><label class="field"><span>{h(t('enc_passphrase_repeat'))}</span><input type="password" name="confirm" required minlength="16" maxlength="200" autocomplete="new-password"></label></div><p class="info-line">{h(t('enc_passphrase_hint'))}</p>'''
                body+=f'''<section class="maint-info-block"><span class="info-chip">{h(t('maint_backup_count'))}: {len(backups)}</span>
                  <p>{h(t('backup_global_note'))}</p><p>{h(t('backup_secret'))}</p>
                  <form method="post" action="/maintenance/backup">{csrf(request)}
                  <button class="btn btn-primary" type="submit">{icon('plus',19)}{h(t('backup_make'))}</button></form></section>

                  <section class="backup-encryption-panel">
                    <h3>{icon('lock',18)}{'Шифрование резервных копий' if lang=='ru' else 'Backup Encryption'}</h3>
                    <div class="encryption-status {enc_class}">{icon(enc_icon,14)}{h(enc_text)}</div>
                    <form method="post" action="/maintenance/backup/encryption/{'disable' if enc_enabled else 'enable'}">{csrf(request)}
                     {enc_fields}
                     <div class="fields-grid"><label class="field"><span>{h(t('panel_password'))}</span><input type="password" name="password" required autocomplete="current-password"></label></div>
                     <button class="btn {'btn-danger' if enc_enabled else 'btn-primary'}" type="submit"
                       {'data-confirm="'+h(t('enc_disable_confirm'))+'"' if enc_enabled else ''}>
                       {icon('lock',16)}{h(t('enc_disable' if enc_enabled else 'enc_enable'))}
                     </button></form>
                     {enc_change_form}
                     <p class="info-line">{h(t('enc_restore_note'))}</p>
                   </section>

                   <p class="info-line">{h(t('remote_on') + ' ' + str(remote.get('target','')) if remote.get('configured') else t('remote_off'))}</p>
                  <div class="backup-list">{cards or '<p class="empty-state">'+h(t('maint_no_backups'))+'</p>'}</div>
                  <section class="backup-policy-card"><div class="section-title"><h3>{icon('clock',20)}{h(t('backup_policy_title'))}</h3></div>
                   <p class="info-line">{h(t('backup_policy_note'))}</p>
                   <form method="post" action="/maintenance/backup/policy">{csrf(request)}
                     <div class="backup-policy-grid">
                       <label class="field"><span>{h(t('backup_frequency'))}</span><select name="frequency" id="backup-frequency">{freq_options}</select></label>
                       <label class="field"><span>{h(t('backup_hour'))}</span><input type="number" name="hour" min="0" max="23" value="{h(policy['hour'])}" required></label>
                       <label class="field"><span>{h(t('backup_minute'))}</span><input type="number" name="minute" min="0" max="59" value="{h(policy['minute'])}" required></label>
                       <label class="field"><span>{h(t('backup_weekday'))}</span><select name="weekday">{weekday_opts}</select></label>
                       <label class="field"><span>{h(t('backup_keep_days'))}</span><input type="number" name="retention_days" min="1" max="365" value="{h(policy['retention_days'])}" required></label>
                       <label class="field"><span>{h(t('backup_keep_count'))}</span><input type="number" name="max_copies" min="1" max="30" value="{h(policy['max_copies'])}" required></label>
                     </div><button type="submit" class="btn btn-primary">{icon('check',16)}{h(t('backup_policy_save'))}</button>
                   </form></section>'''
            else:
                entries=''.join(f'''<option value="{h(item['name'])}">{h(item['name'])} · {h(human_size(item['size']))}</option>''' for item in backups)
                body+=f'''<div class="maint-warning">{icon('alert',20)}<p>{h(t('maint_restore_warning_short'))}</p></div>
                  <section class="restore-picker-panel"><h3>{icon('archive',20)}{h(t('backup_select'))}</h3>
                  <p class="info-line">{h(t('backup_global_note'))}</p>
                  <form method="post" action="/maintenance/restore" class="restore-form" data-confirm="{h(t('restore_warn'))}">{csrf(request)}
                     <label class="field"><span>{h(t('backup_select'))}</span>
                     <select id="backup-restore-selection" name="name" required>{entries}</select></label>
                     <label class="field"><span>{h(t('restore_confirm'))}</span>
                     <input type="text" name="confirmation" autocomplete="off" required placeholder="{'ВОССТАНОВИТЬ' if lang=='ru' else 'RESTORE'}"></label>
                     <button type="submit" class="btn btn-danger" {'disabled' if not backups else ''}>{icon('restart',17)}{h(t('backup_restore'))}</button>
                  </form><form method="post" action="/maintenance/backup/check" class="backup-check-form">{csrf(request)}
                     <label class="field"><span>{h(t('backup_check'))}</span><select name="name" required>{entries}</select></label>
                     <button type="submit" class="btn btn-secondary" {'disabled' if not backups else ''}>{icon('check',17)}{h(t('backup_check'))}</button>
                  </form></section>'''
        elif tab=='profiles':
            members=server_list()
            for server in members:
                iface=server['interface']
                if not SERVER_RE.fullmatch(iface): continue
                body+=f'''<section class="maint-form-panel"><div class="scope-banner">
                 {icon('server',18)}<strong>{h(iface)}</strong><span>{h(server['subnet'])} · UDP {h(server['port'])}</span></div>
                 <div class="section-title"><h3>{icon('file',19)}{h(t('profile'))} · {h(iface)}</h3></div>
                 <p>{h(t('profile_note'))}</p>
                 <a class="btn btn-secondary" href="/servers/{h(iface)}/settings/profile">{icon('download',18)}{h(t('profile_download'))}</a>
                 <form method="post" action="/servers/{h(iface)}/settings/profile" data-confirm="{h(t('confirm_import'))}">{csrf(request)}
                 <label class="field"><span>{h(t('profile_content'))} · {h(iface)}</span>
                 <textarea name="profile" rows="5" required maxlength="16000" spellcheck="false"></textarea></label>
                 <button class="btn btn-primary" type="submit">{h(t('profile_import'))} · {h(iface)}</button></form></section>'''
        elif tab=='security':
            body+=f'''<section class="maint-form-panel"><h3>{icon('key',19)}{h(t('password_change'))}</h3>
                <form method="post" action="/maintenance/password">{csrf(request)}
                <div class="fields-grid"><label class="field"><span>{h(t('password_old'))}</span>
                <input type="password" name="old" required autocomplete="current-password"></label>
                <label class="field"><span>{h(t('password_new'))}</span>
                <input type="password" name="new" minlength="12" required autocomplete="new-password"></label>
                <label class="field"><span>{h(t('password_confirm'))}</span>
                <input type="password" name="confirm" minlength="12" required autocomplete="new-password"></label></div>
                <button class="btn btn-primary" type="submit">{icon('lock',18)}{h(t('password_change'))}</button></form>
                </section>'''
            if read_auth().get('totp_secret'):
                secret=base64.b32encode(secrets.token_bytes(20)).decode()
                uri='otpauth://totp/AWG31%20Console:admin?secret='+secret+'&issuer=AWG31%20Console'
                picture=io.BytesIO(); qrcode.make(uri).save(picture,format='PNG')
                new_qr_base64 = base64.b64encode(picture.getvalue()).decode()
                body+=f'''<section class="maint-form-panel"><h3>{icon('shield',19)}{h(t('totp_title'))}</h3>
                <p class="info-line">{h(t('totp_on'))} {h(t('totp_lost'))}</p>
                <details class="totp-regenerate">
                <summary class="btn btn-secondary">{icon('restart',16)}{'Перегенерировать ключ' if lang=='ru' else 'Regenerate key'}</summary>
                <div class="totp-new-key">
                <p class="info-line">{'Новый ключ TOTP' if lang=='ru' else 'New TOTP key'}</p>
                <p><img class="totp-qr" width="200" height="200" alt="TOTP QR" src="data:image/png;base64,{new_qr_base64}"></p>
                <p>{h(t('totp_secret'))}: <code class="totp-secret-display">{secret}</code></p>
                <p class="info-line">{'Сохраните ключ перед перегенерацией. Старый ключ перестанет работать после применения.' if lang=='ru' else 'Save the key before regenerating. The old key will stop working after applying.'}</p>
                <form method="post" action="/maintenance/totp/regenerate">{csrf(request)}
                <input type="hidden" name="secret" value="{secret}">
                <div class="fields-grid"><label class="field"><span>{h(t('password'))}</span>
                <input type="password" name="password" required autocomplete="current-password"></label>
                <label class="field"><span>{h(t('totp_code_current'))}</span>
                <input name="current_code" inputmode="numeric" maxlength="7" required autocomplete="one-time-code"></label>
                <label class="field"><span>{h(t('totp_code_new'))}</span>
                <input name="code" inputmode="numeric" maxlength="7" required autocomplete="one-time-code"></label></div>
                <button class="btn btn-primary" type="submit">{icon('shield',18)}{'Применить новый ключ' if lang=='ru' else 'Apply new key'}</button></form>
                </div></details>
                <form method="post" action="/maintenance/totp/disable" class="totp-disable-form">{csrf(request)}
                <div class="fields-grid"><label class="field"><span>{h(t('password'))}</span>
                <input type="password" name="password" required autocomplete="current-password"></label>
                <label class="field"><span>{h(t('totp_code'))}</span>
                <input name="code" inputmode="numeric" maxlength="7" required autocomplete="one-time-code"></label></div>
                <button class="btn btn-danger" type="submit">{h(t('totp_disable'))}</button></form></section>'''
            else:
                secret=base64.b32encode(secrets.token_bytes(20)).decode()
                uri='otpauth://totp/AWG31%20Console:admin?secret='+secret+'&issuer=AWG31%20Console'
                picture=io.BytesIO(); qrcode.make(uri).save(picture,format='PNG')
                body+=f'''<section class="maint-form-panel"><h3>{icon('shield',19)}{h(t('totp_title'))}</h3>
                <p class="info-line">{h(t('totp_off_hint'))}</p>
                <p><img class="totp-qr" width="220" height="220" alt="TOTP QR" src="data:image/png;base64,{base64.b64encode(picture.getvalue()).decode()}"></p>
                <p>{h(t('totp_secret'))}: <code>{secret}</code></p>
                <form method="post" action="/maintenance/totp/enable">{csrf(request)}
                <input type="hidden" name="secret" value="{secret}">
                <div class="fields-grid"><label class="field"><span>{h(t('password'))}</span>
                <input type="password" name="password" required autocomplete="current-password"></label>
                <label class="field"><span>{h(t('totp_code'))}</span>
                <input name="code" inputmode="numeric" maxlength="7" required autocomplete="one-time-code"></label></div>
                <button class="btn btn-primary" type="submit">{icon('shield',18)}{h(t('totp_enable'))}</button></form></section>'''
        elif tab=='telegram':
            bot=ctl('telegram-status',{})
            sub='notify' if request.query_params.get('sub')=='notify' and bot.get('configured') else 'panel'
            def tg_row(title, hint, control, row_class=''):
                return (f'<div class="tg-row{" "+row_class if row_class else ""}"><div class="tg-row-text"><strong>{h(title)}</strong>'
                        f'{"<small>"+h(hint)+"</small>" if hint else ""}</div><div class="tg-row-control">{control}</div></div>')
            def tg_switch(name, checked, label):
                return (f'<label class="tg-switch"><input type="checkbox" role="switch" name="{name}" value="1"'
                        f'{" checked" if checked else ""} aria-label="{h(label)}"><span aria-hidden="true"></span></label>')
            def tg_lang_select(current):
                return ('<select name="lang">'+''.join(f'<option value="{v}"{" selected" if v==current else ""}>{label}</option>'
                                                       for v,label in (('ru','Русский'),('en','English')))+'</select>')
            def tg_token(placeholder, required):
                return (f'<div class="tg-inline"><input id="tg-token" type="password" name="token" maxlength="100" autocomplete="off" '
                        f'spellcheck="false"{" required" if required else ""} pattern="[0-9]{{5,14}}:[a-zA-Z0-9_\\-]{{30,60}}" '
                        f'title="{h(t("tg_token_hint"))}" placeholder="{h(placeholder)}">'
                        f'<button class="btn btn-secondary tg-eye" type="button" data-reveal="tg-token" aria-label="{h(t("tg_reveal"))}" '
                        f'title="{h(t("tg_reveal"))}">{icon("eye",17)}</button>')
            configured=bool(bot.get('configured'))
            tabs=(f'<div class="cfgx-tabs tg-tabs" role="tablist" aria-label="{h(t("tg_title"))}">'
                  f'<button class="cfgx-tab{" is-active" if sub=="panel" else ""}" type="button" role="tab" id="tg-tab-panel" '
                  f'aria-controls="tg-panel-panel" aria-selected="{str(sub=="panel").lower()}" data-tab-target="tg-panel-panel" data-tab-name="panel">'
                  f'{icon("settings",17)}<span>{h(t("tg_tab_panel"))}</span></button>'
                  f'<button class="cfgx-tab{" is-active" if sub=="notify" else ""}" type="button" role="tab" id="tg-tab-notify" '
                  f'aria-controls="tg-panel-notify" aria-selected="{str(sub=="notify").lower()}" data-tab-target="tg-panel-notify" data-tab-name="notify"'
                  f'{"" if configured else " disabled"}>{icon("bell",17)}<span>{h(t("tg_tab_notify"))}</span></button>@@STATE@@</div>')
            notice={'saved':'tg_saved','tested':'tg_tested'}.get(request.query_params.get('done',''))
            notice_html=f'<p class="tg-notice" role="status">{icon("check",16)}{h(t(notice))}</p>' if notice and configured else ''
            if not configured:
                rows=''.join((
                    tg_row(t('tg_token'),t('tg_connect_hint'),tg_token('123456789:AA…',True)+'</div>'),
                    tg_row(t('tg_lang'),'',tg_lang_select(lang)),
                    tg_row(t('panel_password'),'','<input type="password" name="password" required autocomplete="current-password">'),
                ))
                tabs=tabs.replace('@@STATE@@',f'<span class="tg-state">{h(t("tg_not_connected"))}</span>')
                body+=(f'<section class="tg-block">'
                       f'<form method="post" action="/maintenance/telegram/connect">{csrf(request)}{tabs}'
                       f'<div class="tg-tab-panel" id="tg-panel-panel" role="tabpanel" aria-labelledby="tg-tab-panel">{rows}</div>'
                       f'<div class="tg-footer"><div class="tg-actions"><button class="btn btn-primary" type="submit">{icon("radio",16)}{h(t("tg_connect"))}</button></div></div>'
                       f'</form></section>')
            else:
                running=bot.get('active')=='active'
                state=(f'<span class="tg-state{" is-on" if running else ""}">{h(t("tg_running") if running else t("tg_stopped"))}'
                       f'{" · @"+h(bot["username"]) if bot.get("username") else ""}</span>')
                ids=lambda key:', '.join(str(x) for x in bot[key])
                api_value='' if bot.get('api_base')=='https://api.telegram.org' else bot.get('api_base','')
                panel_rows=''.join((
                    tg_row(t('tg_enable'),t('tg_enable_hint'),tg_switch('enabled',bot.get('enabled'),t('tg_enable'))),
                    tg_row(t('tg_token'),t('tg_token_set'),tg_token(t('tg_token_placeholder'),False)
                           +f'<button class="btn btn-secondary" type="submit" formaction="/maintenance/telegram/disconnect" formnovalidate '
                            f'data-confirm-submit="{h(t("tg_clear_confirm"))}">{h(t("tg_clear"))}</button></div>'),
                    tg_row(t('tg_admins'),t('tg_admins_hint'),f'<input name="admins" required value="{h(ids("admins"))}" placeholder="123456789" spellcheck="false">'),
                    tg_row(t('tg_viewers'),t('tg_viewers_hint'),f'<input name="viewers" value="{h(ids("viewers"))}" spellcheck="false">'),
                    tg_row(t('tg_lang'),'',tg_lang_select(bot['lang'])),
                    tg_row(t('tg_api'),t('tg_api_hint'),f'<input name="api_base" value="{h(api_value)}" placeholder="https://api.telegram.org" spellcheck="false" autocomplete="off">'),
                ))
                groups=bot.get('notify') or {}
                chosen=bot.get('events') or {e:bool(groups.get(g,True)) for g,_,events in TG_EVENT_GROUPS for e in events}
                limits=bot.get('thresholds') or {}
                presets=dict(TG_SCHEDULES)
                current={'daily':'0 9 * * *','weekly':'0 9 * * 1'}.get(bot.get('digest','off'),bot.get('digest','off'))
                custom=current!='off' and current not in presets
                schedule=(f'<select name="digest_preset" id="tg-schedule" data-tg-schedule>'
                          f'<option value="off"{" selected" if current=="off" else ""}>{h(t("tg_s_off"))}</option>'
                          +''.join(f'<option value="{h(cron)}"{" selected" if cron==current else ""}>{h(cron)} — {h(t(key))}</option>' for cron,key in TG_SCHEDULES)
                          +f'<option value="custom"{" selected" if custom else ""}>{h(t("tg_custom"))}</option></select>'
                          +f'<label class="tg-custom" data-tg-custom><span>{h(t("tg_custom_hint"))}</span>'
                          +f'<input name="digest_custom" value="{h(current if custom else "")}" placeholder="30 8 * * 1-5" spellcheck="false" autocomplete="off"></label>')
                cards=''
                for group,glyph,events in TG_EVENT_GROUPS:
                    items=''
                    for event in events:
                        on=chosen.get(event)
                        check=(f'<label class="tg-check"><input type="checkbox" name="ev_{event}" value="1"{" checked" if on else ""} data-tg-event>'
                               f'<span>{h(t("tg_e_"+event))}</span></label>')
                        if event in TG_THRESHOLD_EVENTS:     # "CPU load above [90] %" on one line
                            check=(f'<div class="tg-check-line">{check}<label class="tg-threshold"><input type="number" name="th_{event}" '
                                   f'min="10" max="100" step="1" required value="{int(limits.get(event,90))}" '
                                   f'aria-label="{h(t("tg_e_"+event))}, %"><span>%</span></label></div>')
                        items+=check
                    count=sum(1 for e in events if chosen.get(e))
                    title=h(t('tg_g_'+group))
                    cards+=(f'<fieldset class="tg-card" data-tg-group><legend class="tg-legend">{title}</legend>'
                            f'<div class="tg-card-head" aria-hidden="false">{icon(glyph,17)}<strong aria-hidden="true">{title}</strong>'
                            f'<span class="tg-count" data-tg-count>{count}/{len(events)}</span>'
                            f'<input type="checkbox" class="tg-group-toggle" data-tg-all aria-label="{h(t("tg_all"))}: {title}"'
                            f'{" checked" if count==len(events) else ""}></div><div class="tg-card-body">{items}</div></fieldset>')
                notify_rows=''.join((
                    tg_row(t('tg_schedule'),t('tg_schedule_hint'),schedule),
                    tg_row(t('tg_backup_file'),t('tg_backup_file_on') if bot.get('encrypted_backups') else t('tg_backup_file_off'),
                           tg_switch('backup_file',bot.get('backup_file'),t('tg_backup_file'))),
                    f'<div class="tg-row tg-row-events"><div class="tg-row-text"><strong>{h(t("tg_events"))}</strong><small>{h(t("tg_events_hint"))}</small></div>'
                    f'<div class="tg-cards">{cards}</div></div>',
                ))
                tabs=tabs.replace('@@STATE@@',state)
                body+=(f'<section class="tg-block">{notice_html}'
                       f'<form method="post" action="/maintenance/telegram" id="tg-form">{csrf(request)}'
                       f'<input type="hidden" name="sub" value="{sub}" data-tab-memory>'
                       f'<input type="hidden" name="events_form" value="1">{tabs}'
                       f'<div class="tg-tab-panel" id="tg-panel-panel" role="tabpanel" aria-labelledby="tg-tab-panel"{" hidden" if sub!="panel" else ""}>{panel_rows}</div>'
                       f'<div class="tg-tab-panel" id="tg-panel-notify" role="tabpanel" aria-labelledby="tg-tab-notify"{" hidden" if sub!="notify" else ""}>{notify_rows}</div>'
                       f'<div class="tg-footer"><label class="tg-password"><span>{h(t("tg_password_row"))}</span>'
                       f'<input type="password" name="password" autocomplete="current-password"><small>{h(t("tg_password_row_hint"))}</small></label>'
                       f'<div class="tg-actions"><button class="btn btn-primary" type="submit">{icon("check",17)}{h(t("tg_save"))}</button>'
                       f'<button class="btn btn-secondary" type="submit" formaction="/maintenance/telegram/test" formnovalidate>{icon("send",16)}{h(t("tg_test"))}</button>'
                       f'</div></div></form></section>')
        elif tab=='logs':
            body+=logs_tab(request,t,lang)
        elif tab=='audit':
            body+=audit_tab(request,t)
    except (RuntimeError,ValueError,KeyError,TypeError) as exc:
        return error_page(request,t('maintenance_error'),exc)
    body+='</div></div>'
    return page(t('nav_maintenance_short'),body,request)


@app.post('/maintenance/backup')
async def make_backup(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    try: result=ctl('backup-create',{})
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    return RedirectResponse('/maintenance?tab=backups',status_code=303)


@app.post('/maintenance/backup/delete')
async def remove_backup(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    name=str(form.get('name',''))
    if not re.fullmatch(r'awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz(?:\.gpg)?',name):
        raise HTTPException(400,detail='Invalid backup name')
    try: ctl('backup-delete',{'name':name})
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    return RedirectResponse('/maintenance?tab=backups',status_code=303)


@app.post('/maintenance/backup/policy')
async def backup_schedule_update(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    fields=('frequency','hour','minute','weekday','retention_days','max_copies')
    data={key: str(form.get(key,'')) for key in fields}
    try: ctl('backup-policy-set',data)
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    return RedirectResponse('/maintenance?tab=backups',status_code=303)


@app.post('/maintenance/backup/encryption/{action}')
async def backup_encryption_change(request: Request, action: str):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    if action not in ('enable','disable','change'): raise HTTPException(404)
    password = str(form.get('password', ''))
    reply = {}
    try:
        if action in ('enable', 'change'):
            passphrase = str(form.get('passphrase', ''))
            confirm = str(form.get('confirm', ''))
            if passphrase != confirm:
                raise RuntimeError('Passwords do not match')
            if action == 'enable':
                ctl('backup-encryption-set', {'enabled': True, 'passphrase': passphrase, 'password': password})
            else:
                reply = ctl('backup-encryption-change', {'passphrase': passphrase, 'password': password})
        else:
            ctl('backup-encryption-set', {'enabled': False, 'password': password})
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    if reply.get('skipped'):
        lang = lang_of(request)
        body = (f'<section class="card message-card"><h2>{icon("lock",20)} {h(tr(lang,"enc_change"))}</h2>'
                f'<p>{h(tr(lang,"enc_reencrypted").format(count=reply.get("reencrypted",0)))}</p>'
                f'<p class="info-line">{h(tr(lang,"enc_skipped"))}</p><ul>'
                + ''.join(f'<li class="mono">{h(name)}</li>' for name in reply['skipped'])
                + f'</ul><a class="btn btn-primary" href="/maintenance?tab=backups">{h(tr(lang,"back"))}</a></section>')
        return page(tr(lang, 'enc_change'), body, request)
    return RedirectResponse('/maintenance?tab=backups',status_code=303)


@app.post('/maintenance/backup/check')
async def verify_backup(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    name=str(form.get('name',''))
    if not re.fullmatch(r'awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz(?:\.gpg)?',name):
        raise HTTPException(400)
    try: outcome=ctl('backup-check',{'name':name})
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    return page(tr(lang_of(request),'backup_check'),f'''<section class="card message-card">
       <h2>{icon('check',22)}{h(tr(lang_of(request),'backup_check_good'))}</h2>
       <p class="mono">{h(name)}</p>
       <a href="/maintenance?tab=restore" class="btn btn-secondary">{h(tr(lang_of(request),'back'))}</a></section>''',request)


@app.post('/maintenance/restore')
async def restore_backup(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    lang=lang_of(request)
    expected='ВОССТАНОВИТЬ' if lang=='ru' else 'RESTORE'
    if str(form.get('confirmation','')).strip()!=expected:
        raise HTTPException(status_code=400,detail='Restore confirmation mismatch')
    name=str(form.get('name',''))
    if not re.fullmatch(r'awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz(?:\.gpg)?',name):
        raise HTTPException(400,detail='Invalid backup name')
    try:
        ctl('backup-check',{'name':name})
        result=ctl('backup-restore',{'name':name})
    except RuntimeError as exc:
        return error_page(request,tr(lang,'maintenance_error'),exc)
    response = page(tr(lang,'maint_restore'), f'''<section class="card message-card">
       <div class="section-overline">AWG / RESTORE</div>
       <h2>{icon('check',22)} {h(tr(lang,'maint_restore'))}</h2>
       <p>{h(tr(lang,'restore_sent'))}</p>
       <code class="mono">{h(result['scheduled'])}</code>
       <p><a class="btn btn-secondary" href="/maintenance?tab=restore">{h(tr(lang,'back'))}</a></p>
       </section>''', request)
    response.status_code = 202
    return response


@app.get('/maintenance/backup/{name}')
def download_backup(request: Request, name: str):
    require_auth(request)
    if not re.fullmatch(r'awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz(?:\.gpg)?',name):
        raise HTTPException(404)
    try: value=ctl('backup-export',{'name':name})
    except RuntimeError: raise HTTPException(404)
    return Response(base64.b64decode(value['content'],validate=True),
                    media_type='application/octet-stream',headers={
         'Content-Disposition':f'attachment; filename="{name}"',
         'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.post('/maintenance/totp/{action}')
async def totp_change(request: Request, action: str):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    if action not in ('enable','disable','regenerate'): raise HTTPException(404)
    payload={'password':str(form.get('password','')),'code':str(form.get('code',''))}
    if action in ('enable','regenerate'): payload['secret']=str(form.get('secret',''))
    if action=='regenerate': payload['current_code']=str(form.get('current_code',''))
    try: ctl('totp-enable' if action in ('enable','regenerate') else 'totp-disable',payload)
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    request.session.clear()            # every session ended: sign in again, now with the new rule
    return RedirectResponse('/login',status_code=303)


@app.post('/maintenance/telegram')
async def telegram_update(request: Request):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    payload={'admins':str(form.get('admins','')),'viewers':str(form.get('viewers','')),'lang':str(form.get('lang','ru'))}
    if form.get('events_form')=='1':
        preset=str(form.get('digest_preset','off'))
        payload.update(
            digest=str(form.get('digest_custom','')).strip() if preset=='custom' else preset,
            enabled=form.get('enabled')=='1', backup_file=form.get('backup_file')=='1',
            api_base=str(form.get('api_base','')).strip(), token=str(form.get('token','')).strip(),
            events={event:form.get('ev_'+event)=='1' for _,_,events in TG_EVENT_GROUPS for event in events},
            thresholds={event:str(form.get('th_'+event,'')).strip() for event in TG_THRESHOLD_EVENTS})
    else:                                   # an older page still open in a browser tab
        payload.update(digest=str(form.get('digest','off')),
                       notify={g:form.get('notify_'+g)=='1' for g in NOTIFY_GROUPS})
    if form.get('password'): payload['password']=str(form.get('password'))
    try: ctl('telegram-set',payload)
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    sub='notify' if form.get('sub')=='notify' else 'panel'
    return RedirectResponse(f'/maintenance?tab=telegram&sub={sub}&done=saved',status_code=303)


@app.post('/maintenance/telegram/test')
async def telegram_test(request: Request):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    try: ctl('telegram-test',{})
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    sub='notify' if form.get('sub')=='notify' else 'panel'
    return RedirectResponse(f'/maintenance?tab=telegram&sub={sub}&done=tested',status_code=303)


@app.post('/maintenance/telegram/connect')
async def telegram_connect(request: Request):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    lang=lang_of(request)
    if form.get('cancel')=='1':
        try: ctl('telegram-connect',{'cancel':True})
        except RuntimeError as exc: return error_page(request,tr(lang,'maintenance_error'),exc)
        return RedirectResponse('/maintenance?tab=telegram',status_code=303)
    confirming=form.get('confirm')=='1'
    payload={'admin_id':str(form.get('admin_id','')).strip(),'confirm':confirming,
             'setup_id':str(form.get('setup_id','')).strip()}
    if not confirming:
        payload.update(token=str(form.get('token','')).strip(),lang=str(form.get('lang',lang)),
                       notify={group:form.get('notify_'+group)=='1' for group in NOTIFY_GROUPS},
                       password=str(form.get('password','')))
    try: result=ctl('telegram-connect',payload)
    except RuntimeError as exc: return error_page(request,tr(lang,'maintenance_error'),exc)
    if result.get('pending'):
        candidates=result.get('candidates',[])
        choices=''.join(f'<label class="check-field"><input type="radio" name="admin_id" value="{h(item["id"])}" required><span>{h(item["label"] or "Telegram")} · ID {h(item["id"])}</span></label>' for item in candidates)
        content=f'''<section class="maint-form-panel"><h3>{icon('radio',19)}{h(tr(lang,'tg_confirm_title'))}</h3>
            <p class="info-line">{h(tr(lang,'tg_confirm_hint'))}</p>
            <form method="post" action="/maintenance/telegram/connect">{csrf(request)}
            <input type="hidden" name="setup_id" value="{h(result.get('setup_id',''))}">
            {choices or '<p class="error-message">'+h(tr(lang,'tg_no_candidates'))+'</p>'}
            <button class="btn btn-primary" type="submit" name="confirm" value="1" {'disabled' if not candidates else ''}>{h(tr(lang,'tg_confirm'))}</button>
            <button class="btn btn-secondary" type="submit" name="cancel" value="1" formnovalidate>{h(tr(lang,'cancel_action'))}</button>
            </form></section>'''
        response=page(tr(lang,'maint_telegram'),content,request)
        response.headers['Cache-Control']='no-store'
        return response
    return RedirectResponse('/maintenance?tab=telegram',status_code=303)


@app.post('/maintenance/telegram/disconnect')
async def telegram_disconnect(request: Request):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    try: ctl('telegram-disconnect',{'password':str(form.get('password',''))})
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    return RedirectResponse('/maintenance?tab=telegram',status_code=303)


@app.get('/maintenance/profile')
@app.get('/servers/{interface}/settings/profile')
def export_profile(request: Request, interface: str = ''):
    require_auth(request)
    try: profile=control(request,'profile-export')
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    iface=selected_server(request)
    return Response(json.dumps(profile,indent=2,ensure_ascii=False),media_type='application/json',
      headers={'Content-Disposition':f'attachment; filename="{iface}-profile.json"',
               'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.post('/maintenance/profile')
@app.post('/servers/{interface}/settings/profile')
async def import_profile(request: Request, interface: str = ''):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    content=str(form.get('profile',''))
    if len(content)>16000: raise HTTPException(413)
    try:
        profile=json.loads(content)
        control(request,'profile-import',{'profile':profile})
    except (RuntimeError,ValueError) as exc:
        return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    audit_event('profile_imported',selected_server(request))
    return RedirectResponse('/maintenance?tab=profiles',status_code=303)


@app.post('/maintenance/password')
async def change_password(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    lang=lang_of(request)
    new=str(form.get('new',''))
    if new!=str(form.get('confirm','')):
        return error_page(request,tr(lang,'maintenance_error'),tr(lang,'password_mismatch'))
    try: ctl('password-change',{'old_password':str(form.get('old','')),'new_password':new})
    except RuntimeError as exc: return error_page(request,tr(lang,'maintenance_error'),exc)
    request.session.clear()
    return RedirectResponse('/login',status_code=303)


# ------------------------------------------------------------------ 0.14: logs, connection history, masking
LOG_SOURCE_KEYS = ('panel', 'bot', 'helper', 'sampler', 'backup', 'kernel-check', 'kernel')
LOG_LINE_CHOICES = (100, 200, 500, 1000)


def utc_minute(stamp):
    try: return datetime.fromtimestamp(int(stamp), timezone.utc).strftime('%Y-%m-%d %H:%M')
    except (TypeError, ValueError, OverflowError, OSError): return '—'


def duration_text(seconds, lang):
    seconds = max(0, int(seconds))
    hours, minutes = seconds // 3600, seconds % 3600 // 60
    if hours >= 24: return f'{hours // 24} {"д" if lang == "ru" else "d"} {hours % 24} {"ч" if lang == "ru" else "h"}'
    if hours: return f'{hours} {"ч" if lang == "ru" else "h"} {minutes} {"мин" if lang == "ru" else "min"}'
    return f'{max(1, minutes)} {"мин" if lang == "ru" else "min"}'


def log_query(request):
    """The viewer's choices from the query string, checked the same way the controller checks them."""
    params = request.query_params
    source = params.get('source', 'panel')
    if source not in LOG_SOURCE_KEYS and not re.fullmatch(r'server:awg(?:0|[1-9][0-9]?)', source): source = 'panel'
    level = params.get('level', 'all')
    if level not in ('error', 'warning', 'all'): level = 'all'
    try: lines = int(params.get('lines', 200))
    except ValueError: lines = 200
    if lines not in LOG_LINE_CHOICES: lines = 200
    query = ''.join(c for c in params.get('query', '')[:100] if ord(c) >= 32)
    return {'source': source, 'level': level, 'lines': lines, 'query': query}


def logs_tab(request, t, lang):
    choice = log_query(request)
    status = ctl('logging-status', {})
    settings, debug = status.get('settings', {}), status.get('debug', {})
    servers = [s.get('interface') for s in server_list() if isinstance(s, dict)]
    try:
        lines = ctl('logs-read', choice).get('lines', [])
        log_error = ''
    except RuntimeError as exc:
        lines, log_error = [], str(exc)
    sources = [(key, t('log_src_' + key.replace('-', '_'))) for key in LOG_SOURCE_KEYS] + \
              [(f'server:{iface}', t('log_src_server').format(iface=iface)) for iface in servers]
    def options(pairs, current):
        return ''.join(f'<option value="{h(value)}"{" selected" if str(value) == str(current) else ""}>{h(label)}</option>'
                       for value, label in pairs)
    viewer = f'''<section class="logs-card">
      <h3>{icon('logs', 18)}{h(t('logs_view'))}</h3>
      <p class="logs-warning">{icon('info', 16)}{h(t('logs_view_hint'))}</p>
      <form class="logs-filter" method="get" action="/maintenance" data-logs-form>
        <input type="hidden" name="tab" value="logs">
        <label><span>{h(t('logs_source'))}</span><select name="source">{options(sources, choice['source'])}</select></label>
        <label><span>{h(t('logs_level'))}</span><select name="level">{options((('all', t('logs_level_all')), ('warning', t('logs_level_warning')), ('error', t('logs_level_error'))), choice['level'])}</select></label>
        <label><span>{h(t('logs_lines'))}</span><select name="lines">{options(((n, str(n)) for n in LOG_LINE_CHOICES), choice['lines'])}</select></label>
        <label class="logs-search"><span>{h(t('logs_search'))}</span><input name="query" value="{h(choice['query'])}" maxlength="100" autocomplete="off" spellcheck="false"></label>
        <div class="logs-buttons">
          <button class="btn btn-primary" type="submit">{icon('search', 16)}{h(t('logs_show'))}</button>
          <button class="btn btn-secondary" type="submit" formaction="/maintenance/logs/download">{icon('download', 16)}{h(t('logs_download'))}</button>
          <label class="logs-auto"><input type="checkbox" data-logs-auto><span>{h(t('logs_auto'))}</span></label>
        </div>
      </form>
      {f'<p class="error-message">{h(log_error)}</p>' if log_error else ''}
      <pre class="log-view" data-log-view tabindex="0" aria-label="{h(t('logs_view'))}">{h(chr(10).join(lines)) or h(t('logs_empty'))}</pre>
      <p class="logs-count" data-log-count>{h(t('logs_count').format(n=len(lines)))}</p>
    </section>'''
    masking = settings.get('masking', 'partial')
    history_form = f'''<section class="logs-card">
      <h3>{icon('clock', 18)}{h(t('logs_history'))}</h3>
      <form method="post" action="/maintenance/logs/settings">{csrf(request)}
        <div class="tg-row"><div class="tg-row-text"><strong>{h(t('logs_history_on'))}</strong><small>{h(t('logs_history_hint'))}</small></div>
          <div class="tg-row-control"><label class="tg-switch"><input type="checkbox" role="switch" name="history" value="1"{" checked" if settings.get('history') else ""} aria-label="{h(t('logs_history_on'))}"><span aria-hidden="true"></span></label></div></div>
        <div class="tg-row"><div class="tg-row-text"><strong>{h(t('logs_retention'))}</strong><small>{h(t('logs_retention_hint'))}</small></div>
          <div class="tg-row-control"><input type="number" name="retention_days" min="1" max="365" required value="{int(settings.get('retention_days', 30))}"></div></div>
        <div class="tg-row"><div class="tg-row-text"><strong>{h(t('logs_masking'))}</strong><small>{h(t('logs_masking_hint'))}</small></div>
          <div class="tg-row-control"><select name="masking">{options((('none', t('logs_mask_none')), ('partial', t('logs_mask_partial')), ('full', t('logs_mask_full'))), masking)}</select></div></div>
        <div class="tg-actions logs-save"><button class="btn btn-primary" type="submit">{icon('check', 16)}{h(t('logs_save'))}</button></div>
      </form></section>'''
    until = int(debug.get('until') or 0)
    if debug.get('enabled'):
        debug_state = f'<span class="tg-state is-on">{h(t("logs_debug_on").format(until=utc_minute(until)))}</span>'
        debug_button = f'<button class="btn btn-secondary" type="submit" name="enable" value="0">{h(t("logs_debug_stop"))}</button>'
    else:
        debug_state = f'<span class="tg-state">{h(t("logs_debug_off"))}</span>'
        debug_button = (f'<button class="btn btn-primary" type="submit" name="enable" value="1"'
                        f'{"" if debug.get("available", True) else " disabled"}>{icon("activity", 16)}{h(t("logs_debug_start"))}</button>')
    debug_card = f'''<section class="logs-card">
      <div class="logs-card-head"><h3>{icon('activity', 18)}{h(t('logs_debug'))}</h3>{debug_state}</div>
      <p class="logs-warning">{icon('alert', 16)}{h(t('logs_debug_warning'))}</p>
      <p class="info-line">{h(t('logs_debug_hint'))}</p>
      <form method="post" action="/maintenance/logs/debug" class="tg-actions">{csrf(request)}{debug_button}
        <a class="btn btn-secondary" href="/maintenance?tab=logs&amp;source=kernel">{h(t('logs_debug_view'))}</a></form>
    </section>'''
    report_card = f'''<section class="logs-card">
      <h3>{icon('archive', 18)}{h(t('logs_report'))}</h3>
      <p class="info-line">{h(t('logs_report_hint'))}</p>
      <form method="post" action="/maintenance/logs/report" class="tg-actions">{csrf(request)}
        <button class="btn btn-secondary" type="submit">{icon('download', 16)}{h(t('logs_report_button'))}</button></form>
    </section>'''
    return f'<div class="logs-workspace">{viewer}{history_form}{debug_card}{report_card}</div>'


def audit_tab(request, t):
    params = request.query_params
    query = {'event': params.get('event', ''), 'since': params.get('since', '')[:10], 'until': params.get('until', '')[:10],
             'query': params.get('query', '')[:80], 'page': params.get('page', '1')}
    result = ctl('audit-search', query)
    def keep(**changes):
        merged = {**{k: v for k, v in query.items() if v and k != 'page'}, **changes}
        return '/maintenance?tab=audit&' + '&'.join(f'{quote(str(k))}={quote(str(v))}' for k, v in merged.items() if v)
    events = ''.join(f'<option value="{h(e)}"{" selected" if e == query["event"] else ""}>{h(e)}</option>' for e in result.get('events', []))
    rows = ''.join(f'''<li class="audit-entry"><span class="audit-time">{h(item.get('timestamp', '')[:19].replace('T', ' '))}</span>
        <span class="audit-event">{h(item.get('event', ''))}</span><span class="audit-target">{h(item.get('target', ''))}</span></li>'''
        for item in result.get('entries', []))
    page_no, pages = int(result.get('page', 1)), int(result.get('pages', 1))
    pager = (f'<nav class="audit-pager" aria-label="{h(t("audit_pages"))}">'
             + (f'<a class="btn btn-secondary btn-small" href="{h(keep(page=page_no - 1))}">← {h(t("audit_newer"))}</a>' if page_no > 1 else '')
             + f'<span>{h(t("audit_page").format(page=page_no, pages=pages, total=result.get("total", 0)))}</span>'
             + (f'<a class="btn btn-secondary btn-small" href="{h(keep(page=page_no + 1))}">{h(t("audit_older"))} →</a>' if page_no < pages else '')
             + '</nav>')
    return f'''<form class="logs-filter audit-filter" method="get" action="/maintenance">
        <input type="hidden" name="tab" value="audit">
        <label><span>{h(t('audit_event'))}</span><select name="event"><option value="">{h(t('audit_all_events'))}</option>{events}</select></label>
        <label><span>{h(t('audit_since'))}</span><input type="date" name="since" value="{h(query['since'])}"></label>
        <label><span>{h(t('audit_until'))}</span><input type="date" name="until" value="{h(query['until'])}"></label>
        <label class="logs-search"><span>{h(t('logs_search'))}</span><input name="query" value="{h(query['query'])}" maxlength="80" autocomplete="off"></label>
        <div class="logs-buttons"><button class="btn btn-primary" type="submit">{icon('search', 16)}{h(t('logs_show'))}</button>
        <button class="btn btn-secondary" type="submit" formaction="/maintenance/audit.csv">{icon('download', 16)}CSV</button></div>
      </form>
      <ol class="audit-entries">{rows or '<li class="empty-state">' + h(t('audit_empty')) + '</li>'}</ol>{pager}'''


def sessions_section(request, name, t, lang):
    try: data = control(request, 'sessions', {'name': name, 'limit': 50})
    except RuntimeError: return ''
    items = data.get('sessions', [])
    if not data.get('history') and not items:
        return (f'<section class="card detail-card client-sessions"><div class="section-title"><h2>{icon("clock", 20)}{h(t("sessions_title"))}</h2></div>'
                f'<p class="info-line">{h(t("sessions_off"))} <a href="/maintenance?tab=logs">{h(t("sessions_enable"))}</a></p></section>')
    now = time.time()
    rows = ''
    for item in items:
        active = not item.get('ended')
        end = int(item.get('ended') or item.get('last_seen') or 0)
        rows += (f'<tr><td>{h(utc_minute(item.get("started")))}</td>'
                 f'<td>{h(t("sessions_now")) if active else h(utc_minute(end))}</td>'
                 f'<td>{h(duration_text((now if active else end) - int(item.get("started") or 0), lang))}</td>'
                 f'<td class="mono">{h(item.get("address") or "—")}</td>'
                 f'<td>{h(human_size(int(item.get("rx") or 0) + int(item.get("tx") or 0)))}</td></tr>')
    table = (f'<div class="table-scroll sessions-table"><table><thead><tr><th>{h(t("sessions_start"))}</th><th>{h(t("sessions_end"))}</th>'
             f'<th>{h(t("sessions_length"))}</th><th>{h(t("sessions_address"))}</th><th>{h(t("sessions_traffic"))}</th></tr></thead>'
             f'<tbody>{rows}</tbody></table></div>') if rows else f'<p class="info-line">{h(t("sessions_empty"))}</p>'
    note = t('sessions_note').format(days=data.get('retention_days', 30)) + (' ' + t('sessions_paused') if not data.get('history') else '')
    return (f'<section class="card detail-card client-sessions"><div class="section-title"><h2>{icon("clock", 20)}{h(t("sessions_title"))}</h2></div>'
            f'<p class="info-line">{h(note)}</p>{table}</section>')


@app.get('/api/logs')
def logs_api(request: Request):
    require_auth(request)
    try: return JSONResponse(ctl('logs-read', log_query(request)), headers={'Cache-Control': 'no-store'})
    except RuntimeError as exc: return JSONResponse({'error': str(exc)}, status_code=400)


@app.get('/maintenance/logs/download')
def logs_download(request: Request):
    require_auth(request)
    choice = log_query(request)
    try: lines = ctl('logs-read', choice).get('lines', [])
    except RuntimeError as exc: return error_page(request, tr(lang_of(request), 'maintenance_error'), exc)
    name = f"awg31-{choice['source'].replace(':', '-')}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.txt"
    return Response('\n'.join(lines) + '\n', media_type='text/plain; charset=utf-8',
                    headers={'Content-Disposition': f'attachment; filename="{name}"', 'Cache-Control': 'no-store'})


@app.post('/maintenance/logs/settings')
async def logs_settings(request: Request):
    form = await request.form(); require_csrf(request, form.get('csrf', ''))
    try: ctl('logging-set', {'history': form.get('history') == '1', 'retention_days': str(form.get('retention_days', '30')),
                             'masking': str(form.get('masking', 'partial'))})
    except RuntimeError as exc: return error_page(request, tr(lang_of(request), 'maintenance_error'), exc)
    return RedirectResponse('/maintenance?tab=logs', status_code=303)


@app.post('/maintenance/logs/debug')
async def logs_debug(request: Request):
    form = await request.form(); require_csrf(request, form.get('csrf', ''))
    try: ctl('handshake-debug', {'enable': form.get('enable') == '1'})
    except RuntimeError as exc: return error_page(request, tr(lang_of(request), 'maintenance_error'), exc)
    return RedirectResponse('/maintenance?tab=logs', status_code=303)


@app.post('/maintenance/logs/report')
async def logs_report(request: Request):
    form = await request.form(); require_csrf(request, form.get('csrf', ''))
    try: report = ctl('support-report', {})
    except RuntimeError as exc: return error_page(request, tr(lang_of(request), 'maintenance_error'), exc)
    name = str(report.get('name', ''))
    if not re.fullmatch(r'awg31-support-[0-9]{8}T[0-9]{6}Z\.tar\.gz', name): raise HTTPException(500, detail='Invalid report')
    return Response(base64.b64decode(report.get('data', '')), media_type='application/gzip',
                    headers={'Content-Disposition': f'attachment; filename="{name}"', 'Cache-Control': 'no-store'})


@app.get('/maintenance/audit.csv')
def audit_csv(request: Request):
    require_auth(request)
    import csv
    params = request.query_params
    query = {'event': params.get('event', ''), 'since': params.get('since', '')[:10], 'until': params.get('until', '')[:10],
             'query': params.get('query', '')[:80], 'size': 1000}
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(['timestamp', 'event', 'target'])
    try:
        page_no = 1
        while page_no <= 50:                       # at most 50 000 rows
            result = ctl('audit-search', {**query, 'page': page_no})
            for item in result.get('entries', []):
                target = str(item.get('target', ''))
                if target[:1] in '=+-@': target = "'" + target   # no formulas when opened in a spreadsheet
                writer.writerow([item.get('timestamp', ''), item.get('event', ''), target])
            if page_no >= int(result.get('pages', 1)): break
            page_no += 1
    except RuntimeError as exc: return error_page(request, tr(lang_of(request), 'maintenance_error'), exc)
    name = f"awg31-audit-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    return Response(out.getvalue(), media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition': f'attachment; filename="{name}"', 'Cache-Control': 'no-store'})


TEXT['ru'].update({
    'maint_logs': 'Журналы',
    'maint_logs_hint': 'Системные журналы панели, бота и серверов, история подключений клиентов, маскировка адресов, отладка и отчёт для поддержки.',
    'logs_view': 'Просмотр журналов',
    'logs_view_hint': 'Журналы могут содержать имена клиентов и адреса. Публичные IP показываются так, как задано в маскировке ниже.',
    'logs_source': 'Источник', 'logs_level': 'Уровень', 'logs_lines': 'Строк', 'logs_search': 'Поиск', 'logs_show': 'Показать',
    'logs_download': 'Скачать .txt', 'logs_auto': 'Обновлять каждые 5 с', 'logs_empty': 'Записей нет.', 'logs_count': 'Строк: {n}',
    'logs_level_all': 'Все', 'logs_level_warning': 'Предупреждения и ошибки', 'logs_level_error': 'Только ошибки',
    'log_src_panel': 'Веб-панель', 'log_src_bot': 'Telegram-бот', 'log_src_helper': 'Помощник (привилегированные операции)',
    'log_src_sampler': 'Опрос клиентов и лимитов', 'log_src_backup': 'Резервные копии', 'log_src_kernel_check': 'Проверка нового ядра',
    'log_src_kernel': 'Ядро: модуль AmneziaWG', 'log_src_server': 'Сервер {iface} (awg-quick)',
    'logs_history': 'История подключений и маскировка адресов', 'logs_history_on': 'Записывать историю подключений',
    'logs_history_hint': 'Когда клиент подключился, с какого адреса, сколько был на связи и сколько передал. Строится из рукопожатий раз в минуту.',
    'logs_retention': 'Срок хранения, дней', 'logs_retention_hint': 'Старые записи удаляются сами. От 1 до 365 дней.',
    'logs_masking': 'Маскировка адресов',
    'logs_masking_hint': 'Как хранятся и показываются публичные IP: в истории, журнале действий, уведомлениях бота и в просмотре журналов. При «Полностью» адрес не сохраняется вовсе.',
    'logs_mask_none': 'Не скрывать (203.0.113.45:51820)', 'logs_mask_partial': 'Частично (203.0.113.x)', 'logs_mask_full': 'Полностью (IP-3f2a1c)',
    'logs_debug': 'Отладка рукопожатий AmneziaWG', 'logs_debug_off': 'Выключена', 'logs_debug_on': 'Включена до {until} UTC',
    'logs_debug_warning': 'Подробные сообщения модуля ядра замедляют сервер и содержат адреса клиентов. Отладка выключится сама через 15 минут.',
    'logs_debug_hint': 'Нужна, когда клиент не может подключиться, например после смены обфускации: в журнале «Ядро: модуль AmneziaWG» видно, доходят ли рукопожатия и что с ними происходит.',
    'logs_debug_start': 'Включить на 15 минут', 'logs_debug_stop': 'Выключить сейчас', 'logs_debug_view': 'Смотреть сообщения ядра',
    'logs_report': 'Отчёт для поддержки',
    'logs_report_hint': 'Архив с диагностикой, версиями, настройками серверов и последними строками журналов. Ключи, токены, Endpoint и публичные адреса в нём заменены. Просмотрите его перед отправкой.',
    'logs_report_button': 'Скачать отчёт', 'logs_save': 'Сохранить',
    'audit_event': 'Событие', 'audit_all_events': 'Все события', 'audit_since': 'С даты', 'audit_until': 'По дату',
    'audit_pages': 'Страницы журнала', 'audit_newer': 'Новее', 'audit_older': 'Старше',
    'audit_page': 'Страница {page} из {pages} · записей: {total}',
    'sessions_title': 'История подключений', 'sessions_off': 'История подключений выключена.',
    'sessions_enable': 'Включить в «Обслуживание → Журналы»',
    'sessions_now': 'на связи', 'sessions_start': 'Начало (UTC)', 'sessions_end': 'Конец', 'sessions_length': 'Длительность',
    'sessions_address': 'Адрес', 'sessions_traffic': 'Трафик', 'sessions_empty': 'Подключений пока не было.',
    'sessions_note': 'Последние 50 подключений, хранятся {days} дн.', 'sessions_paused': 'Запись сейчас выключена.',
})
TEXT['en'].update({
    'maint_logs': 'Logs',
    'maint_logs_hint': 'System journals of the panel, bot and servers, client connection history, address masking, debugging and a support report.',
    'logs_view': 'Journal viewer',
    'logs_view_hint': 'Journals may contain client names and addresses. Public IPs are shown as the masking below says.',
    'logs_source': 'Source', 'logs_level': 'Level', 'logs_lines': 'Lines', 'logs_search': 'Search', 'logs_show': 'Show',
    'logs_download': 'Download .txt', 'logs_auto': 'Refresh every 5 s', 'logs_empty': 'No entries.', 'logs_count': 'Lines: {n}',
    'logs_level_all': 'All', 'logs_level_warning': 'Warnings and errors', 'logs_level_error': 'Errors only',
    'log_src_panel': 'Web panel', 'log_src_bot': 'Telegram bot', 'log_src_helper': 'Helper (privileged operations)',
    'log_src_sampler': 'Client and quota polling', 'log_src_backup': 'Backups', 'log_src_kernel_check': 'New kernel check',
    'log_src_kernel': 'Kernel: AmneziaWG module', 'log_src_server': 'Server {iface} (awg-quick)',
    'logs_history': 'Connection history and address masking', 'logs_history_on': 'Record connection history',
    'logs_history_hint': 'When a client connected, from which address, how long it stayed and how much it transferred. Built from handshakes once a minute.',
    'logs_retention': 'Keep for, days', 'logs_retention_hint': 'Older entries are removed automatically. From 1 to 365 days.',
    'logs_masking': 'Address masking',
    'logs_masking_hint': 'How public IPs are stored and shown: in the history, the audit log, bot notifications and the journal viewer. With “Full” the address is never stored.',
    'logs_mask_none': 'Do not hide (203.0.113.45:51820)', 'logs_mask_partial': 'Partial (203.0.113.x)', 'logs_mask_full': 'Full (IP-3f2a1c)',
    'logs_debug': 'AmneziaWG handshake debug', 'logs_debug_off': 'Off', 'logs_debug_on': 'On until {until} UTC',
    'logs_debug_warning': 'Detailed kernel module messages slow the server down and contain client addresses. Debug switches itself off after 15 minutes.',
    'logs_debug_hint': 'Use it when a client cannot connect, for example after changing the obfuscation: the “Kernel: AmneziaWG module” journal shows whether handshakes arrive and what happens to them.',
    'logs_debug_start': 'Switch on for 15 minutes', 'logs_debug_stop': 'Switch off now', 'logs_debug_view': 'View kernel messages',
    'logs_report': 'Support report',
    'logs_report_hint': 'An archive with diagnostics, versions, server settings and the latest journal lines. Keys, tokens, Endpoint and public addresses are replaced. Look through it before you send it.',
    'logs_report_button': 'Download the report', 'logs_save': 'Save',
    'audit_event': 'Event', 'audit_all_events': 'All events', 'audit_since': 'From', 'audit_until': 'To',
    'audit_pages': 'Audit log pages', 'audit_newer': 'Newer', 'audit_older': 'Older',
    'audit_page': 'Page {page} of {pages} · {total} entries',
    'sessions_title': 'Connection history', 'sessions_off': 'Connection history is off.',
    'sessions_enable': 'Switch it on under Maintenance → Logs',
    'sessions_now': 'online', 'sessions_start': 'Start (UTC)', 'sessions_end': 'End', 'sessions_length': 'Duration',
    'sessions_address': 'Address', 'sessions_traffic': 'Traffic', 'sessions_empty': 'No connections yet.',
    'sessions_note': 'The last 50 connections, kept for {days} days.', 'sessions_paused': 'Recording is off now.',
})
