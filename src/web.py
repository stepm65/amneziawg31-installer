"""Bilingual charcoal/amber AWG 3.1 console. Unprivileged; localhost only."""
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
import time
from urllib.parse import quote
import re
from datetime import datetime, timezone

import qrcode
from amnezialink import build_vpn_uri
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.middleware.sessions import SessionMiddleware

AUTH_FILE = Path(os.environ.get('AWG31_AUTH', '/etc/awg31-panel/auth.json'))
AUTH = json.loads(AUTH_FILE.read_text())
STYLESHEET = Path(__file__).with_name('panel.css')
SCRIPT = Path(__file__).with_name('panel.js')
COOKIE_SECURE = os.environ.get('AWG31_COOKIE_SECURE', '1') == '1'
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
        'server_switch':'Перейти', 'server_stop':'Остановить', 'server_start':'Запустить', 'server_remove':'Удалить сервер', 'server_remove_confirm':'Удалить сервер? Сначала удалите всех клиентов. Конфигурация будет перемещена в резервную копию.',
        'advanced':'Параметры обфускации AWG 3.1', 'generate':'Сгенерировать параметры',
        'advanced_hint':'Изменение S/H и HeaderProtectionKey потребует переимпорта конфигураций всех клиентов этого сервера.',
        'new_server_note':'Создание второго сервера не изменяет awg0. Подсети и UDP-порты не должны пересекаться.',
        'server_create_failed':'Не удалось создать сервер',
        'dashboard': 'Управление сервером', 'clients': 'Клиенты', 'settings': 'Настройки сервера',
        'documentation': 'Документация', 'logout': 'Выход', 'sign_in': 'Вход администратора',
        'login': 'Войти', 'password': 'Пароль администратора', 'login_error': 'Неверный пароль',
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
        'add_client': 'Добавить клиента', 'create': 'Создать',
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
    },
    'en': {
        'server_instances':'Servers and interfaces', 'new_server':'Create server',
        'new_server_hint':'Each server has independent keys, subnet, UDP port and clients.',
        'server_name':'Interface (e.g. awg1)', 'server_subnet':'IPv4 subnet',
        'server_uplink':'Uplink interface', 'server_mode':'Routing',
        'server_switch':'Open', 'server_stop':'Stop', 'server_start':'Start', 'server_remove':'Delete server', 'server_remove_confirm':'Delete server? Remove all clients first. The configuration will be backed up.',
        'advanced':'AWG 3.1 obfuscation parameters', 'generate':'Generate parameters',
        'advanced_hint':'Changing S/H and HeaderProtectionKey requires clients on this server to re-import their configurations.',
        'new_server_note':'Creating another server does not change awg0. Subnets and UDP ports must be unique.',
        'server_create_failed':'Could not create server',
        'dashboard': 'Server overview', 'clients': 'Clients', 'settings': 'Server settings',
        'documentation': 'Documentation', 'logout': 'Log out', 'sign_in': 'Administrator sign in',
        'login': 'Sign in', 'password': 'Administrator password', 'login_error': 'Incorrect password',
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
        'add_client': 'Add client', 'create': 'Create',
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
    },
}


# Operations/maintenance translations; all UI strings remain self-hosted.
TEXT['ru'].update({
    'policy':'Политика доступа', 'comment':'Комментарий', 'expires':'Дата отключения (UTC)',
    'quota':'Лимит трафика (ГиБ; 0 = без лимита)', 'usage':'Использовано',
    'save_policy':'Сохранить ограничения', 'history':'История трафика',
    'history_note':'Данные собираются системным таймером раз в минуту, даже когда панель закрыта.',
    'maintenance':'Обслуживание и безопасность', 'diagnostics':'Диагностика системы',
    'kernel_check':'Проверка модуля DKMS после обновления ядра',
    'backup':'Резервные копии', 'backup_make':'Создать полную резервную копию',
    'backup_secret':'Архив содержит приватные ключи и данные администратора. Храните его в безопасном месте.',
    'backup_download':'Скачать архив', 'backup_restore':'Восстановить', 'restore_warn':'Восстановление заменит настройки, клиентов и ключи из резервной копии, перезапустит VPN и панель. Текущие данные будут сохранены в аварийной копии.', 'restore_confirm':'Введите ВОССТАНОВИТЬ для подтверждения', 'restore_sent':'Восстановление запланировано. Соединение с панелью временно прервётся. Следите за журналом systemd.', 'profile':'Профиль сервера',
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
    'save_policy':'Save access limits', 'history':'Traffic history',
    'history_note':'Samples are collected by a systemd timer each minute, even when the panel is closed.',
    'maintenance':'Maintenance and security', 'diagnostics':'System diagnostics',
    'kernel_check':'DKMS module check after a kernel update',
    'backup':'Backups', 'backup_make':'Create full backup',
    'backup_secret':'Backups contain private keys and administrator credentials. Store them securely.',
    'backup_download':'Download archive', 'backup_restore':'Restore', 'restore_warn':'Restoration replaces settings, clients and keys from the backup and restarts the VPN and panel. Current data will be snapshotted first.', 'restore_confirm':'Type RESTORE to confirm', 'restore_sent':'Restore job scheduled. The panel may disconnect temporarily. Monitor systemd logs.', 'profile':'Server profile',
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
    'peer_routes_hint':'По одной сети на строку или через запятую; добавляются только на СЕРВЕРЕ в AllowedIPs этого peer. Например: 192.168.50.0/24 и 172.20.10.5/32.',
    'peer_routes_short':'Сети за клиентом',
    'cps_enabled':'Использовать I1–I5 для этого клиента',
    'cps_hint':'Опциональные CPS-пакеты, отправляемые клиентом перед handshake. По умолчанию выключены для совместимости QR и приложений.',
    'cps_label':'Дополнительные пакеты I1–I5 (опционально)',
    'cps_example':'Например: <r 48>',
    'peer_network_settings':'Маршруты и имитация трафика клиента',
    'save_client_network':'Сохранить параметры клиента',
    'client_network_saved':'Параметры клиента сохранены',
    'client_network_changed':'Если изменили I1–I5 — заново импортируйте .conf или QR на клиенте. Дополнительные маршруты требуют IPv4 forwarding и корректных обратных маршрутов на самом клиенте и за ним.',
    'routes_apply_warning':'Изменятся маршруты Linux и AllowedIPs peer. Рекомендуется делать это в окне обслуживания.',
    'qr_warning':'Большой I-профиль может создать слишком плотный QR; используйте .conf при необходимости.',
    'peer_address_static':'Основной VPN-адрес назначен автоматически и не изменяется при редактировании маршрутов.',
})
TEXT['en'].update({
    'peer_routes':'Networks or hosts behind this client (IPv4 CIDR)',
    'peer_routes_hint':'One CIDR per line or comma-separated; added only on the SERVER to this peer’s AllowedIPs. Examples: 192.168.50.0/24 and 172.20.10.5/32.',
    'peer_routes_short':'Behind-client networks',
    'cps_enabled':'Enable I1–I5 for this client',
    'cps_hint':'Optional client-originated CPS packets sent before handshake. Disabled by default for easier QR/app compatibility.',
    'cps_label':'Additional I1–I5 packets (optional)',
    'cps_example':'For example: <r 48>',
    'peer_network_settings':'Client routing and traffic imitation',
    'save_client_network':'Save client settings',
    'client_network_saved':'Client settings saved',
    'client_network_changed':'Re-import the client .conf/QR after changing I1–I5. Behind-client networks also require IPv4 forwarding and return routes on the client and its LAN.',
    'routes_apply_warning':'This updates Linux routes and peer AllowedIPs. Schedule routing changes carefully.',
    'qr_warning':'Long I1–I5 settings can make QR codes too dense; use .conf if scanning fails.',
    'peer_address_static':'The primary VPN address is assigned automatically and is unchanged when editing these routes.',
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
    'qr_overflow': 'QR слишком велик. Используйте копирование ссылки или скачивание .conf.',
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
    'qr_overflow': 'QR is too large. Copy the link or download the .conf instead.',
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
    'info': '<circle cx="12" cy="12" r="10"/><path d="M12 11v6M12 7h.01"/>',
    'check': '<path d="m5 12 4 4L19 6"/>',
    'arrow': '<path d="M5 12h14m-6-6 6 6-6 6"/>',
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


def ctl(command, data=None):
    proc = subprocess.run(['sudo', '-n', '/usr/local/sbin/awg31mgr', command],
                          input=json.dumps(data) if data is not None else None,
                          capture_output=True, text=True, timeout=(90 if command in ('server-create','backup-create','backup-export','backup-restore','backup-check') else 35))
    if proc.returncode:
        try:
            msg = json.loads(proc.stderr).get('error', 'Ошибка контроллера')
        except ValueError:
            msg = 'Ошибка контроллера: см. журнал службы'
        raise RuntimeError(str(msg)[:300])
    return json.loads(proc.stdout)


SERVER_RE = re.compile(r'^awg(?:0|[1-9][0-9]?)$')
OBF_EDIT_FIELDS = ('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4',
                   'HeaderProtectionKey','ContentPaddingAddition','RandomTrailers',
                   'DisableCookies','RekeyAfterTime','RekeyTimeout','RejectAfterTime',
                   'KeepaliveTimeout','MaxHandshakeAttempts')


def selected_server(request):
    value = request.cookies.get('awg31_server','awg0')
    return value if SERVER_RE.fullmatch(value) else 'awg0'


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


def require_csrf(request, token):
    require_auth(request)
    if not hmac.compare_digest(str(token), str(request.session.get('csrf', ''))):
        raise HTTPException(status_code=403, detail=tr(lang_of(request), 'csrf_error'))


def csrf(request):
    return f'<input type="hidden" name="csrf" value="{h(request.session.get("csrf", ""))}">'


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
    sidebar = ''
    if authenticated:
        sidebar = f'''<aside class="sidebar" aria-label="{h(tr(lang,'dashboard'))}">
          <div class="sidebar-nav-caption">AWG CONSOLE</div>
          <a class="side-link side-active" href="/#overview">{icon('home',17)}<span>{h(tr(lang,'nav_overview'))}</span></a>
          <a class="side-link" href="/#clients">{icon('users',17)}<span>{h(tr(lang,'clients'))}</span></a>
          <a class="side-link" href="/#servers">{icon('server',17)}<span>{h(tr(lang,'server_instances'))}</span></a>
          <a class="side-link" href="/#monitoring">{icon('activity',17)}<span>{h(tr(lang,'nav_monitoring'))}</span></a>
          <a class="side-link" href="/#settings">{icon('settings',17)}<span>{h(tr(lang,'settings'))}</span></a>
          <a class="side-link" href="/maintenance">{icon('shield',17)}<span>{h(tr(lang,'maintenance'))}</span></a>
          <div class="side-footer"><span class="side-footer-top"><span class="live-beacon"></span>{h(tr(lang,'module_info'))}</span>
          <strong>{h(tr(lang,'module_active'))}</strong><span class="side-footer-caption">KERNEL · NO DOCKER</span></div>
          </aside>'''
    status_link = (f'<a class="top-link" href="/logout">{icon("logout",16)}<span>{h(tr(lang,"logout"))}</span></a>'
                   if authenticated else '')
    refresh_button = (f'<button class="icon-btn" id="refresh-page" type="button" aria-label="{h(tr(lang,"refresh"))}" title="{h(tr(lang,"refresh"))}">{icon("restart",16)}</button>'
                      if authenticated else '')
    body = f'''<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>{h(title)} — AmneziaWG 3.1</title>
    <link rel="stylesheet" href="/assets/panel.css?v=0.6.0">
    <link rel="stylesheet" href="/assets/md3.css?v=0.6.0">
    <script defer src="/assets/panel.js?v=0.6.0"></script>
    </head><body>
    <header class="topbar"><a href="/" class="brand"><span class="brand-emblem">{icon('shield',18)}</span><span>AmneziaWG <b>3.1</b></span></a>
    <div class="topbar-right"><span class="top-kernel">KERNEL</span>{language_picker(request)}{refresh_button}{status_link}</div></header>
    <div class="shell">{sidebar}<main class="main {'main-login' if not authenticated else ''}">
    <div class="page-heading"><div><div class="eyebrow">AMNEZIAWG / CONTROL PANEL</div><h1>{h(title)}</h1>
    <p class="heading-subtitle">{h(tr(lang,'top_subtitle'))}</p></div></div>{content}</main></div></body></html>'''
    return HTMLResponse(body, headers={
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
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


@app.get('/assets/panel.js')
def javascript():
    return Response(SCRIPT.read_text(encoding='utf-8'), media_type='text/javascript',
                    headers={'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff'})


@app.get('/api/traffic')
def traffic(request: Request):
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


@app.get('/api/obfuscation/generate')
def obfuscation_generate(request: Request):
    require_auth(request)
    nums = secrets.SystemRandom().sample(range(10000, 2500000),4)
    sizes = [secrets.randbelow(50)+12 for _ in range(4)]
    while sizes[0] + 56 == sizes[1]: sizes[1] = secrets.randbelow(50)+12
    params = {'Jc':secrets.randbelow(5)+4, 'Jmin':10, 'Jmax':50,
              **{k:sizes[i] for i,k in enumerate(('S1','S2','S3','S4'))},
              **{f'H{i+1}':str(n) for i,n in enumerate(nums)},
              'HeaderProtectionKey':base64.b64encode(secrets.token_bytes(32)).decode(),
              'ContentPaddingAddition':'0-16','RandomTrailers':'on','DisableCookies':'on'}
    return Response(json.dumps(params),media_type='application/json',
                    headers={'Cache-Control':'no-store'})

@app.get('/server/{interface}')
def server_switch(request:Request, interface:str):
    require_auth(request)
    if not SERVER_RE.fullmatch(interface) or interface not in [x['interface'] for x in server_list()]:
        raise HTTPException(404)
    response = RedirectResponse('/', status_code=303)
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
        if not SERVER_RE.fullmatch(iface) or iface=='awg0':
            raise RuntimeError('Use an interface name such as awg1')
        ctl('server-create',data)
        audit_event('server_created',iface)
    except RuntimeError as exc:
        return error_page(request,tr(lang,'server_create_failed'),exc)
    response=RedirectResponse('/',status_code=303)
    response.set_cookie('awg31_server',iface,secure=COOKIE_SECURE,httponly=True,
                        samesite='strict',path='/',max_age=365*86400)
    return response

@app.post('/server/{interface}/{action}')
async def server_service_action(request:Request,interface:str,action:str):
    body=await request.form()
    require_csrf(request,body.get('csrf',''))
    if not SERVER_RE.fullmatch(interface) or action not in ('start','stop','delete'):
        raise HTTPException(404)
    try:
        payload={'interface':interface}
        if action=='delete':
            payload['confirm']=str(body.get('confirm',''))
        ctl('server-'+action, payload)
        audit_event('server_'+{'start':'started','stop':'stopped','delete':'deleted'}[action],interface)
    except RuntimeError as exc:
        return error_page(request,tr(lang_of(request),'error'),exc)
    if action == 'delete':
        response=RedirectResponse('/',status_code=303)
        response.delete_cookie('awg31_server')
        return response
    return RedirectResponse('/',status_code=303)


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


def login_form(request, error=''):
    lang = lang_of(request)
    msg = f'<p class="error-message" role="alert">{h(error)}</p>' if error else ''
    return page(tr(lang, 'sign_in'), f'''<section class="card login-card">
        <div class="login-mark">{icon('lock',28)}</div>
        {msg}<form method="post" action="/login">
        <label class="field" for="password"><span>{h(tr(lang,'password'))}</span>
        <input id="password" type="password" name="password" required autocomplete="current-password"></label>
        <button class="btn btn-primary full-width" type="submit">{h(tr(lang,'login'))}{icon('arrow',18)}</button>
        </form></section>''', request)


@app.get('/health')
def health():
    return {'ok': True, 'service': 'awg31-panel'}


@app.get('/login')
def login_get(request: Request):
    return RedirectResponse('/') if logged(request) else login_form(request)


@app.post('/login')
def login_post(request: Request, password: str = Form(...)):
    lang = lang_of(request)
    now = time.monotonic()
    address = str(request.client.host if request.client else 'unknown')[:80]
    attempts = [t for t in login_attempts.get(address,[]) if now-t<300]
    # Cap the dictionary size and avoid unlimited entries from varied addresses.
    if len(login_attempts)>4096: login_attempts.clear()
    login_attempts[address]=attempts
    if len(attempts) >= 5:
        return page(tr(lang, 'sign_in'),
                    '<section class="card"><p role="alert">'+h(tr(lang,'login_limited'))+'</p></section>',request)
    try:
        auth=read_auth()
        candidate=hashlib.scrypt(password.encode('utf-8'),salt=bytes.fromhex(auth['salt']),
                                 n=2**14,r=8,p=1,dklen=32)
        valid=hmac.compare_digest(candidate.hex(),auth['password_hash'])
    except (ValueError,OverflowError,OSError): valid=False
    if not valid:
        attempts.append(now)
        audit_event('login_failed',address)
        return login_form(request,tr(lang,'login_error'))
    login_attempts.pop(address,None)
    audit_event('login_success',address)
    request.session.clear()
    request.session['authenticated']=True
    request.session['auth_version']=auth.get('auth_version','')
    request.session['csrf']=secrets.token_urlsafe(32)
    return RedirectResponse('/', status_code=303)


@app.get('/logout')
def logout(request: Request):
    request.session.clear()
    return RedirectResponse('/login', status_code=303)


def form_field(name, val, label, help='', required=True, field_id=None):
    extra = ' inputmode="numeric"' if name in ('port', 'mtu') else ''
    field_id = field_id or name
    req = " required" if required else ""
    return (f'<label class="field" for="{field_id}"><span>{h(label)}</span>'
            f'<input id="{field_id}" name="{name}" value="{h(val)}"{extra}{req}>'
            f'{"<small>"+h(help)+"</small>" if help else ""}</label>')


def stat(icon_name, label, value, *, mono=True, detail=''):
    klass = 'mono' if mono else ''
    return (f'<div class="stat"> <span class="stat-icon">{icon(icon_name,22)}</span>'
            f'<div class="stat-body"><span class="stat-label">{h(label)}</span>'
            f'<span class="stat-value {klass}">{h(value)}</span>'
            f'{"<span class=\"stat-caption\">" + h(detail) + "</span>" if detail else ""}'
            f'</div></div>')


def error_page(request, heading, exc):
    lang = lang_of(request)
    return page(heading, f'<section class="card message-card"><p class="error-message" role="alert">'
                + h(controller_message(lang, exc)) + '</p>'
                + f'<a class="btn btn-secondary" href="/">{icon("arrow",18)}{h(tr(lang,"back"))}</a></section>', request)


@app.get('/')
def index(request: Request):
    if not logged(request):
        return RedirectResponse('/login')
    lang = lang_of(request)
    t = lambda key: tr(lang, key)
    try:
        state = control(request,'list')
    except RuntimeError as exc:
        return error_page(request, t('error'), exc)

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
    rows = ''
    for c in state['clients']:
        st = c.get('stats', {})
        seen = (time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(st['handshake']))
                if st.get('handshake') else t('never'))
        name = h(c['name'])
        encoded_name = quote(c['name'], safe='')
        active = bool(c['enabled'])
        status_class = 'running' if active else 'stopped'
        actions = f'<a class="btn btn-secondary btn-small" href="/client/{encoded_name}">{icon("file",16)}{h(t("client_details"))}</a>'
        toggle = 'disable' if active else 'enable'
        actions += (f'<form method="post" action="/client/{encoded_name}/{toggle}" class="inline">'
                    f'{csrf(request)}<button class="btn btn-secondary btn-small" type="submit">'
                    f'{icon("pause" if active else "play",16)}{h(t("disable" if active else "enable"))}'
                    '</button></form>')
        actions += (f'<form method="post" action="/client/{encoded_name}/delete" class="inline" data-confirm="{h(t("confirm_delete"))}">'
                    f'{csrf(request)}<button class="btn btn-danger btn-small" type="submit">'
                    f'{icon("trash",16)}{h(t("delete"))}</button></form>')
        rows += (f'<tr class="client-row" data-name="{h(c["name"].lower())}" data-ip="{h(c["ip"])}" data-enabled="{int(active)}"><td class="client-name">{icon("server",16)}<span>{h(c["name"])}</span></td>'
                 f'<td><code class="ip-pill">{h(c["ip"])}</code>'
                 f'<small class="peer-routes-compact">{h(c.get("routed_subnets", ""))}</small></td>'
                 f'<td><span class="pill pill-{status_class}"><span class="dot"></span>'
                 f'{h(t("active" if active else "disabled"))}</span><small class="handshake">{h(seen)}</small></td>'
                 f'<td><span class="traffic mono">↓ {h(st.get("received",0))} B <span class="traffic-divider"></span> '
                 f'↑ {h(st.get("sent",0))} B</span></td>'
                 f'<td><div class="actions">{actions}</div></td></tr>')

    if not rows:
        rows = (f'<tr><td colspan="5"><div class="empty-state">{icon("users",26)}'
                f'<strong>{h(t("no_clients"))}</strong><span>{h(t("no_clients_hint"))}</span>'
                '</div></td></tr>')
    clients = f'''<section class="card clients-card" id="clients">
        <div class="section-title"><div><span class="section-overline">PEERS / ACCESS</span>
        <h2>{icon('users',20)}{h(t('clients'))}</h2>
        <p class="section-subtitle">{h(t('client_help'))}</p></div>
        <a class="btn btn-primary" href="#add-client">{icon('plus',16)}{h(t('add_client'))}</a></div>
        <div class="table-tools"><label class="table-search">{icon('search',16)}<input id="client-search" type="search" placeholder="{h(t('search_clients'))}" aria-label="{h(t('search_clients'))}"></label>
        <select id="client-filter" aria-label="{h(t('status'))}"><option value="all">{h(t('all_clients'))}</option><option value="enabled">{h(t('active_only'))}</option></select>
        <span class="table-count mono">{len(clients_all)} PEERS</span></div>
        <div class="table-scroll"><table><thead><tr>
        <th>{h(t('name'))}</th><th>{h(t('vpn_ip'))}</th><th>{h(t('status'))}</th>
        <th>{h(t('traffic'))}</th><th>{h(t('actions'))}</th></tr></thead><tbody>{rows}</tbody></table></div>
        <div class="add-client" id="add-client"><div><span class="section-overline">NEW PEER</span><h3>{icon('plus',18)}{h(t('add_client'))}</h3></div>
        <form class="add-client-form" method="post" action="/client">{csrf(request)}
        <label class="field" for="client-name"><span>{h(t('client_name'))}</span>
        <input id="client-name" name="name" placeholder="{h(t('client_placeholder'))}"
        pattern="[A-Za-z0-9][A-Za-z0-9_-]*" maxlength="32" required></label>
        <div class="peer-network-options">
          <label class="field" for="routed-subnets-new"><span>{h(t('peer_routes'))}</span>
          <textarea id="routed-subnets-new" name="routed_subnets" rows="2" placeholder="192.168.50.0/24"></textarea>
          <small>{h(t('peer_routes_hint'))}</small></label>
          <div class="fields-grid">
            {form_field('comment','',t('comment'),required=False,field_id='new-comment')}
            {form_field('expires_at','',t('expires'),required=False,field_id='new-expires')}
            {form_field('quota_gib','0',t('quota'),required=False,field_id='new-quota')}
          </div>
          <details class="cps-box"><summary>{h(t('cps_label'))}</summary>
          <label class="check-field"><input type="checkbox" name="i_enabled" value="1"><span>{h(t('cps_enabled'))}</span></label>
          <p class="info-line">{h(t('cps_hint'))}</p>
          <div class="fields-grid">{''.join(form_field(f'i{i}', '', f'I{i}', required=False, field_id=f'new-i{i}') for i in range(1,6))}</div>
          </details>
        </div>
        <button class="btn btn-primary" type="submit">{icon('plus',16)}{h(t('create'))}</button>
        </form></div></section>'''
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
           f'<input type="hidden" name="confirm" value="{h(x["interface"])}">'
           f'<button class="btn btn-danger btn-small" type="submit">{h(t("server_remove"))}</button></form>'
           if x['interface'] != 'awg0' and not x.get('clients',0) else '')
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
    ])
    obf=state.get('obfuscation') or {}
    obf_labels={key:key for key in OBF_EDIT_FIELDS}
    obf_inputs=''.join(form_field(key, obf.get(key,''), obf_labels[key], required=(key not in ('RekeyAfterTime','RekeyTimeout','RejectAfterTime','KeepaliveTimeout','MaxHandshakeAttempts')))
                       for key in OBF_EDIT_FIELDS if key not in ('RandomTrailers','DisableCookies'))
    obf_inputs+=''.join('<label class="field"><span>'+h(key)+'</span><select name="'+key+'">'
             +''.join('<option value="'+val+'" '+('selected' if obf.get(key,'on')==val else '')+'>'
             +val+'</option>' for val in ('on','off'))+'</select></label>'
             for key in ('RandomTrailers','DisableCookies'))
    advanced=f'''<details class="advanced-box" id="obfuscation"><summary>{icon('settings',16)}{h(t('advanced'))}</summary>
          <p class="info-line">{h(t('advanced_hint'))}</p>
          <button class="btn btn-secondary" id="generate-obf" type="button">{icon('restart',16)}{h(t('generate'))}</button>
          <div class="fields-grid" id="obfuscation-fields">{obf_inputs}</div></details>'''
    settings = f'''<section class="card settings-card" id="settings"><div class="section-title">
        <div><span class="section-overline">SYSTEM / CONFIG</span><h2>{icon('settings',20)}{h(t('settings'))}</h2></div></div>
        <p class="section-subtitle">{h(t('settings_hint'))}</p>
        <form method="post" action="/settings" data-confirm="{h(t('confirm_restart'))}">{csrf(request)}
        <div class="fields-grid">{fields}</div>{advanced}
        <button class="btn btn-primary" type="submit">{icon('restart',18)}{h(t('save_restart'))}</button>
        </form><p class="info-line">{icon('info',16)}{h(t('settings_note'))}</p></section>'''
    return page(t('dashboard'), head + history_html + servers_html + clients + settings, request)


@app.post('/settings')
async def settings(request: Request):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    lang=lang_of(request)
    payload={k: str(form[k]) for k in ('endpoint','port','mtu','dns') if k in form}
    payload.update({k: str(form[k]) for k in OBF_EDIT_FIELDS if k in form})
    try:
        control(request,'settings',payload)
        audit_event('server_settings_changed',selected_server(request))
    except RuntimeError as exc:
        return error_page(request,tr(lang,'settings_error'),exc)
    return page(tr(lang,'settings_saved'),'<section class="card message-card">'
                + f'<p>{h(tr(lang,"settings_saved_hint"))}</p><a class="btn btn-primary" href="/">'
                + h(tr(lang,'back')) + '</a></section>',request)

@app.post('/client')
async def create(request: Request):
    data = await request.form()
    require_csrf(request, data.get('csrf',''))
    payload = {'name':str(data.get('name','')),
               'comment':str(data.get('comment','')),
               'expires_at':str(data.get('expires_at','')),
               'traffic_limit_bytes':gib_bytes(data.get('quota_gib','0')),
               'routed_subnets':str(data.get('routed_subnets','')),
               'i_enabled':'1' if data.get('i_enabled')=='1' else '0',
               **{f'i{n}':str(data.get(f'i{n}','')) for n in range(1,6)}}
    try:
        result = control(request, 'add', payload)
    except RuntimeError as exc:
        return error_page(request, tr(lang_of(request), 'create_error'), exc)
    audit_event('client_added',result['name'])
    return RedirectResponse('/client/' + quote(result['name'], safe=''), status_code=303)


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
    return build_vpn_uri(obj['config'], name=name, server_ip=obj['server_ip'],
                         subnet=obj['subnet'], client_public_key=obj['client_public_key'])


@app.get('/client/{name}')
def detail(request: Request, name: str):
    require_auth(request)
    lang = lang_of(request)
    try:
        obj = control(request,'download', {'name': name})
    except RuntimeError as exc:
        return error_page(request, tr(lang, 'not_available'), exc)
    name_url = quote(name, safe='')
    t = lambda key: tr(lang,key)
    i_fields = ''.join(form_field(f'i{x}', obj.get(f'i{x}',''), f'I{x}', required=False,
                                   field_id=f'detail-i{x}') for x in range(1,6))
    checked = ' checked' if obj.get('i_enabled') else ''
    try:
        share_uri = build_client_link(obj, name)
    except (ValueError, KeyError, TypeError):
        share_uri = None
    safe_name = h(name)
    config = obj['config']
    qr_conf = f'/client/{name_url}/qr?mode=conf'
    qr_vpn = f'/client/{name_url}/qr?mode=vpn'
    # The tab is deliberately disabled rather than inventing a URI for old
    # controllers that do not return a client's public key.
    link_contents = (f'''<div class="share-grid"><figure class="qr-frame">
          <img alt="{h(t('share_link_tab'))} QR" loading="lazy" src="{qr_vpn}">
          <figcaption><a class="btn btn-secondary btn-small" href="{qr_vpn}&amp;download=1">{h(t('save_qr'))}</a></figcaption>
          </figure><div class="share-text-col"><p class="info-line">{h(t('vpn_link_note'))}</p>
          <label class="sr-only" for="share-vpn-text">{h(t('share_link_tab'))}</label>
          <textarea id="share-vpn-text" class="share-text" readonly spellcheck="false">{h(share_uri)}</textarea>
          <div class="share-actions"><button type="button" class="btn btn-secondary" data-copy-target="share-vpn-text">{h(t('copy'))}</button>
          <a class="btn btn-primary" href="/client/{name_url}/vpn-link?download=1">{h(t('save_vpn'))}</a></div></div></div>'''
          if share_uri else f'<p role="status" class="info-line">{h(t("link_unavailable"))}</p>')
    link_disabled = '' if share_uri else ' disabled aria-disabled="true"'
    contents = f'''<section class="card detail-card share-dialog" aria-label="{h(t('share_config'))}">
        <div class="section-title share-heading"><div><span class="section-overline">PEER / EXPORT</span>
        <h2>{icon('file',21)}{h(t('share_config'))}: <span class="mono">{safe_name}</span></h2></div>
        <a class="btn btn-secondary btn-small" href="/#clients">{icon('arrow',16)}{h(t('close_window'))}</a></div>
        <div class="share-security">{icon('lock',16)}{h(t('sensitive_data'))}</div>
        <div class="share-tabs" role="tablist" aria-label="{h(t('share_config'))}">
          <button class="share-tab is-active" type="button" role="tab" id="share-tab-conf" aria-controls="share-panel-conf" aria-selected="true" data-tab-target="share-panel-conf">{h(t('share_conf_tab'))}</button>
          <button class="share-tab" type="button" role="tab" id="share-tab-vpn" aria-controls="share-panel-vpn" aria-selected="false" data-tab-target="share-panel-vpn"{link_disabled}>{h(t('share_link_tab'))}</button>
        </div>
        <section class="share-tab-panel" role="tabpanel" id="share-panel-conf" aria-labelledby="share-tab-conf">
          <div class="share-grid"><figure class="qr-frame">
            <img alt="{h(t('share_conf_tab'))} QR" loading="lazy" src="{qr_conf}">
            <figcaption><a class="btn btn-secondary btn-small" href="{qr_conf}&amp;download=1">{h(t('save_qr'))}</a></figcaption></figure>
            <div class="share-text-col"><p class="info-line">{h(t('conf_qr_note'))}</p>
            <label class="sr-only" for="share-conf-text">{h(t('share_conf_tab'))}</label>
            <textarea id="share-conf-text" class="share-text" readonly spellcheck="false">{h(config)}</textarea>
            <div class="share-actions"><button class="btn btn-secondary" type="button" data-copy-target="share-conf-text">{h(t('copy'))}</button>
            <a class="btn btn-primary" href="/client/{name_url}/download">{icon('file',16)}{h(t('download'))}</a></div>
            </div></div></section>
        <section class="share-tab-panel" role="tabpanel" id="share-panel-vpn" aria-labelledby="share-tab-vpn" hidden>{link_contents}</section>
        <p class="sr-only" aria-live="polite" id="copy-status" data-copy-ok="{h(t('copy_ok'))}" data-copy-failed="{h(t('copy_failed'))}"></p>
        </section>'''
    network_form = f'''<section class="card detail-card client-options">
        <details><summary class="section-title"><h2>{icon('network',20)}{h(t('client_options'))}</h2></summary>
        <p class="info-line"><strong class="mono">{h(obj.get('ip',name))}/32</strong> · {h(t('peer_address_static'))}</p>
        <form method="post" action="/client/{name_url}/network" data-confirm="{h(t('routes_apply_warning'))}">
          {csrf(request)}
          <label class="field" for="edit-routed-subnets"><span>{h(t('peer_routes'))}</span>
          <textarea id="edit-routed-subnets" name="routed_subnets" rows="3" placeholder="192.168.50.0/24">{h(obj.get('routed_subnets',''))}</textarea>
          <small>{h(t('peer_routes_hint'))}</small></label>
          <details class="cps-box"><summary>{h(t('cps_label'))}</summary>
          <label class="check-field"><input type="checkbox" name="i_enabled" value="1"{checked}><span>{h(t('cps_enabled'))}</span></label>
          <p class="info-line">{h(t('cps_hint'))}</p><div class="fields-grid">{i_fields}</div></details>
          <p class="info-line">{h(t('client_network_changed'))}</p>
          <button type="submit" class="btn btn-primary">{icon('check',16)}{h(t('save_client_network'))}</button>
        </form></details></section>'''
    policy_form=f'''<section class="card detail-card client-policy">
      <h2>{icon('clock',20)}{h(t('policy'))}</h2>
      <p class="info-line">{h(t('policy_note'))}</p>
      <p>{h(t('usage'))}: <strong>{h(gib_format(obj.get('used_bytes',0)))} GiB</strong></p>
      <form method="post" action="/client/{name_url}/policy">{csrf(request)}
      <div class="fields-grid">
        {form_field('comment',obj.get('comment',''),t('comment'),required=False,field_id='policy-comment')}
        {form_field('expires_at',(obj.get('expires_at') or '')[:10],t('expires'),required=False,field_id='policy-expires')}
        {form_field('quota_gib',gib_format(obj.get('traffic_limit_bytes',0)),t('quota'),required=False,field_id='policy-quota')}
      </div><button class="btn btn-primary" type="submit">{h(t('save_policy'))}</button>
      </form></section>'''
    return page(t('client') + ' ' + name, contents + network_form + policy_form, request)


@app.post('/client/{name}/network')
async def client_network(request: Request, name: str):
    data = await request.form()
    require_csrf(request, data.get('csrf', ''))
    payload = {'name':name, 'routed_subnets':str(data.get('routed_subnets','')),
               'i_enabled':'1' if data.get('i_enabled')=='1' else '0',
               **{f'i{n}':str(data.get(f'i{n}','')) for n in range(1,6)}}
    try:
        control(request,'client-network',payload)
        audit_event('client_modified',name)
    except RuntimeError as exc:
        return error_page(request,tr(lang_of(request),'error'),exc)
    return RedirectResponse('/client/'+quote(name,safe=''),status_code=303)


@app.post('/client/{name}/policy')
async def policy_update(request: Request, name: str):
    form=await request.form()
    require_csrf(request,form.get('csrf',''))
    payload={'name':name,'comment':str(form.get('comment','')),
             'expires_at':str(form.get('expires_at','')),
             'traffic_limit_bytes':gib_bytes(form.get('quota_gib','0'))}
    try: control(request,'client-policy',payload)
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'error'),exc)
    audit_event('client_modified',name)
    return RedirectResponse('/client/'+quote(name,safe=''),status_code=303)


@app.get('/api/history')
def history_api(request: Request, window: str = '24h'):
    require_auth(request)
    if window not in ('24h','7d','30d'): raise HTTPException(422)
    try: result=control(request,'history',{'window':window})
    except RuntimeError: raise HTTPException(503)
    return Response(json.dumps(result),media_type='application/json',
                    headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.get('/client/{name}/download')
def download(request: Request, name: str):
    require_auth(request)
    obj = control(request,'download', {'name': name})
    return Response(obj['config'], media_type='application/octet-stream',
                    headers={'Content-Disposition': f'attachment; filename="{name}.conf"',
                             'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@app.get('/client/{name}/vpn-link')
def vpn_link(request: Request, name: str, download: bool = False):
    require_auth(request)
    obj = control(request, 'download', {'name': name})
    try:
        uri = build_client_link(obj, name)
    except (ValueError, KeyError, TypeError):
        raise HTTPException(422, detail=tr(lang_of(request), 'link_unavailable')) from None
    headers = {'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'}
    if download:
        headers['Content-Disposition'] = f'attachment; filename="{name}.vpn"'
    return Response(uri + '\n', media_type='text/plain; charset=utf-8', headers=headers)


@app.get('/client/{name}/qr')
def qr(request: Request, name: str, mode: str = 'conf', download: bool = False):
    require_auth(request)
    if mode not in ('conf', 'vpn'):
        raise HTTPException(404)
    obj = control(request,'download', {'name': name})
    if mode == 'vpn':
        try:
            payload = build_client_link(obj, name)
        except (ValueError, KeyError, TypeError):
            raise HTTPException(422, detail=tr(lang_of(request), 'link_unavailable')) from None
    else:
        payload = obj['config']
    try:
        pic = qrcode.make(payload, error_correction=qrcode.constants.ERROR_CORRECT_L)
    except qrcode.exceptions.DataOverflowError:
        raise HTTPException(status_code=422, detail=tr(lang_of(request), 'qr_overflow')) from None
    buffer = io.BytesIO()
    pic.save(buffer, format='PNG')
    headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options':'nosniff'}
    if download:
        headers['Content-Disposition'] = f'attachment; filename="{name}-{mode}-qr.png"'
    return Response(buffer.getvalue(), media_type='image/png', headers=headers)


@app.post('/client/{name}/{action}')
def client_operation(request: Request, name: str, action: str, csrf: str = Form(...)):
    require_csrf(request, csrf)
    if action not in ('enable', 'disable', 'delete'):
        raise HTTPException(404)
    try:
        control(request,action, {'name': name})
        audit_event({'enable':'client_enabled','disable':'client_disabled','delete':'client_deleted'}[action],name)
    except RuntimeError as exc:
        return error_page(request, tr(lang_of(request), 'error'), exc)
    return RedirectResponse('/', status_code=303)


@app.get('/maintenance')
def maintenance(request: Request):
    require_auth(request)
    lang=lang_of(request);t=lambda k:tr(lang,k)
    try:
        diag=control(request,'diagnostics')
        backups=ctl('backup-list',{}).get('backups',[])
        entries=ctl('audit-list',{}).get('entries',[])
    except RuntimeError as exc: return error_page(request,t('maintenance_error'),exc)
    checks=''.join(f'<tr><td>{h(key)}</td><td class="mono">{h(str(value.get("output",""))[:320])}</td><td>{"OK" if value.get("ok") else "WARN"}</td></tr>'
                   for key,value in diag.items() if isinstance(value,dict))
    backup_rows=''.join(f'<li class="audit-item"><span class="mono">{h(item["name"])}</span> · {h(item["size"])} B '
                  f'<a class="btn btn-secondary btn-small" href="/maintenance/backup/{h(item["name"])}">{h(t("backup_download"))}</a>'
                  f'<form method="post" action="/maintenance/restore" class="inline-form">{csrf(request)}'
                  f'<input type="hidden" name="name" value="{h(item["name"])}">'
                  f'<label>{h(t("restore_confirm"))}<input type="text" name="confirmation" autocomplete="off" required></label>'
                  f'<button type="submit" class="btn btn-secondary btn-small">{h(t("backup_restore"))}</button></form></li>'
                  for item in backups)
    log_rows=''.join(f'<li class="audit-item"><span class="mono">{h(item.get("timestamp",""))}</span> '
                  f'{h(item.get("event",""))} · {h(item.get("target",""))}</li>' for item in reversed(entries))
    body=f'''<section class="card settings-card">
      <h2>{icon('shield',20)}{h(t('maintenance'))}</h2>
      <div class="maintenance-columns"><div><h3>{h(t('diagnostics'))}</h3>
      <p class="info-line">{h(t('kernel_check'))}</p>
      <div class="table-scroll"><table><tbody>{checks}</tbody></table></div></div>
    </section>
    <section class="card settings-card"><h2>{h(t('backup'))}</h2>
      <p class="info-line">{h(t('backup_secret'))} {h(t('restore_warn'))}</p>
      <form method="post" action="/maintenance/backup">{csrf(request)}
      <button class="btn btn-primary" type="submit">{h(t('backup_make'))}</button></form>
      <ul>{backup_rows}</ul></section>
    <section class="card settings-card"><h2>{h(t('profile'))}</h2>
      <p class="info-line">{h(t('profile_note'))}</p>
      <a class="btn btn-secondary" href="/maintenance/profile">{h(t('profile_download'))}</a>
      <form method="post" action="/maintenance/profile" data-confirm="{h(t('confirm_import'))}">{csrf(request)}
      <label class="field"><span>{h(t('profile_content'))}</span>
      <textarea name="profile" rows="7" required maxlength="16000" spellcheck="false"></textarea></label>
      <button class="btn btn-primary" type="submit">{h(t('profile_import'))}</button></form></section>
    <section class="card settings-card"><h2>{h(t('password_change'))}</h2>
      <form method="post" action="/maintenance/password">{csrf(request)}
      <div class="fields-grid">
      <label class="field"><span>{h(t('password_old'))}</span><input type="password" name="old" required autocomplete="current-password"></label>
      <label class="field"><span>{h(t('password_new'))}</span><input type="password" name="new" minlength="12" required autocomplete="new-password"></label>
      <label class="field"><span>{h(t('password_confirm'))}</span><input type="password" name="confirm" minlength="12" required autocomplete="new-password"></label>
      </div><button class="btn btn-primary" type="submit">{h(t('password_change'))}</button></form></section>
    <section class="card settings-card"><h2>{h(t('audit'))}</h2>
      <ul>{log_rows or h(t('audit_empty'))}</ul></section>'''
    return page(t('maintenance'),body,request)


@app.post('/maintenance/backup')
async def make_backup(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    try: result=ctl('backup-create',{})
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    return RedirectResponse('/maintenance',status_code=303)


@app.post('/maintenance/restore')
async def restore_backup(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    lang=lang_of(request)
    expected='ВОССТАНОВИТЬ' if lang=='ru' else 'RESTORE'
    if str(form.get('confirmation','')).strip()!=expected:
        raise HTTPException(status_code=400,detail='Restore confirmation mismatch')
    name=str(form.get('name',''))
    if not re.fullmatch(r'awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz',name):
        raise HTTPException(400,detail='Invalid backup name')
    try:
        ctl('backup-check',{'name':name})
        result=ctl('backup-restore',{'name':name})
    except RuntimeError as exc:
        return error_page(request,tr(lang,'maintenance_error'),exc)
    return HTMLResponse('<!doctype html><html lang="'+lang+'"><meta charset="utf-8"><title>AWG restore</title>'
                        '<body><h2>'+h(tr(lang,'restore_sent'))+'</h2><p>'+h(result['scheduled'])+'</p></body></html>',
                        status_code=202,headers={'Cache-Control':'no-store'})


@app.get('/maintenance/backup/{name}')
def download_backup(request: Request, name: str):
    require_auth(request)
    if not re.fullmatch(r'awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz',name):
        raise HTTPException(404)
    try: value=ctl('backup-export',{'name':name})
    except RuntimeError: raise HTTPException(404)
    return Response(base64.b64decode(value['content'],validate=True),
                    media_type='application/octet-stream',headers={
         'Content-Disposition':f'attachment; filename="{name}"',
         'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.get('/maintenance/profile')
def export_profile(request: Request):
    require_auth(request)
    try: profile=control(request,'profile-export')
    except RuntimeError as exc: return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    iface=selected_server(request)
    return Response(json.dumps(profile,indent=2,ensure_ascii=False),media_type='application/json',
      headers={'Content-Disposition':f'attachment; filename="{iface}-profile.json"',
               'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@app.post('/maintenance/profile')
async def import_profile(request: Request):
    form=await request.form();require_csrf(request,form.get('csrf',''))
    content=str(form.get('profile',''))
    if len(content)>16000: raise HTTPException(413)
    try:
        profile=json.loads(content)
        control(request,'profile-import',{'profile':profile})
    except (RuntimeError,ValueError) as exc:
        return error_page(request,tr(lang_of(request),'maintenance_error'),exc)
    audit_event('profile_imported',selected_server(request))
    return RedirectResponse('/maintenance',status_code=303)


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
