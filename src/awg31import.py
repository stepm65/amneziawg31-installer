"""Client lists from other panels, read into one neutral form.

Runs inside the web panel, without privileges, on files the administrator uploads.
Nothing here is trusted later: awg31mgr and awg31ctl validate every field again.

Sources:
  wg-easy 15            /etc/wireguard/wg-easy.db (SQLite, clients_table)
  wg-easy 14 and older  /etc/wireguard/wg0.json
  3x-ui                 /etc/x-ui/x-ui.db (WireGuard and AmneziaWG inbounds, the clients table, devices)
  AmneziaVPN            /opt/amnezia/awg/awg0.conf (or wg0.conf) and /opt/amnezia/awg/clientsTable
  any WireGuard server  a .conf with [Peer] blocks; names come from the comment above each peer
"""
import base64
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone

MAX_FILE = 32 * 1024 * 1024
MAX_CLIENTS = 500
KEY_RE = re.compile(r'^[A-Za-z0-9+/]{43}=$')
NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$')
SOURCES = {'wg-easy-15': 'wg-easy 15', 'wg-easy-14': 'wg-easy 14', '3x-ui': '3x-ui', 'amnezia': 'AmneziaVPN',
           'conf': 'WireGuard / AmneziaWG (.conf)'}
_RU = dict(zip('абвгдеёжзийклмнопрстуфхцчшщъыьэюя',
               ['a', 'b', 'v', 'g', 'd', 'e', 'e', 'zh', 'z', 'i', 'y', 'k', 'l', 'm', 'n', 'o', 'p', 'r', 's', 't', 'u',
                'f', 'h', 'ts', 'ch', 'sh', 'sch', '', 'y', '', 'e', 'yu', 'ya']))


class ImportError_(ValueError):
    """A file that cannot be read as any known source."""


def clean_name(raw, fallback='client'):
    """A client name the console accepts: Latin letters, digits, - and _, up to 32 characters."""
    text = ''.join((_RU[c.lower()].capitalize() if c != c.lower() else _RU[c]) if c.lower() in _RU else c
                   for c in str(raw or ''))
    text = re.sub(r'[^A-Za-z0-9_-]+', '-', text).strip('-_')
    text = re.sub(r'-{2,}', '-', text)[:32].strip('-_')
    return text if text and NAME_RE.fullmatch(text) else fallback


def unique_names(records, taken=()):
    """Give each record a distinct console name, kept apart from the names already taken."""
    used = {n.lower() for n in taken}
    for n, record in enumerate(records, 1):
        base = clean_name(record.get('source_name'), f'client-{n}')
        name, k = base, 2
        while name.lower() in used:
            suffix = f'-{k}'
            name = base[:32 - len(suffix)] + suffix
            k += 1
        used.add(name.lower())
        record['name'] = name
    return records


def key(value):
    text = str(value or '').strip()
    if not KEY_RE.fullmatch(text):
        return ''
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return ''
    return text if len(raw) == 32 and any(raw) else ''


def first_ipv4(value):
    items = value if isinstance(value, list) else re.split(r'[,\s]+', str(value or ''))
    for item in items:
        try:
            network = ipaddress.ip_interface(str(item).strip())
        except ValueError:
            continue
        if network.version == 4:
            return str(network.ip)
    return ''


def iso_time(value):
    """ISO 8601 (UTC) from what the sources keep: milliseconds since 1970, ISO strings, 'YYYY-MM-DD HH:MM:SS'."""
    if value in (None, '', 0):
        return ''
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r'-?[0-9]{9,16}', str(value)):
            number = int(value)
            if number <= 0:
                return ''                                   # 3x-ui: a negative term starts at the first connection
            moment = datetime.fromtimestamp(number / 1000 if number > 10 ** 11 else number, timezone.utc)
        else:
            moment = datetime.fromisoformat(str(value).strip().replace('Z', '+00:00').replace(' ', 'T'))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except (ValueError, OverflowError, OSError):
        return ''


def record(source_name, *, private='', public='', psk='', address='', enabled=True, expires='', limit=0, monthly=False,
           comment='', group='', telegram='', owner=''):
    private, public = key(private), key(public)
    return {'source_name': str(source_name or '')[:64], 'private_key': private, 'public_key': public, 'psk': key(psk),
            'address': first_ipv4(address), 'enabled': bool(enabled), 'expires_at': iso_time(expires),
            'traffic_limit_bytes': max(0, int(limit or 0)), 'quota_period': 'monthly' if monthly else '',
            'comment': ' '.join(str(comment or '').split())[:200], 'group': ' '.join(str(group or '').split())[:32],
            'telegram_id': str(telegram) if re.fullmatch(r'[1-9][0-9]{2,14}', str(telegram or '')) else '',
            'owner': ' '.join(str(owner or '').split())[:40]}


def _json(data):
    try:
        return json.loads(data.decode('utf-8-sig'))
    except (UnicodeDecodeError, ValueError):
        return None


def _sqlite(data):
    """An uploaded SQLite file, opened read-only from a private temporary copy."""
    handle, path = tempfile.mkstemp(prefix='awg31-import-', suffix='.sqlite3')
    with os.fdopen(handle, 'wb') as out:
        out.write(data)
    con = sqlite3.connect(f'file:{path}?mode=ro&immutable=1', uri=True)
    con.row_factory = sqlite3.Row
    os.unlink(path)                                        # the open connection keeps the file until it closes
    return con


def detect(data):
    if data.startswith(b'SQLite format 3\x00'):
        try:
            con = _sqlite(data)
            try:
                tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                con.close()
        except sqlite3.DatabaseError:
            return None
        if 'clients_table' in tables:
            return 'wg-easy-15'
        if 'inbounds' in tables:
            return '3x-ui'
        return None
    parsed = _json(data)
    if isinstance(parsed, dict) and isinstance(parsed.get('server'), dict) and isinstance(parsed.get('clients'), dict):
        return 'wg-easy-14'
    if isinstance(parsed, list) and all(isinstance(x, dict) and 'clientId' in x for x in parsed[:50]):
        return 'amnezia-table'
    if isinstance(parsed, dict) and parsed and all(isinstance(v, dict) and 'clientName' in v for v in list(parsed.values())[:50]):
        return 'amnezia-table'
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        return None
    if re.search(r'^\s*\[Peer\]\s*$', text, re.M):
        return 'conf'
    return None


def parse_wg_easy_15(data):
    con = _sqlite(data)
    try:
        columns = {r[1] for r in con.execute('PRAGMA table_info(clients_table)')}
        wanted = [c for c in ('name', 'ipv4_address', 'private_key', 'public_key', 'pre_shared_key', 'expires_at', 'enabled')
                  if c in columns]
        if not {'name', 'public_key'} <= set(wanted):
            raise ImportError_('wg-easy: в базе нет таблицы клиентов нужного вида')
        rows = [dict(r) for r in con.execute(f'SELECT {",".join(wanted)} FROM clients_table ORDER BY rowid LIMIT {MAX_CLIENTS + 1}')]
    finally:
        con.close()
    return [record(r.get('name'), private=r.get('private_key'), public=r.get('public_key'), psk=r.get('pre_shared_key'),
                   address=r.get('ipv4_address'), enabled=r.get('enabled', 1), expires=r.get('expires_at')) for r in rows]


def parse_wg_easy_14(data):
    parsed = _json(data)
    result = []
    for client in list(parsed['clients'].values())[:MAX_CLIENTS + 1]:
        if not isinstance(client, dict):
            continue
        result.append(record(client.get('name'), private=client.get('privateKey'), public=client.get('publicKey'),
                             psk=client.get('preSharedKey'), address=client.get('address'), enabled=client.get('enabled', True),
                             expires=client.get('expiredAt') or client.get('expiresAt') or client.get('expireAt')))
    return result


def _xui_client(c, fallback, owners, result):
    """One 3x-ui client: a key of its own, or several devices that become one owner."""
    email = re.sub(r'[<>"\'`;\\\x00-\x1f]+', '', ' '.join(str(c.get('email') or fallback).split()))[:40] or fallback[:40]
    monthly = str(c.get('trafficReset') or c.get('traffic_reset') or '') == 'monthly'
    limit = int(c.get('totalGB') or c.get('total_gb') or 0)
    expires = c.get('expiryTime') if 'expiryTime' in c else c.get('expiry_time')
    enabled = bool(c.get('enable', True))
    telegram = c.get('tgId') or c.get('tg_id') or ''
    devices = c.get('wireguardDevices') or c.get('wg_devices') or []
    if isinstance(devices, str):
        devices = _json(devices.encode()) or []
    devices = [d for d in devices if isinstance(d, dict) and key(d.get('publicKey'))]
    if devices:
        try:
            ceiling = int(c.get('wgDeviceLimit') or c.get('wg_device_limit') or 0)
        except (TypeError, ValueError):
            ceiling = 0
        owners[email] = {'name': email[:40], 'telegram_id': record('', telegram=telegram)['telegram_id'],
                         'traffic_limit_bytes': max(0, limit), 'quota_period': 'monthly' if monthly else '',
                         'expires_at': iso_time(expires), 'max_devices': max(ceiling, len(devices)) if ceiling else 0,
                         'comment': ' '.join(str(c.get('comment') or '').split())[:200]}
        for d in devices:
            result.append(record(f'{email}-{d.get("name") or d.get("id") or len(result) + 1}', private=d.get('privateKey'),
                                 public=d.get('publicKey'), psk=d.get('preSharedKey'), address=d.get('allowedIPs'),
                                 enabled=enabled and d.get('enable', True), group=c.get('group'), owner=email))
        return
    public = c.get('publicKey') or c.get('wg_public_key')
    if not key(public) and key(c.get('privateKey') or c.get('wg_private_key')) == '':
        return
    result.append(record(email, private=c.get('privateKey') or c.get('wg_private_key'), public=public,
                         psk=c.get('preSharedKey') or c.get('psk') or c.get('wg_pre_shared_key'),
                         address=c.get('allowedIPs') or c.get('wg_allowed_ips'), enabled=enabled, expires=expires, limit=limit,
                         monthly=monthly, comment=c.get('comment'), group=c.get('group') or c.get('group_name'),
                         telegram=telegram))


def parse_3x_ui(data):
    con = _sqlite(data)
    result, owners = [], {}
    try:
        for inbound in con.execute("SELECT * FROM inbounds WHERE protocol IN ('wireguard','amneziawg') ORDER BY id"):
            settings = _json(str(inbound['settings'] or '').encode()) or {}
            remark = str(inbound['remark'] or f'wg{inbound["id"]}')
            for n, c in enumerate(settings.get('clients') or [], 1):
                if isinstance(c, dict):
                    _xui_client(c, f'{remark}-{n}', owners, result)
            for n, peer in enumerate(settings.get('peers') or [], 1):          # older 3x-ui: plain xray peers
                if isinstance(peer, dict):
                    result.append(record(peer.get('email') or f'{remark}-{n}', private=peer.get('privateKey'),
                                         public=peer.get('publicKey'), psk=peer.get('preSharedKey') or peer.get('psk'),
                                         address=peer.get('allowedIPs'), enabled=bool(inbound['enable'])))
            if len(result) > MAX_CLIENTS:
                break
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'clients' in tables:
            columns = {r[1] for r in con.execute('PRAGMA table_info(clients)')}
            if 'wg_public_key' in columns or 'wg_devices' in columns:
                for row in con.execute(f'SELECT * FROM clients ORDER BY rowid LIMIT {MAX_CLIENTS + 1}'):
                    row = dict(row)
                    _xui_client(row, f'client-{row.get("id") or len(result) + 1}', owners, result)
    finally:
        con.close()
    return result, list(owners.values())


def parse_conf(text):
    """[Peer] blocks of a server configuration; the comment just above a peer (or inside it) names it."""
    result, current, label = [], None, ''
    for line in text.splitlines():
        stripped = line.strip()
        comment = re.match(r'^#+\s*(?:Client:?\s|Name:|Peer:|friendly_name\s*=)?\s*(.+?)\s*$', stripped)
        if comment and not re.match(r'^#+\s*(PublicKey|PresharedKey|AllowedIPs|Endpoint)\b', stripped):
            name = re.sub(r'\s*\([0-9a-f-]{8,}\)$', '', comment.group(1))          # wg-easy 14: "# Client: name (uuid)"
            if current is not None and not current.get('label'):
                current['label'] = name
            else:
                label = name
            continue
        if stripped.lower() == '[peer]':
            current = {'label': label}
            result.append(current)
            label = ''
            continue
        if stripped.startswith('['):
            current, label = None, ''
            continue
        if current is not None and '=' in stripped:
            field, _, value = stripped.partition('=')
            current[field.strip().lower()] = value.strip()
    return [(p.get('label', ''), p) for p in result[:MAX_CLIENTS + 1]]


def parse_amnezia_table(data):
    parsed = _json(data)
    names = {}
    if isinstance(parsed, list):
        for item in parsed:
            user = item.get('userData') if isinstance(item.get('userData'), dict) else {}
            names[str(item.get('clientId', ''))] = (user.get('clientName') or '', user.get('creationDate') or '')
    elif isinstance(parsed, dict):
        for client_id, user in parsed.items():
            names[str(client_id)] = (user.get('clientName') or '', '')
    return names


def parse(files):
    """files: [(file name, bytes)] -> {'source', 'clients', 'owners', 'warnings'}."""
    kinds = {}
    for filename, data in files:
        if len(data) > MAX_FILE:
            raise ImportError_(f'{filename}: файл больше 32 МиБ')
        kind = detect(data)
        if not kind:
            raise ImportError_(f'{filename}: не похоже ни на wg-easy, ни на 3x-ui, ни на AmneziaVPN, ни на конфигурацию WireGuard')
        kinds.setdefault(kind, []).append((filename, data))
    warnings, owners = [], []
    if 'wg-easy-15' in kinds:
        source, clients = 'wg-easy-15', parse_wg_easy_15(kinds['wg-easy-15'][0][1])
    elif 'wg-easy-14' in kinds:
        source, clients = 'wg-easy-14', parse_wg_easy_14(kinds['wg-easy-14'][0][1])
    elif '3x-ui' in kinds:
        source = '3x-ui'
        clients, owners = parse_3x_ui(kinds['3x-ui'][0][1])
    elif 'conf' in kinds:
        names = {}
        for _, data in kinds.get('amnezia-table', []):
            names.update(parse_amnezia_table(data))
        source = 'amnezia' if names or '/opt/amnezia' in kinds['conf'][0][1].decode('utf-8', 'replace') else 'conf'
        clients = []
        for n, (label, peer) in enumerate(parse_conf(kinds['conf'][0][1].decode('utf-8-sig')), 1):
            public = peer.get('publickey', '')
            name, created = names.get(public, ('', ''))
            clients.append(record(name or label or f'peer-{n}', public=public, psk=peer.get('presharedkey'),
                                  address=peer.get('allowedips'), comment=f'AmneziaVPN, {created[:40]}' if created else ''))
        if source == 'amnezia' or not names:
            warnings.append('no_private_keys')
    elif 'amnezia-table' in kinds:
        raise ImportError_('Это только список имён AmneziaVPN (clientsTable): добавьте к нему конфигурацию сервера '
                           'awg0.conf или wg0.conf из того же контейнера')
    else:
        raise ImportError_('Нет файлов для импорта')
    if len(clients) > MAX_CLIENTS:
        raise ImportError_(f'Слишком много клиентов: больше {MAX_CLIENTS} за один раз')
    if any(not c['private_key'] for c in clients) and 'no_private_keys' not in warnings:
        warnings.append('some_without_keys')
    seen, unique = set(), []
    for c in clients:                                   # 3x-ui may list a client both in an inbound and in its table
        mark = c['public_key'] or c['private_key'] or id(c)
        if mark in seen:
            continue
        seen.add(mark)
        unique.append(c)
    return {'source': source, 'clients': unique_names(unique), 'owners': owners, 'warnings': warnings}
