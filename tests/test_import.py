"""0.21: clients from wg-easy, 3x-ui, AmneziaVPN and plain WireGuard configurations."""
import base64
import json
import secrets
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import awg31import as imp  # noqa: E402

from test_owners import farm, ctl, GIB  # noqa: E402,F401  (pytest fixture)
from test_workflows import ui, token  # noqa: E402,F401  (pytest fixture)


def k():
    return base64.b64encode(secrets.token_bytes(32)).decode()


PAIRS = {}


def pair():
    private, public = k(), k()
    PAIRS[private] = public
    return private, public


def sqlite_bytes(tmp_path, name, statements):
    path = tmp_path / name
    with sqlite3.connect(path) as con:
        for statement, *args in statements:
            con.execute(statement, *args)
    return path.read_bytes()


# ------------------------------------------------------------------ parsers
def test_wg_easy_15(tmp_path):
    p1, u1 = pair()
    data = sqlite_bytes(tmp_path, 'wg-easy.db', [
        ('CREATE TABLE clients_table (id INTEGER PRIMARY KEY, name TEXT, ipv4_address TEXT, ipv6_address TEXT, private_key TEXT,'
         ' public_key TEXT, pre_shared_key TEXT, expires_at TEXT, enabled INTEGER)',),
        ('INSERT INTO clients_table VALUES (1,?,?,?,?,?,?,?,1)', ('Мама телефон', '10.8.0.2', 'fdcc::2', p1, u1, k(), '2027-03-01')),
        ('INSERT INTO clients_table VALUES (2,?,?,?,?,?,?,?,0)', ('laptop', '10.8.0.3', 'fdcc::3', None, k(), None, None)),
    ])
    found = imp.parse([('wg-easy.db', data)])
    assert found['source'] == 'wg-easy-15' and [c['name'] for c in found['clients']] == ['Mama-telefon', 'laptop']
    mom, laptop = found['clients']
    assert mom['private_key'] == p1 and mom['public_key'] == u1 and mom['address'] == '10.8.0.2'
    assert mom['expires_at'] == '2027-03-01T00:00:00+00:00' and mom['enabled'] and not laptop['enabled']
    assert laptop['private_key'] == '' and found['warnings'] == ['some_without_keys']


def test_wg_easy_14():
    p1, u1 = pair()
    data = json.dumps({'server': {'privateKey': k(), 'publicKey': k(), 'address': '10.8.0.1'},
                       'clients': {'a1': {'name': 'phone', 'address': '10.8.0.2', 'privateKey': p1, 'publicKey': u1,
                                          'preSharedKey': k(), 'enabled': True, 'createdAt': '2024-01-01'},
                                   'a2': {'name': 'phone', 'address': '10.8.0.3', 'privateKey': k(), 'publicKey': k(), 'enabled': False}}})
    found = imp.parse([('wg0.json', data.encode())])
    assert found['source'] == 'wg-easy-14' and [c['name'] for c in found['clients']] == ['phone', 'phone-2']


def test_3x_ui_inbounds_clients_and_devices(tmp_path):
    d1, d2, single = pair(), pair(), pair()
    amnezia = {'server': {'privateKey': k()}, 'clients': [
        {'email': 'anna@example.com', 'enable': True, 'totalGB': 50 * GIB, 'expiryTime': 1798675200000, 'tgId': 700000001,
         'trafficReset': 'monthly', 'wgDeviceLimit': 3,
         'wireguardDevices': [{'id': 'x', 'name': 'iphone', 'enable': True, 'privateKey': d1[0], 'publicKey': d1[1], 'allowedIPs': ['10.0.0.2/32']},
                              {'id': 'y', 'name': 'mac', 'enable': False, 'privateKey': d2[0], 'publicKey': d2[1], 'allowedIPs': ['10.0.0.3/32']}]},
        {'email': 'bob', 'enable': True, 'privateKey': single[0], 'publicKey': single[1], 'preSharedKey': k(),
         'allowedIPs': ['10.0.0.4/32'], 'totalGB': 0, 'expiryTime': -86400000, 'comment': 'старый ноутбук', 'group': 'work'}]}
    old_peer = pair()
    wireguard = {'secretKey': k(), 'peers': [{'privateKey': old_peer[0], 'publicKey': old_peer[1], 'allowedIPs': ['10.1.0.2/32']}]}
    data = sqlite_bytes(tmp_path, 'x-ui.db', [
        ('CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, protocol TEXT, settings TEXT, enable INTEGER)',),
        ('INSERT INTO inbounds VALUES (1, ?, ?, ?, 1)', ('AWG home', 'amneziawg', json.dumps(amnezia))),
        ('INSERT INTO inbounds VALUES (2, ?, ?, ?, 1)', ('wg', 'wireguard', json.dumps(wireguard))),
        ('INSERT INTO inbounds VALUES (3, ?, ?, ?, 1)', ('vless', 'vless', '{"clients":[{"email":"x"}]}')),
        ('CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, wg_private_key TEXT, wg_public_key TEXT, wg_pre_shared_key TEXT,'
         ' wg_allowed_ips TEXT, wg_devices TEXT, enable INTEGER, total_gb INTEGER, expiry_time INTEGER, tg_id INTEGER)',),
        ('INSERT INTO clients VALUES (1, ?, ?, ?, NULL, ?, NULL, 1, 0, 0, 0)', ('bob', single[0], single[1], '10.0.0.4/32')),
    ])
    found = imp.parse([('x-ui.db', data)])
    names = [c['name'] for c in found['clients']]
    assert found['source'] == '3x-ui' and names == ['anna-example-com-iphone', 'anna-example-com-mac', 'bob', 'wg-1']
    iphone, mac, bob, wg = found['clients']
    assert iphone['owner'] == 'anna@example.com' and iphone['enabled'] and not mac['enabled']
    assert iphone['traffic_limit_bytes'] == 0                                # the limit belongs to the owner
    assert found['owners'] == [{'name': 'anna@example.com', 'telegram_id': '700000001', 'traffic_limit_bytes': 50 * GIB,
                                'quota_period': 'monthly', 'expires_at': '2026-12-31T00:00:00+00:00', 'max_devices': 3, 'comment': ''}]
    assert bob['expires_at'] == '' and bob['comment'] == 'старый ноутбук' and bob['group'] == 'work' and bob['address'] == '10.0.0.4'
    assert wg['private_key'] == old_peer[0]                                 # bob is listed once, though stored twice


def test_amneziavpn_needs_both_files_and_has_no_private_keys():
    a, b = k(), k()
    conf = f"""[Interface]
PrivateKey = {k()}
Address = 10.8.1.0/24
ListenPort = 34567
Jc = 4

[Peer]
PublicKey = {a}
PresharedKey = {k()}
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = {b}
PresharedKey = {k()}
AllowedIPs = 10.8.1.3/32
"""
    table = json.dumps([{'clientId': a, 'userData': {'clientName': 'Папа', 'creationDate': 'Mon Jan 6 2025'}}])
    with pytest.raises(ValueError, match='clientsTable'):
        imp.parse([('clientsTable', table.encode())])
    found = imp.parse([('awg0.conf', conf.encode()), ('clientsTable', table.encode())])
    assert found['source'] == 'amnezia' and [c['name'] for c in found['clients']] == ['Papa', 'peer-2']
    assert found['warnings'] == ['no_private_keys'] and found['clients'][0]['comment'] == 'AmneziaVPN, Mon Jan 6 2025'
    old_format = json.dumps({a: {'clientName': 'Дочь'}})
    assert imp.parse([('awg0.conf', conf.encode()), ('clientsTable', old_format.encode())])['clients'][0]['name'] == 'Doch'


def test_plain_conf_names_from_comments():
    conf = f"""[Interface]
PrivateKey = {k()}
# Client: Mom (6f1c2b9e-1111-2222-3333-444455556666)
[Peer]
PublicKey = {k()}
AllowedIPs = 10.9.0.2/32
### Client laptop
[Peer]
PublicKey = {k()}
AllowedIPs = 10.9.0.3/32, fd00::3/128
"""
    found = imp.parse([('wg0.conf', conf.encode())])
    assert found['source'] == 'conf' and [c['name'] for c in found['clients']] == ['Mom', 'laptop']
    assert found['clients'][1]['address'] == '10.9.0.3'


def test_garbage_is_refused(tmp_path):
    for data in (b'hello', b'{"a": 1}', b'SQLite format 3\x00broken', sqlite_bytes(tmp_path, 'other.db', [('CREATE TABLE x (a)',)])):
        with pytest.raises(ValueError):
            imp.parse([('file', data)])
    with pytest.raises(ValueError, match='32'):
        imp.parse([('big', b'x' * (imp.MAX_FILE + 1))])
    assert imp.clean_name('???', 'client-1') == 'client-1' and imp.clean_name('a' * 40) == 'a' * 32
    assert imp.key('not a key') == '' and imp.key(base64.b64encode(bytes(32)).decode()) == ''


# ------------------------------------------------------------------ manager and controller
def test_import_keeps_keys_addresses_and_makes_owners(farm, monkeypatch):
    monkeypatch.setattr(ctl, 'pubkey', lambda private: PAIRS.get(private) or private.replace('private', 'public'))
    d1, d2, single, wrong = pair(), pair(), pair(), pair()
    clients = [imp.record('anna-iphone', private=d1[0], public=d1[1], address='10.77.10.7', owner='anna@example.com'),
               imp.record('anna-mac', private=d2[0], public=d2[1], address='10.99.0.3', owner='anna@example.com'),
               imp.record('bob', private=single[0], public=single[1], address='10.77.10.7', telegram='700000010', limit=GIB,
                          expires='2020-01-01'),
               imp.record('mismatch', private=wrong[0], public=k()),
               imp.record('no-key', public=k(), enabled=False)]
    imp.unique_names(clients)
    owners = [{'name': 'anna@example.com', 'telegram_id': '700000001', 'traffic_limit_bytes': 50 * GIB, 'quota_period': 'monthly',
               'expires_at': '', 'max_devices': 3, 'comment': ''}]
    result = farm.call('clients-import', {'interface': 'awg0', 'source': '3x-ui', 'clients': clients, 'owners': owners})
    created = {c['name']: c for c in result['created']}
    assert set(created) == {'anna-iphone', 'anna-mac', 'bob', 'no-key'} and result['skipped'] == {'mismatch': 'key_mismatch'}
    assert result['owners_created'] == 2
    iphone = farm.client('awg0', 'anna-iphone')
    assert iphone['private_key'] == d1[0] and iphone['ip'] == '10.77.10.7' and created['anna-iphone']['kept_key']
    assert farm.client('awg0', 'anna-mac')['ip'] != '10.99.0.3'             # outside the subnet: a free address instead
    assert farm.client('awg0', 'bob')['ip'] != '10.77.10.7'                  # taken by now
    bob = farm.client('awg0', 'bob')
    assert (bob['enabled'], bob['disabled_reason'], bob['traffic_limit_bytes']) == (0, 'expired', GIB)
    assert farm.client('awg0', 'no-key')['enabled'] == 0 and not created['no-key']['kept_key']
    owners = {o['name']: o for o in farm.call('owners')['owners']}
    assert owners['anna@example.com']['device_count'] == 2 and owners['anna@example.com']['quota_period'] == 'monthly'
    assert iphone['telegram_id'] == '700000001' and owners['Telegram 700000010']['device_count'] == 1
    assert any(e['event'] == 'clients_imported' and e['target'] == 'awg0: 4 clients from 3x-ui' for e in farm.events())
    # The same file again: keys already there are skipped, names never clash.
    again = farm.call('clients-import', {'interface': 'awg0', 'source': '3x-ui', 'clients': clients[:1], 'owners': owners and []})
    assert again['skipped'] == {'anna-iphone': 'key_exists'}
    fresh = farm.call('clients-import', {'interface': 'awg0', 'source': 'conf', 'clients': [imp.record('x', public=k()) | {'name': 'bob'}],
                                         'keep_keys': False})
    assert fresh['created'][0]['name'] == 'bob-2'


def test_import_options_and_limits(farm, monkeypatch):
    monkeypatch.setattr(ctl, 'pubkey', lambda private: PAIRS.get(private) or private.replace('private', 'public'))
    one = pair()
    clients = imp.unique_names([imp.record('kept', private=one[0], public=one[1], address='10.77.10.9', owner='o', telegram='700000011')])
    result = farm.call('clients-import', {'interface': 'awg1', 'source': 'wg-easy-14', 'clients': clients, 'keep_keys': False,
                                          'keep_addresses': False, 'create_owners': False,
                                          'owners': [{'name': 'o', 'telegram_id': '', 'traffic_limit_bytes': 0, 'quota_period': '',
                                                      'expires_at': '', 'max_devices': 0, 'comment': ''}]})
    row = farm.client('awg1', 'kept')
    assert row['private_key'] != one[0] and row['ip'] == '10.77.11.2' and row['owner_id'] == '' and row['telegram_id'] == ''
    assert result['owners_created'] == 0 and farm.call('owners')['owners'] == []
    for bad in ({'source': 'unknown', 'clients': clients}, {'source': 'conf', 'clients': []},
                {'source': 'conf', 'clients': [{'name': '../x'}]}, {'source': 'conf', 'clients': clients * 501}):
        with pytest.raises(ValueError):
            farm.call('clients-import', {'interface': 'awg0', **bad})


# ------------------------------------------------------------------ panel
def test_import_page_preview_and_apply(ui, tmp_path):
    app, client, calls = ui
    original = app.ctl

    def fake(op, data=None):
        if op == 'clients-import':
            calls.append((op, dict(data)))
            return {'ok': True, 'created': [{'name': c['name'], 'ip': '10.77.10.9', 'kept_key': bool(c['private_key'])} for c in data['clients']],
                    'skipped': {'old': 'key_exists'}, 'owners_created': 1}
        return original(op, data)
    app.ctl = fake
    tab = client.get('/maintenance?tab=import')
    assert tab.status_code == 200 and 'enctype="multipart/form-data"' in tab.text and '/etc/x-ui/x-ui.db' in tab.text
    p1, u1 = pair()
    data = json.dumps({'server': {}, 'clients': {'a': {'name': 'Мама', 'address': '10.8.0.2', 'privateKey': p1, 'publicKey': u1, 'enabled': True},
                                                 'b': {'name': 'papa', 'address': '10.8.0.3', 'privateKey': k(), 'publicKey': k(), 'enabled': True}}})
    preview = client.post('/maintenance/import', data={'csrf': token(tab), 'interface': 'awg1', 'keep_keys': '1', 'create_owners': '1'},
                          files=[('files', ('wg0.json', data.encode(), 'application/json'))])
    assert preview.status_code == 200 and preview.headers['cache-control'] == 'no-store'
    assert 'Найдено клиентов: 2' in preview.text and '<strong>Mama</strong><small class="muted">Мама</small>' in preview.text
    assert 'name="pick" value="1" checked' in preview.text and 'wg-easy 14' in preview.text
    records = preview.text.split('<textarea name="records" hidden>')[1].split('</textarea>')[0]
    import html
    done = client.post('/maintenance/import', data={'csrf': token(preview), 'interface': 'awg1', 'keep_keys': '1',
                                                     'records': html.unescape(records), 'pick': ['1']})
    sent = [d for op, d in calls if op == 'clients-import'][-1]
    assert sent['interface'] == 'awg1' and [c['name'] for c in sent['clients']] == ['papa'] and sent['source'] == 'wg-easy-14'
    assert sent['keep_keys'] is True and sent['keep_addresses'] is False and sent['create_owners'] is False
    assert 'Перенесено клиентов на awg1: 1' in done.text and 'клиент с этим ключом уже есть' in done.text
    assert 'href="/servers/awg1/clients/papa"' in done.text
    bad = client.post('/maintenance/import', data={'csrf': token(tab), 'interface': 'awg1'},
                      files=[('files', ('x.txt', b'nothing here', 'text/plain'))])
    assert 'не похоже' in bad.text
    assert client.post('/maintenance/import', data={'csrf': token(tab), 'interface': 'awg9'},
                       files=[('files', ('wg0.json', data.encode(), 'application/json'))]).status_code == 422


def test_wiring_for_import():
    from test_telegram_bot import sudo_list
    assert 'clients-import' in sudo_list('AWG31_SUDO_COMMANDS') and 'clients-import' not in sudo_list('AWG31_BOT_SUDO_COMMANDS')
    sudoers = (ROOT / 'scripts/sudoers.sh').read_text()
    assert 'import-batch' not in sudoers
    for name in ('scripts/setup-wizard.sh', 'scripts/upgrade-core.sh', 'scripts/upgrade-ui.sh'):
        assert 'awg31import.py' in (ROOT / name).read_text(), name
    nginx = (ROOT / 'scripts/setup-nginx.sh').read_text()
    assert 'location = /maintenance/import' in nginx and 'client_max_body_size 64m' in nginx and 'proxy_add_import' in nginx
