"""0.20: owners with several devices on any server and shared limits (traffic, term, number of devices)."""
import io
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from test_peer_routes_i import profile

ROOT = Path(__file__).resolve().parents[1]
ctl = SourceFileLoader('awg31_owners_ctl', str(ROOT / 'src/awg31ctl')).load_module()


@pytest.fixture
def farm(tmp_path, monkeypatch):
    """Two servers with real databases; awg31mgr talks to the controller in-process."""
    monkeypatch.setenv('AWG31_ROOT', str(tmp_path))
    monkeypatch.setenv('AWG31_AUDIT', str(tmp_path / 'audit.jsonl'))
    monkeypatch.setenv('AWG31_LOGGING', str(tmp_path / 'logging.json'))
    monkeypatch.setenv('AWG31_PEER_BACKUPS', str(tmp_path / 'peer-backups'))
    mgr = SourceFileLoader('awg31_owners_mgr', str(ROOT / 'src/awg31mgr')).load_module()
    admin = mgr.load_source('awg31admin_owners', ROOT / 'src/awg31admin.py')
    monkeypatch.setattr(mgr, 'load_source', lambda *a: admin)
    monkeypatch.setattr(mgr.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(ctl.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(ctl, 'LOCK', tmp_path / 'control.lock')
    applied = []
    keys = iter(range(10000))
    monkeypatch.setattr(ctl, 'apply', lambda cfg, con, **k: applied.append(ctl.IFACE))
    monkeypatch.setattr(ctl, 'keygen', lambda: f'private-{next(keys)}')
    monkeypatch.setattr(ctl, 'pubkey', lambda private: private.replace('private', 'public'))
    monkeypatch.setattr(ctl, 'pskgen', lambda: 'psk')
    stats = {}
    monkeypatch.setattr(ctl, 'live_stats', lambda: stats)
    monkeypatch.setattr(ctl.subprocess, 'run', lambda *a, **k: types.SimpleNamespace(returncode=1, stdout='', stderr=''))
    servers = {'awg0': tmp_path / 'state.sqlite3', 'awg1': tmp_path / 'servers' / 'awg1.sqlite3'}
    (tmp_path / 'servers').mkdir()
    for n, (iface, path) in enumerate(servers.items()):
        monkeypatch.setattr(ctl, 'DB', path)
        con = ctl.get_conn(True)
        ctl.put_settings(con, {**profile(), 'subnet': f'10.77.{10 + n}.0/24', 'server_ip': f'10.77.{10 + n}.1'})
        con.commit(); con.close()
    monkeypatch.setattr(mgr, 'interfaces', lambda: list(servers))
    monkeypatch.setattr(mgr, 'exists', lambda iface: iface in servers)
    monkeypatch.setattr(mgr, 'db_path', lambda iface: servers[iface])

    def child(iface, command, payload):
        monkeypatch.setattr(ctl, 'DB', servers[iface])
        monkeypatch.setattr(ctl, 'IFACE', iface)
        monkeypatch.setattr(sys, 'argv', ['awg31ctl', command])
        monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(payload)))
        out = io.StringIO()
        monkeypatch.setattr(sys, 'stdout', out)
        try:
            ctl.main()
        finally:
            monkeypatch.setattr(sys, 'stdout', sys.__stdout__)
        return json.loads(out.getvalue())
    monkeypatch.setattr(mgr, 'child', child)

    def call(op, data=None):
        monkeypatch.setattr(sys, 'argv', ['awg31mgr', op])
        monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(data or {})))
        return mgr.main()

    def client(iface, name):
        import sqlite3
        with sqlite3.connect(servers[iface]) as con:
            con.row_factory = sqlite3.Row
            return dict(con.execute('SELECT * FROM clients WHERE name=?', (name,)).fetchone())

    def traffic(iface, name, amount):
        row = client(iface, name)
        stats[row['public_key']] = {'received': row['last_rx'] + amount, 'sent': row['last_tx'], 'handshake': 1}

    def events():
        path = tmp_path / 'audit.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    return types.SimpleNamespace(call=call, client=client, traffic=traffic, events=events, admin=admin, mgr=mgr, child=child)


GIB = 1024 ** 3


def test_owner_has_devices_on_two_servers_and_a_shared_quota(farm):
    anna = farm.call('owner-set', {'name': 'Анна', 'telegram_id': '700000001', 'traffic_limit_bytes': 3 * GIB,
                                   'max_devices': 3})['owner']
    assert anna['id'].startswith('o') and anna['device_count'] == 0 and anna['blocked'] == ''
    farm.call('add', {'interface': 'awg0', 'name': 'anna-phone', 'owner_id': anna['id']})
    farm.call('add', {'interface': 'awg1', 'name': 'anna-laptop', 'owner_id': anna['id']})
    farm.call('add', {'interface': 'awg0', 'name': 'bob'})
    assert farm.client('awg1', 'anna-laptop')['telegram_id'] == '700000001'         # mirrored from the owner
    listed = {o['name']: o for o in farm.call('owners')['owners']}
    assert [d['name'] for d in listed['Анна']['devices']] == ['anna-phone', 'anna-laptop']
    # 2 GiB on one server, 1.5 GiB on the other: together over the 3 GiB of the owner.
    farm.traffic('awg0', 'anna-phone', 2 * GIB)
    farm.call('sample-all')
    assert farm.client('awg0', 'anna-phone')['enabled'] == 1
    farm.traffic('awg1', 'anna-laptop', 3 * GIB // 2)
    result = farm.call('sample-all')
    assert result['owners'][0]['to'] == 'quota'
    for iface, name in (('awg0', 'anna-phone'), ('awg1', 'anna-laptop')):
        row = farm.client(iface, name)
        assert (row['enabled'], row['disabled_reason']) == (0, 'owner_quota')
    assert farm.client('awg0', 'bob')['enabled'] == 1
    assert any(e['event'] == 'owner_blocked' and 'quota, 2 devices' in e['target'] for e in farm.events())
    with pytest.raises(ValueError, match='общий лимит'):
        farm.call('enable', {'interface': 'awg0', 'name': 'anna-phone'})
    skipped = farm.call('client-batch', {'interface': 'awg1', 'names': ['anna-laptop'], 'action': 'enable'})['skipped']
    assert skipped == {'anna-laptop': 'owner'}
    # More traffic for the owner: the devices come back at once, not at the next sample.
    farm.call('owner-set', {'id': anna['id'], 'traffic_limit_bytes': 10 * GIB})
    assert farm.client('awg0', 'anna-phone')['enabled'] == 1 and farm.client('awg1', 'anna-laptop')['enabled'] == 1


def test_device_limit_and_self_service_from_the_bot(farm):
    owner = farm.call('owner-set', {'name': 'Kid', 'telegram_id': '700000002', 'max_devices': 2, 'self_add': '1',
                                    'home_server': 'awg1'})['owner']
    made = farm.call('owner-device-add', {'telegram_id': '700000002', 'kind': 'phone'})
    assert made['interface'] == 'awg1' and made['name'] == 'kid-phone' and 'PrivateKey' in made['config']
    row = farm.client('awg1', 'kid-phone')
    assert row['owner_id'] == owner['id'] and row['owner_export'] == 1 and row['telegram_id'] == '700000002'
    assert farm.call('owner-device-add', {'telegram_id': '700000002', 'kind': 'phone'})['name'] == 'kid-phone-2'
    with pytest.raises(ValueError, match='2 из 2'):
        farm.call('owner-device-add', {'telegram_id': '700000002', 'kind': 'tablet'})
    with pytest.raises(ValueError, match='2 из 2'):
        farm.call('add', {'interface': 'awg0', 'name': 'kid-pc', 'owner_id': owner['id']})
    farm.call('add', {'interface': 'awg0', 'name': 'spare'})
    with pytest.raises(ValueError, match='2 из 2'):
        farm.call('client-policy', {'interface': 'awg0', 'name': 'spare', 'owner_id': owner['id']})
    farm.call('client-policy', {'interface': 'awg1', 'name': 'kid-phone', 'comment': 'still mine', 'owner_id': owner['id']})
    with pytest.raises(ValueError, match='уже 2'):
        farm.call('owner-set', {'id': owner['id'], 'max_devices': 1})
    farm.call('owner-set', {'id': owner['id'], 'self_add': ''})
    with pytest.raises(ValueError, match='не разрешено'):
        farm.call('owner-device-add', {'telegram_id': '700000002', 'kind': 'phone'})
    with pytest.raises(ValueError):
        farm.call('owner-device-add', {'telegram_id': '700000099', 'kind': 'phone'})
    with pytest.raises(ValueError):
        farm.call('owner-device-add', {'telegram_id': '700000002', 'kind': 'toaster'})


def test_shared_term_and_monthly_reset(farm, monkeypatch):
    past = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
    owner = farm.call('owner-set', {'name': 'Gone', 'expires_at': past})['owner']
    assert owner['blocked'] == 'expired'
    farm.call('add', {'interface': 'awg0', 'name': 'gone-1', 'owner_id': owner['id']})
    farm.call('sample-all')
    assert farm.client('awg0', 'gone-1')['disabled_reason'] == 'owner_expired'
    farm.call('owner-set', {'id': owner['id'], 'expires_at': '', 'traffic_limit_bytes': GIB, 'quota_period': 'monthly'})
    assert farm.client('awg0', 'gone-1')['enabled'] == 1
    farm.traffic('awg0', 'gone-1', 2 * GIB)
    farm.call('sample-all')
    assert farm.client('awg0', 'gone-1')['disabled_reason'] == 'owner_quota'
    # Next month: the owner's counter starts again and the devices return.
    next_month = datetime.now(timezone.utc).replace(day=28) + timedelta(days=5)
    changed = farm.admin.owners_sample(farm.mgr, {}, now=next_month)
    assert changed['changed'][0]['to'] == '' and changed['blocked'] == {}
    farm.admin._sync_servers(farm.mgr, {'blocked': changed['blocked']})
    assert farm.client('awg0', 'gone-1')['enabled'] == 1


def test_own_limits_still_apply_when_the_owner_is_free(farm):
    owner = farm.call('owner-set', {'name': 'Both', 'traffic_limit_bytes': GIB})['owner']
    farm.call('add', {'interface': 'awg0', 'name': 'both-1', 'owner_id': owner['id'], 'traffic_limit_bytes': 512 * 1024 ** 2})
    farm.traffic('awg0', 'both-1', GIB)
    farm.call('sample-all')
    assert farm.client('awg0', 'both-1')['disabled_reason'] in ('quota', 'owner_quota')
    farm.call('owner-set', {'id': owner['id'], 'traffic_limit_bytes': 0})
    row = farm.client('awg0', 'both-1')
    assert (row['enabled'], row['disabled_reason']) == (0, 'quota')                 # its own limit is still spent


def test_clients_with_a_telegram_id_become_owners(farm):
    farm.child('awg0', 'add', {'name': 'old-a', 'telegram_id': '700000003', 'owner_export': True})
    farm.child('awg1', 'add', {'name': 'old-b', 'telegram_id': '700000003'})
    farm.child('awg1', 'add', {'name': 'old-c', 'telegram_id': '700000004'})
    owners = {o['name']: o for o in farm.call('owners')['owners']}
    assert set(owners) == {'Telegram 700000003', 'Telegram 700000004'}
    assert [d['name'] for d in owners['Telegram 700000003']['devices']] == ['old-a', 'old-b']
    assert farm.client('awg0', 'old-a')['owner_export'] == 1                        # nothing else changes
    # The bot sets a Telegram ID on a client: that person's owner is found, or made.
    farm.call('add', {'interface': 'awg0', 'name': 'new-d'})
    farm.call('client-policy', {'interface': 'awg0', 'name': 'new-d', 'telegram_id': '700000004'})
    assert farm.client('awg0', 'new-d')['owner_id'] == owners['Telegram 700000004']['id']
    farm.call('client-policy', {'interface': 'awg0', 'name': 'new-d', 'telegram_id': '700000005'})
    assert farm.call('owners', {'telegram_id': '700000005'})['owners'][0]['device_count'] == 1
    farm.call('client-policy', {'interface': 'awg0', 'name': 'new-d', 'telegram_id': '0'})
    assert (farm.client('awg0', 'new-d')['owner_id'], farm.client('awg0', 'new-d')['telegram_id']) == ('', '')


def test_changing_the_owners_telegram_moves_devices_and_drops_the_export(farm):
    owner = farm.call('owner-set', {'name': 'Pat', 'telegram_id': '700000006'})['owner']
    farm.call('add', {'interface': 'awg1', 'name': 'pat-1', 'owner_id': owner['id'], 'owner_export': True})
    assert farm.client('awg1', 'pat-1')['owner_export'] == 1
    farm.call('owner-set', {'id': owner['id'], 'telegram_id': '700000007'})
    row = farm.client('awg1', 'pat-1')
    assert (row['telegram_id'], row['owner_export']) == ('700000007', 0)
    with pytest.raises(ValueError, match='уже у владельца'):
        farm.call('owner-set', {'name': 'Other', 'telegram_id': '700000007'})
    with pytest.raises(ValueError, match='таким именем'):
        farm.call('owner-set', {'name': 'pat'})
    farm.call('owner-delete', {'id': owner['id']})
    row = farm.client('awg1', 'pat-1')
    assert (row['owner_id'], row['telegram_id'], row['enabled']) == ('', '', 1)
    assert farm.call('owners')['owners'] == []


def test_bulk_owner_and_move_keep_the_owner(farm):
    owner = farm.call('owner-set', {'name': 'Team', 'max_devices': 2})['owner']
    for name in ('t1', 't2', 't3'):
        farm.call('add', {'interface': 'awg0', 'name': name})
    with pytest.raises(ValueError, match='0 из 2'):
        farm.call('client-batch', {'interface': 'awg0', 'names': ['t1', 't2', 't3'], 'action': 'owner', 'owner_id': owner['id']})
    done = farm.call('client-batch', {'interface': 'awg0', 'names': ['t1', 't2'], 'action': 'owner', 'owner_id': owner['id']})
    assert done['changed'] == ['t1', 't2']
    farm.call('client-move', {'interface': 'awg0', 'name': 't1', 'target': 'awg1'})
    assert farm.client('awg1', 't1')['owner_id'] == owner['id']
    assert farm.call('owners')['owners'][0]['device_count'] == 2


def test_invitation_makes_the_person_an_owner(farm):
    farm.call('add', {'interface': 'awg0', 'name': 'guest'})
    code = farm.call('client-invite', {'interface': 'awg0', 'name': 'guest', 'days': 7})['code']
    assert farm.call('invite-redeem', {'interface': 'awg0', 'code': code, 'telegram_id': '700000008',
                                       'owner_name': 'Мария @maria'})['found']
    owners = farm.call('owners')['owners']
    assert owners[0]['name'] == 'Мария @maria' and owners[0]['telegram_id'] == '700000008'
    assert farm.client('awg0', 'guest')['owner_id'] == owners[0]['id']


def test_owner_fields_are_validated(farm):
    for bad in ({'name': ''}, {'name': 'x' * 41}, {'name': 'a<b'}, {'name': 'ok', 'telegram_id': '@anna'},
                {'name': 'ok', 'max_devices': 101}, {'name': 'ok', 'expires_at': '31/12/2026'},
                {'name': 'ok', 'quota_period': 'weekly'}, {'name': 'ok', 'home_server': 'awg7'},
                {'id': 'o0000000000', 'name': 'missing'}, {'id': '../x', 'name': 'bad'}):
        with pytest.raises(ValueError):
            farm.call('owner-set', bad)
    made = farm.call('owner-set', {'name': '  Ольга   Петрова ', 'expires_at': '31.12.2030'})['owner']
    assert made['name'] == 'Ольга Петрова' and made['expires_at'].startswith('2030-12-31T23:59:59')


def test_wiring():
    sudoers = (ROOT / 'scripts/sudoers.sh').read_text()
    from test_telegram_bot import sudo_list
    panel, bot = sudo_list('AWG31_SUDO_COMMANDS'), sudo_list('AWG31_BOT_SUDO_COMMANDS')
    assert {'owners', 'owner-set', 'owner-delete', 'owner-device-add'} <= panel
    assert {'owners', 'owner-device-add'} <= bot and not {'owner-set', 'owner-delete'} & bot
    assert 'owner-sync' not in panel | bot and 'owner-sync' not in sudoers
    assert "'owner_id'" in ctl.MOVE_KEEP.__repr__()


# ------------------------------------------------------------------ bot
from test_telegram_bot import FakeApi, FakeController, bot_module, press, message, ADMIN, TOKEN  # noqa: E402

KID = 700000002


@pytest.fixture
def obot(tmp_path):
    api, controller, now = FakeApi(), FakeController(), [1_780_000_000.0]
    controller.owner_rows = [{'id': 'o0123456789', 'name': 'Kid', 'telegram_id': str(KID), 'device_count': 1, 'max_devices': 3,
                              'self_add': True, 'blocked': '', 'used_bytes': 5 * GIB, 'traffic_limit_bytes': 20 * GIB,
                              'quota_period': 'monthly', 'expires_at': '2027-01-31T23:59:59+00:00'}]
    controller.clients['awg0']['kid-phone'] = {**controller.new_client('10.8.0.7'), 'telegram_id': str(KID), 'owner_export': True}
    config = {'token': TOKEN, 'admins': {ADMIN}, 'lang': 'ru', 'api_base': 'https://api.telegram.org',
              'notify': {'server': True, 'clients': True, 'security': True, 'backups': True}}
    bot = bot_module.Bot(config, api=api, controller=controller, state_path=tmp_path / 'state.json', clock=lambda: now[0])
    return bot, api, controller, now


def kid_texts(api):
    return [p['text'] for m, p in api.calls if m in ('sendMessage', 'editMessageText') and p.get('chat_id') == KID]


def test_owner_sees_the_shared_balance_and_adds_a_device(obot):
    bot, api, controller, now = obot
    bot.handle_update(message('/start', user=KID))
    screen = kid_texts(api)[-1]
    assert 'Общий трафик: 5.0 GiB из 20.0 GiB (в месяц)' in screen and 'устройств 1 / 3' in screen and '2027-01-31' in screen
    assert 'ma' in api.buttons()
    now[0] += 5
    bot.handle_update(press('ma', user=KID))
    assert {'mk:phone', 'mk:router'} <= set(api.buttons())
    now[0] += 5
    controller.allow_device = True
    bot.handle_update(press('mk:laptop', user=KID))
    assert ('owner-device-add', {'telegram_id': str(KID), 'kind': 'laptop'}) in controller.log
    assert any('kid-laptop' in t and 'добавлено' in t for t in kid_texts(api))
    assert [f[2] for f in api.files if f[1] == KID] == ['kid-laptop.conf', 'kid-laptop-qr.png']
    admin = [p['text'] for m, p in api.calls if m == 'sendMessage' and p.get('chat_id') == ADMIN]
    assert any('добавил(а) устройство' in t and 'kid-laptop' in t for t in admin)


def test_no_button_when_full_blocked_or_not_allowed(obot):
    bot, api, controller, now = obot
    for change in ({'device_count': 3}, {'blocked': 'quota'}, {'self_add': False}, {'max_devices': 0}):
        controller.owner_rows[0] = {**controller.owner_rows[0], 'device_count': 1, 'blocked': '', 'self_add': True, 'max_devices': 3, **change}
        api.calls.clear(); now[0] += 5
        bot.owners_at = None
        bot.handle_update(message('/start', user=KID))
        assert 'ma' not in api.buttons(), change
        now[0] += 5
        bot.handle_update(press('mk:phone', user=KID))                       # a forged button changes nothing either
    controller.owner_rows[0] = {**controller.owner_rows[0], 'blocked': 'quota', 'max_devices': 3}
    now[0] += 5
    bot.handle_update(message('/start', user=KID))
    assert 'Общий трафик исчерпан' in kid_texts(api)[-1]
    assert 'owner-device-add' not in controller.commands()


def test_owner_with_no_device_yet_can_start(obot):
    bot, api, controller, now = obot
    del controller.clients['awg0']['kid-phone']
    controller.owner_rows[0]['device_count'] = 0
    bot.handle_update(message('/start', user=KID))
    assert 'ma' in api.buttons()
    controller.owner_rows[0]['self_add'] = False
    bot.owners_at = None; api.calls.clear(); now[0] += 5
    bot.handle_update(message('/start', user=KID))
    assert kid_texts(api) == []                                            # a stranger again: no answer


def test_owner_limit_events_reach_admins_and_the_owner(obot):
    bot, api, controller, now = obot
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'owner_blocked', 'target': 'Kid (o0123456789): quota, 2 devices'})
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'owner_unblocked', 'target': 'Kid (o0123456789): quota, 2 devices'})
    bot.state['audit_seen'] = ''
    bot.check_audit()
    admin = [p['text'] for m, p in api.calls if m == 'sendMessage' and p.get('chat_id') == ADMIN]
    assert any('Владелец «Kid»: израсходован общий трафик, отключено устройств: 2' in t for t in admin)
    assert any('включено устройств: 2' in t for t in admin)
    assert any('отключён на всех устройствах' in t for t in kid_texts(api)) and any('снова работает' in t for t in kid_texts(api))


# ------------------------------------------------------------------ panel
from test_workflows import ui, token  # noqa: E402,F401  (pytest fixture)

ANNA = {'id': 'oabcdef0123', 'name': 'Анна', 'telegram_id': '700000001', 'comment': 'семья', 'traffic_limit_bytes': 100 * GIB,
        'quota_period': 'monthly', 'quota_month': '2026-11', 'used_bytes': 38 * GIB, 'expires_at': '2027-01-31T23:59:59+00:00',
        'max_devices': 3, 'self_add': True, 'home_server': 'awg1', 'blocked': '', 'created_at': '2026-11-28T10:00:00+00:00',
        'devices': [{'interface': 'awg0', 'name': 'alpha', 'enabled': True, 'disabled_reason': '', 'used_bytes': GIB, 'last_handshake': 0},
                    {'interface': 'awg1', 'name': 'beta', 'enabled': False, 'disabled_reason': 'owner_quota', 'used_bytes': 0,
                     'last_handshake': 0}],
        'device_count': 2}


def owners_ui(ui):
    app, client, calls = ui
    original = app.ctl

    def fake(op, data=None):
        if op == 'owners':
            calls.append((op, dict(data or {})))
            return {'owners': [ANNA]}
        if op == 'owner-set':
            calls.append((op, dict(data or {})))
            return {'ok': True, 'owner': {**ANNA, 'id': data.get('id') or 'o9999999999'}}
        if op == 'owner-device-add':
            calls.append((op, dict(data or {})))
            return {'ok': True, 'interface': data['interface'], 'name': data['name'] or 'anna-phone', 'config': ''}
        result = original(op, data)
        if op == 'list' and isinstance(result, dict):
            for c in result.get('clients', []):
                c['owner_id'] = ANNA['id']
        if op == 'download':
            result['owner_id'] = ANNA['id']
        return result
    app.ctl = fake
    return app, client, calls


def test_owners_page_lists_and_creates(ui):
    app, client, calls = owners_ui(ui)
    page = client.get('/owners')
    assert page.status_code == 200 and 'href="/owners"' in page.text and 'data-nav-key="owners"' in page.text
    assert 'Анна' in page.text and '2 / 3' in page.text and '38.0 GiB / 100.0 GiB в месяц' in page.text and '2027-01-31' in page.text
    reply = client.post('/owners', data={'csrf': token(page), 'name': 'Борис', 'telegram_id': '700000009', 'quota_gib': '50',
                                         'quota_monthly': '1', 'expires_at': '31.12.2027', 'max_devices': '2', 'self_add': '1',
                                         'home_server': 'awg0'}, follow_redirects=False)
    assert reply.status_code == 303 and reply.headers['location'] == '/owners/o9999999999?saved=1'
    sent = [d for op, d in calls if op == 'owner-set'][-1]
    assert sent == {'name': 'Борис', 'telegram_id': '700000009', 'comment': '', 'traffic_limit_bytes': 50 * GIB, 'quota_period': 'monthly',
                    'expires_at': '31.12.2027', 'max_devices': 2, 'self_add': True, 'home_server': 'awg0', 'reset_used': False}
    assert client.post('/owners', data={'csrf': token(page), 'name': 'x', 'max_devices': 'many'}).status_code == 422


def test_owner_page_devices_and_adding_one(ui):
    app, client, calls = owners_ui(ui)
    page = client.get('/owners/oabcdef0123')
    assert page.status_code == 200
    assert 'href="/servers/awg1/clients/beta"' in page.text and 'Общий лимит владельца' in page.text
    assert '<progress class="owner-meter" max="100" value="38"' in page.text and 'style=' not in page.text and 'добавляет сам' in page.text
    assert '<option value="awg1" selected>awg1</option>' in page.text                    # the owner's server comes first
    reply = client.post('/owners/oabcdef0123/device', data={'csrf': token(page), 'interface': 'awg1', 'kind': 'tablet', 'name': '',
                                                            'owner_export': '1'}, follow_redirects=False)
    assert reply.headers['location'] == '/servers/awg1/clients/anna-phone'
    assert ('owner-device-add', {'owner_id': 'oabcdef0123', 'interface': 'awg1', 'kind': 'tablet', 'name': '', 'owner_export': True}) in calls
    for bad in ({'interface': 'eth0', 'kind': 'phone'}, {'interface': 'awg1', 'kind': 'toaster'}, {'interface': 'awg1', 'kind': 'phone', 'name': '../x'}):
        assert client.post('/owners/oabcdef0123/device', data={'csrf': token(page), **bad}).status_code == 422
    client.post('/owners/oabcdef0123', data={'csrf': token(page), 'name': 'Анна', 'max_devices': '4', 'reset_used': '1'})
    assert [d for op, d in calls if op == 'owner-set'][-1]['id'] == 'oabcdef0123'
    assert client.post('/owners/oabcdef0123/delete', data={'csrf': token(page)}, follow_redirects=False).headers['location'] == '/owners?deleted=1'
    assert ('owner-delete', {'id': 'oabcdef0123'}) in calls
    assert client.get('/owners/o0000000000').status_code == 404 and client.get('/owners/..%2Fetc').status_code == 404


def test_client_forms_pick_an_owner(ui):
    app, client, calls = owners_ui(ui)
    listing = client.get('/servers/awg0/clients')
    assert 'class="owner-chip" href="/owners/oabcdef0123"' in listing.text and 'data-text="анна"' in listing.text
    assert 'id="new-owner" name="owner_id"' in listing.text
    detail = client.get('/servers/awg0/clients/alpha')
    assert '<option value="oabcdef0123" selected>Анна · 700000001 (2 / 3)</option>' in detail.text
    client.post('/servers/awg0/clients/alpha/policy', data={'csrf': token(detail), 'owner_id': '', 'quota_gib': '0'})
    assert [d for op, d in calls if op == 'client-policy'][-1]['owner_id'] == ''
    assert client.post('/servers/awg0/clients/alpha/policy', data={'csrf': token(detail), 'owner_id': 'evil'}).status_code == 422
    client.post('/servers/awg0/clients', data={'csrf': token(listing), 'name': 'newbie', 'owner_id': 'oabcdef0123'})
    assert [d for op, d in calls if op == 'add'][-1]['owner_id'] == 'oabcdef0123'


def test_bulk_owner(ui):
    app, client, calls = owners_ui(ui)
    listing = client.get('/servers/awg0/clients')
    assert 'data-modal-open="bulk-owner-modal"' in listing.text and 'id="bulk-owner" name="owner_id"' in listing.text
    client.post('/servers/awg0/clients/bulk-action', data={'csrf': token(listing), 'action': 'owner', 'names': ['alpha'],
                                                         'owner_id': 'oabcdef0123'})
    assert ('client-batch', {'names': ['alpha'], 'action': 'owner', 'owner_id': 'oabcdef0123', 'interface': 'awg0'}) in calls
    assert 'Владелец задан клиентам: 1' in client.get('/servers/awg0/clients?bulk=owner&changed=1').text
    assert client.post('/servers/awg0/clients/bulk-action', data={'csrf': token(listing), 'action': 'owner', 'names': ['alpha'],
                                                                'owner_id': 'x'}).status_code == 422
