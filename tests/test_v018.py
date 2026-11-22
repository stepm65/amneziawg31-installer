"""0.18: configurations for owners after a change, client keys in rotation, Steam and custom masking,
moving a client between servers, random subnets, wider random obfuscation and the bot's unit."""
import json
import re
import subprocess
import sys
import types
from io import StringIO
from pathlib import Path

import pytest

from test_peer_routes_i import profile
from test_telegram_bot import FakeApi, FakeController, bot_module, sudo_list, ADMIN, TOKEN
from test_v015 import ctl, db, row  # noqa: F401  (pytest fixture)
from test_v017 import rotating  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)
from importlib.machinery import SourceFileLoader

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ obfuscation defaults
def test_fresh_obfuscation_has_wider_random_junk_and_padding():
    seen = set()
    for _ in range(200):
        fresh = ctl.fresh_obfuscation()
        low, high = (int(x) for x in fresh['ContentPaddingAddition'].split('-'))
        assert 40 <= fresh['Jmin'] <= 79 and 50 <= fresh['Jmax'] - fresh['Jmin'] <= 160
        assert 16 <= low <= 40 and 48 <= high - low <= 96
        checked = ctl.validate_obfuscation({**fresh, 'HeaderProtectionKey': fresh['header_key']}, {'mtu': 1280})
        assert checked['Jmax'] == fresh['Jmax'] and checked['ContentPaddingAddition'] == fresh['ContentPaddingAddition']
        seen.add((fresh['Jmin'], fresh['ContentPaddingAddition']))
    assert len(seen) > 50


# ------------------------------------------------------------------ rotation of client keys
def test_rotation_replaces_only_subscribed_clients_keys(rotating):
    con, call, applied, _ = rotating
    call(ctl.subscription_token, {'name': 'alpha'})
    before = {r['name']: dict(r) for r in con.execute('SELECT * FROM clients')}
    result = call(ctl.rotate_op, {'parts': ['client_keys']})
    after = {r['name']: dict(r) for r in con.execute('SELECT * FROM clients')}
    assert result['clients_rekeyed'] == ['alpha'] and result['port'] == result['old_port'] and applied
    assert after['alpha']['private_key'] != before['alpha']['private_key'] and after['alpha']['psk'] == 'new-psk'
    assert after['alpha']['sub_hash'] == before['alpha']['sub_hash'] and after['alpha']['ip'] == before['alpha']['ip']
    for name in ('beta', 'gamma', 'delta', 'omega'):
        assert after[name] == before[name], name
    assert call(ctl.rotate_schedule, {'days': 3, 'parts': ['port', 'client_keys']})['parts'] == ['port', 'client_keys']


# ------------------------------------------------------------------ masking: Steam and custom
def test_custom_profile_keeps_its_i1_for_new_clients(rotating):
    con, call, _, _ = rotating
    own = '<b 0xdeadbeef><r 40>'
    with pytest.raises(ValueError):
        call(ctl.mask_apply, {'profile': 'custom', 'i1': {}})
    with pytest.raises(ValueError):
        call(ctl.mask_apply, {'profile': 'custom', 'custom_i1': own, 'i1': {'alpha': '<r 10>'}})
    result = call(ctl.mask_apply, {'profile': 'custom', 'custom_i1': own, 'i1': {'alpha': own}, 'port': 4444})
    assert result['port'] == 4444 and row(con, 'alpha')['i1'] == own
    status = ctl.get_status(con)
    assert status['mask_profile'] == 'custom' and status['mask_i1'] == own
    call(ctl.mask_apply, {'profile': 'steam', 'i1': {}, 'port': 27015})
    assert ctl.get_status(con)['mask_i1'] == '' and ctl.get_settings(con)['port'] == 27015


def test_steam_preset_and_profile(ui):
    app, client, calls = ui
    value = app.cps_value('steam')
    assert value == '<b 0xffffffff54536f7572636520456e67696e6520517565727900>'
    assert ctl.validate_i_fields({'i_enabled': '1', 'i1': value})['i1'] == value
    page = client.get('/servers/awg0/settings')
    assert 'value="steam"' in page.text and 'value="custom"' in page.text and 'name="custom_i1"' in page.text
    assert 'name="client_keys"' in page.text
    client.post('/servers/awg0/mask', data={'csrf': token(page), 'profile': 'steam', 'clients': '1', 'use_port': '1'})
    sent = [d for op, d in calls if op == 'mask-apply'][-1]
    assert sent['port'] == 27015 and sent['i1'] == {'alpha': value}
    client.post('/servers/awg0/mask', data={'csrf': token(page), 'profile': 'custom', 'clients': '1', 'use_port': '1',
                                            'custom_port': '4444', 'custom_i1': '<b 0xdead\nbeef>  <r 8>'})
    sent = [d for op, d in calls if op == 'mask-apply'][-1]
    assert sent == {'interface': 'awg0', 'profile': 'custom', 'custom_i1': '<b 0xdeadbeef><r 8>',
                    'i1': {'alpha': '<b 0xdeadbeef><r 8>'}, 'port': 4444}
    client.post('/servers/awg0/rotate', data={'csrf': token(page), 'client_keys': '1'})
    assert ('rotate', {'interface': 'awg0', 'parts': ['client_keys']}) in calls


# ------------------------------------------------------------------ moving a client
@pytest.fixture
def second(db, tmp_path, monkeypatch):
    """The same controller module pointed at a second server's database."""
    con, call, applied = db
    first = (ctl.DB, ctl.CONF, ctl.IFACE)

    def use(which):
        if which == 'awg1':
            monkeypatch.setattr(ctl, 'DB', tmp_path / 'awg1.sqlite3')
            monkeypatch.setattr(ctl, 'CONF', tmp_path / 'awg1.conf')
            monkeypatch.setattr(ctl, 'IFACE', 'awg1')
        else:
            monkeypatch.setattr(ctl, 'DB', first[0]); monkeypatch.setattr(ctl, 'CONF', first[1]); monkeypatch.setattr(ctl, 'IFACE', first[2])
    use('awg1')
    other = ctl.get_conn(True)
    ctl.put_settings(other, {**profile(), 'subnet': '10.88.0.0/24', 'server_ip': '10.88.0.1', 'port': 51999})
    other.commit()
    use('awg0')
    yield con, other, call, use
    other.close()


def test_client_record_moves_with_keys_owner_and_subscription(second):
    con, other, call, use = second
    call(ctl.subscription_token, {'name': 'alpha'})
    con.execute("UPDATE clients SET comment='office', routed_subnets='', extra_lines='PostUp = echo up' WHERE name='alpha'")
    con.commit()
    exported = call(ctl.client_export_row, {'name': 'alpha'})['row']
    assert set(exported) == set(ctl.MOVE_KEEP) and 'ip' not in exported
    use('awg1')
    moved = call(lambda c: ctl.client_import_row(other), {'row': exported})
    assert moved['ip'].startswith('10.88.0.') and moved['interface'] == 'awg1'
    here = dict(other.execute('SELECT * FROM clients WHERE name=?', ('alpha',)).fetchone())
    for key in ('private_key', 'public_key', 'psk', 'telegram_id', 'sub_hash', 'comment', 'extra_lines', 'expires_at'):
        assert here[key] == exported[key], key
    assert here['exported_hash'] == '' and here['invite_hash'] == ''
    with pytest.raises(ValueError, match='уже есть клиент alpha'):
        call(lambda c: ctl.client_import_row(other), {'row': exported})
    with pytest.raises(ValueError, match='Неполная'):
        call(lambda c: ctl.client_import_row(other), {'row': {**exported, 'ip': '1.2.3.4'}})


def mgr_module():
    return SourceFileLoader('awg31mgr_v018', str(ROOT / 'src/awg31mgr')).load_module()


def test_manager_moves_and_undoes_a_half_move(monkeypatch):
    mgr = mgr_module()
    log = []
    fail_delete = {'on': False}

    def child(iface, command, payload):
        log.append((iface, command, payload))
        if command == 'client-export': return {'row': {'name': payload['name']}}
        if command == 'client-import': return {'ok': True, 'ip': '10.88.0.2'}
        if command == 'delete' and iface == 'awg0' and fail_delete['on']: raise RuntimeError('busy')
        return {'ok': True}
    monkeypatch.setattr(mgr, 'child', child)
    monkeypatch.setattr(mgr, 'exists', lambda iface: iface in ('awg0', 'awg1'))
    monkeypatch.setattr(mgr.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(mgr, 'load_source', lambda *a: types.SimpleNamespace())

    def run(data):
        monkeypatch.setattr(sys, 'argv', ['awg31mgr', 'client-move'])
        monkeypatch.setattr(sys, 'stdin', StringIO(json.dumps(data)))
        return mgr.main()
    assert run({'interface': 'awg0', 'name': 'alpha', 'target': 'awg1'}) == {'ok': True, 'name': 'alpha', 'from': 'awg0', 'to': 'awg1', 'ip': '10.88.0.2'}
    assert [c[:2] for c in log] == [('awg0', 'client-export'), ('awg1', 'client-import'), ('awg0', 'delete')]
    log.clear(); fail_delete['on'] = True
    with pytest.raises(RuntimeError):
        run({'interface': 'awg0', 'name': 'alpha', 'target': 'awg1'})
    assert log[-1][:2] == ('awg1', 'delete')                       # the key never stays on two servers
    for bad in ({'interface': 'awg0', 'name': 'alpha', 'target': 'awg0'}, {'interface': 'awg0', 'name': 'alpha', 'target': 'awg7'}):
        with pytest.raises(ValueError):
            run(bad)


def test_manager_random_subnet_retries_only_on_overlaps(monkeypatch):
    mgr = mgr_module()
    tried = []

    def check_new(iface, data):
        tried.append(data['subnet'])
        if len(tried) < 3: raise ValueError('VPN subnet overlaps awg0')
        return data
    monkeypatch.setattr(mgr, 'check_new', check_new)
    data = {}
    mgr.random_subnet('awg1', data)
    assert len(tried) == 3 and all(re.fullmatch(r'10\.([1-9][0-9]?|1[0-9]{2}|2[0-5][0-9])\.[0-9]{1,3}\.0/24', x) for x in tried)
    monkeypatch.setattr(mgr, 'check_new', lambda iface, data: (_ for _ in ()).throw(ValueError('UDP port already used by awg0')))
    with pytest.raises(ValueError, match='UDP port'):
        mgr.random_subnet('awg1', {})
    source = (ROOT / 'src/awg31mgr').read_text()
    assert "payload.pop('random_subnet', False)" in source and "sys.argv[1]=='probe'" in source


def test_panel_wiring_for_move_and_random_subnet(ui):
    app, client, calls = ui
    page = client.get('/servers/awg0/clients/alpha')
    assert 'action="/servers/awg0/clients/alpha/move"' in page.text and '<option value="awg1">awg1</option>' in page.text
    reply = client.post('/servers/awg0/clients/alpha/move', data={'csrf': token(page), 'target': 'awg1'}, follow_redirects=False)
    assert reply.status_code == 303 and reply.headers['location'] == '/servers/awg1/clients/alpha?moved=1'
    assert ('client-move', {'interface': 'awg0', 'name': 'alpha', 'target': 'awg1'}) in calls
    assert client.post('/servers/awg0/clients/alpha/move', data={'csrf': token(page), 'target': 'awg0'}).status_code == 422
    servers = client.get('/servers')
    assert 'name="random_subnet"' in servers.text and 'data-random-subnet="create-subnet"' in servers.text
    client.post('/server/create', data={'csrf': token(servers), 'interface': 'awg2', 'subnet': '', 'port': '51822', 'mtu': '1280',
                                        'endpoint': 'vpn.example.test', 'dns': '1.1.1.1', 'mode': 'split', 'uplink': 'ens3',
                                        'random_subnet': '1'})
    assert [d for op, d in calls if op == 'server-create'][-1]['random_subnet'] is True
    panel = sudo_list('AWG31_SUDO_COMMANDS')
    assert 'client-move' in panel and 'client-move' not in sudo_list('AWG31_BOT_SUDO_COMMANDS')
    assert not {'client-export', 'client-import'} & (panel | sudo_list('AWG31_BOT_SUDO_COMMANDS'))
    assert "'client_moved'" in (ROOT / 'src/awg31admin.py').read_text()


def test_subscription_link_follows_a_moved_client(ui, tmp_path):
    from test_v017 import sub_ui
    app, client, calls, state = sub_ui(ui, tmp_path)
    inner = app.ctl

    def moved(op, data=None):
        if op == 'sub-fetch' and data['interface'] == 'awg0':
            calls.append((op, dict(data)))
            return {'found': False}
        return inner(op, data)
    app.ctl = moved
    from fastapi.testclient import TestClient
    reply = TestClient(app.app).get('/sub/awg0/' + 'T' * 43)
    assert reply.status_code == 200 and [d['interface'] for op, d in calls if op == 'sub-fetch'][-2:] == ['awg0', 'awg1']


# ------------------------------------------------------------------ bot: new configurations for owners
class OwnersController(FakeController):
    def __init__(self):
        super().__init__()
        self.running['awg1'] = True
        self.clients['awg1'] = {}
        base = self.new_client
        self.clients['awg0'] = {
            'alice': {**base('10.8.0.2'), 'telegram_id': '700000001', 'owner_export': True},
            'bob': {**base('10.8.0.3'), 'telegram_id': '700000002', 'owner_export': False},
            'router': {**base('10.8.0.4'), 'telegram_id': '700000003', 'owner_export': True, 'subscription': True},
            'boss': {**base('10.8.0.5'), 'telegram_id': str(ADMIN), 'owner_export': True},
            'off': {**base('10.8.0.6'), 'telegram_id': '700000004', 'owner_export': True, 'enabled': False},
        }


@pytest.fixture
def obot(tmp_path):
    api, controller = FakeApi(), OwnersController()
    config = {'token': TOKEN, 'admins': {ADMIN}, 'lang': 'en', 'api_base': 'https://api.telegram.org'}
    bot = bot_module.Bot(config, api=api, controller=controller, state_path=tmp_path / 'state.json', clock=lambda: 1_780_000_000.0)
    bot.check_audit()
    return bot, api, controller


def to(api, chat):
    return [p['text'] for m, p in api.calls if m == 'sendMessage' and p.get('chat_id') == chat]


def test_owners_get_new_configs_after_a_rotation(obot):
    bot, api, controller = obot
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'server_rotated',
                             'target': 'awg0: port, obfuscation, port 51820 → 34567 (schedule)'})
    bot.check_audit()
    assert any('new configuration of <b>alice</b>' in t for t in to(api, 700000001))
    assert [f[1:3] for f in api.files] == [(700000001, 'alice.conf'), (700000001, 'alice-qr.png')]
    assert any('Ask the administrator' in t for t in to(api, 700000002))
    assert not to(api, 700000003) and not to(api, 700000004)              # a router fetches, a disabled client waits
    assert any('sent to their owners: 1' in t for t in to(api, ADMIN))
    assert ('download', {'interface': 'awg0', 'name': 'alice', 'mark': True}) in controller.log


def test_owners_get_configs_after_the_bot_own_rotation_and_a_move(obot):
    bot, api, controller = obot
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'server_rotated',
                             'target': f'awg0: port, obfuscation, port 51820 → 34567 (telegram {ADMIN})'})
    bot.check_audit()
    assert len(api.files) == 2
    api.files.clear()
    controller.clients['awg1']['alice'] = controller.clients['awg0'].pop('alice')
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'client_moved', 'target': 'awg0/alice → awg1/alice (10.88.0.2)'})
    bot.check_audit()
    assert [f[1:3] for f in api.files] == [(700000001, 'alice.conf'), (700000001, 'alice-qr.png')]
    assert not any('bob' in t for t in to(api, 700000002)[1:])           # only the moved client
    api.files.clear()
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'mask_profile_applied', 'target': 'awg0: none, 0 clients, port 51820 → 51820'})
    bot.check_audit()
    assert api.files == []                                                # nothing changed for anybody


# ------------------------------------------------------------------ installer and units
def test_bot_unit_is_hardened_without_breaking_sudo():
    unit = (ROOT / 'scripts/awg31-bot.service').read_text()
    for line in ('LockPersonality=true', 'RestrictRealtime=true', 'RestrictSUIDSGID=true', 'ProtectHostname=true',
                 'ProtectControlGroups=true', 'SystemCallArchitectures=native', 'PrivateTmp=true', 'ProtectHome=true'):
        assert line in unit, line
    for forbidden in ('NoNewPrivileges=', 'ProtectKernelModules=', 'ProtectKernelTunables='):
        assert forbidden not in unit, forbidden


def test_wizard_offers_a_random_subnet():
    out = subprocess.run(['bash', '-c', f'source {ROOT}/scripts/os-support.sh; for i in 1 2 3 4 5 6; do awg31_random_subnet; done'],
                         capture_output=True, text=True, check=True).stdout.split()
    assert len(out) == 6 and all(re.fullmatch(r'10\.[0-9]{1,3}\.[0-9]{1,3}\.0/24', x) for x in out) and len(set(out)) > 1
    wizard = (ROOT / 'scripts/setup-wizard.sh').read_text()
    assert 'AWG31_RANDOM_SUBNET' in wizard and 'awg31_random_subnet' in wizard
    assert wizard.index('awg31_random_subnet') < wizard.index("ask SUBNET")
    assert 'AWG31_RANDOM_SUBNET=1' in (ROOT / 'install.sh').read_text()
