"""0.10: speed limits, monthly quota, batch creation, host protection, encrypted backups,
two-factor sign-in, Telegram settings in the panel and the new bot roles and messages."""
import base64
import hashlib
import hmac
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader
from io import StringIO
from pathlib import Path

import pytest

from test_regressions import load_admin, p2p_config
from test_telegram_bot import ADMIN, OWNER, FakeApi, FakeController, bot_module, message, notifications, press
from test_workflows import ui, token  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
ctl = SourceFileLoader('awg31ctl_v010', str(ROOT / 'src' / 'awg31ctl')).load_module()


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, 'DB', tmp_path / 'state.sqlite3')
    monkeypatch.setattr(ctl, 'CONF', tmp_path / 'awg0.conf')
    monkeypatch.setattr(ctl, 'live_stats', lambda: {})
    commands = []

    def fake_run(argv, *args, **kwargs):
        commands.append(list(argv))
        return type('P', (), {'returncode': 1, 'stdout': '', 'stderr': ''})()     # interface "down": nothing live to sync
    monkeypatch.setattr(ctl.subprocess, 'run', fake_run)
    keys = iter(range(10_000))
    monkeypatch.setattr(ctl, 'keygen', lambda: f'priv{next(keys):040d}')
    monkeypatch.setattr(ctl, 'pubkey', lambda private: 'pub' + private[4:])
    monkeypatch.setattr(ctl, 'pskgen', lambda: 'p' * 44)
    con = ctl.get_conn(True)
    ctl.put_settings(con, {**p2p_config(), **ctl.fresh_obfuscation()})
    con.commit()

    def call(function, payload):
        monkeypatch.setattr(sys, 'stdin', StringIO(json.dumps(payload)))
        return function(con)
    yield con, call, commands
    con.close()


# ------------------------------------------------------------------ speed limit
def test_speed_limit_becomes_tc_rules_for_both_directions(db):
    con, call, _ = db
    call(ctl.clients_add, {'name': 'slow', 'speed_limit_mbit': 10})
    call(ctl.clients_add, {'name': 'free'})
    con.execute("UPDATE clients SET routed_subnets='192.168.50.0/24' WHERE name='slow'")     # a LAN behind the client
    ctl.apply(ctl.get_settings(con), con)
    peers = ctl.peer_rows(con)
    commands = ctl.shaping_commands(ctl.get_settings(con), peers)
    slow = next(p for p in peers if p['name'] == 'slow')
    number = int(slow['ip'].rsplit('.', 1)[1])
    assert commands[0] == 'tc qdisc add dev awg0 root handle 1: htb default 0'       # unmatched traffic is not shaped
    assert f'tc class add dev awg0 parent 1: classid 1:{number:x} htb rate 10mbit ceil 10mbit' in commands
    assert any(f"match ip dst {slow['ip']}/32 flowid 1:{number:x}" in c for c in commands)          # download
    assert any(f"match ip src {slow['ip']}/32 police rate 10mbit" in c and 'drop' in c for c in commands)   # upload
    assert any('match ip dst 192.168.50.0/24' in c for c in commands), 'the LAN behind the client shares its limit'
    free = next(p for p in peers if p['name'] == 'free')
    assert not any(free['ip'] + '/32' in c for c in commands)
    conf = ctl.CONF.read_text()
    assert conf.count('PostUp = tc ') == len(commands)
    assert all(line.endswith('|| true') for line in conf.splitlines() if line.startswith('PostUp = tc ')), \
        'a failed limit must not keep the VPN from starting'


def test_no_limits_means_no_tc_at_all_and_disabled_clients_are_skipped(db):
    con, call, _ = db
    call(ctl.clients_add, {'name': 'plain'})
    assert ctl.shaping_commands(ctl.get_settings(con), ctl.peer_rows(con)) == []
    assert 'tc ' not in ctl.CONF.read_text()
    call(ctl.client_policy_update, {'name': 'plain', 'speed_limit_mbit': 25})
    assert 'htb rate 25mbit' in ctl.CONF.read_text(), 'changing the limit rewrites the configuration'
    call(lambda c: ctl.clients_action(c, 'disable'), {'name': 'plain'})
    assert 'tc ' not in ctl.CONF.read_text()


@pytest.mark.parametrize('value', [-1, 10001, 'fast', '1.5'])
def test_bad_speed_is_rejected(value):
    with pytest.raises(ValueError):
        ctl.validate_policy({'speed_limit_mbit': value})


# ------------------------------------------------------------------ monthly quota
def test_monthly_quota_resets_and_revives_only_quota_stopped_clients(db):
    con, call, _ = db
    for name in ('monthly', 'lifetime', 'expired'):
        call(ctl.clients_add, {'name': name, 'traffic_limit_bytes': 1000,
                               'quota_period': '' if name == 'lifetime' else 'monthly'})
    con.execute("UPDATE clients SET used_bytes=5000, enabled=0, disabled_reason='quota', quota_month='2026-01'")
    con.execute("UPDATE clients SET expires_at='2026-01-15T00:00:00+00:00' WHERE name='expired'")
    con.commit()
    same_month = ctl.sample_usage(con, datetime(2026, 1, 31, 23, 59, tzinfo=timezone.utc))
    assert same_month['enabled'] == []
    result = ctl.sample_usage(con, datetime(2026, 2, 1, 0, 1, tzinfo=timezone.utc))
    assert result['enabled'] == ['monthly']
    rows = {r['name']: r for r in ctl.peer_rows(con)}
    assert rows['monthly']['enabled'] == 1 and rows['monthly']['used_bytes'] == 0 and rows['monthly']['quota_month'] == '2026-02'
    assert rows['lifetime']['enabled'] == 0 and rows['lifetime']['used_bytes'] == 5000, 'a lifetime quota never resets'
    assert rows['expired']['enabled'] == 0 and rows['expired']['used_bytes'] == 0, 'an expired client stays off'
    assert ctl.sample_usage(con, datetime(2026, 2, 2, tzinfo=timezone.utc))['enabled'] == []


def test_turning_monthly_on_does_not_reset_at_once(db):
    con, call, _ = db
    call(ctl.clients_add, {'name': 'c1', 'traffic_limit_bytes': 10 ** 9})
    con.execute("UPDATE clients SET used_bytes=777")
    con.commit()
    call(ctl.client_policy_update, {'name': 'c1', 'quota_period': 'monthly'})
    ctl.sample_usage(con)
    assert ctl.peer_rows(con)[0]['used_bytes'] == 777


# ------------------------------------------------------------------ batch creation
def test_batch_creates_numbered_clients_with_shared_limits(db):
    con, call, commands = db
    result = call(ctl.clients_add_batch, {'prefix': 'office', 'count': 12, 'start': 9, 'traffic_limit_bytes': 5 * 1024 ** 3,
                                          'speed_limit_mbit': 20, 'expires_at': '2030-01-01', 'telegram_id': '123456',
                                          'routed_subnets': '10.0.0.0/8'})
    names = [c['name'] for c in result['clients']]
    assert names == [f'office-{n:02d}' for n in range(9, 21)]
    assert len({c['ip'] for c in result['clients']}) == 12 and all('PrivateKey = priv' in c['config'] for c in result['clients'])
    rows = ctl.peer_rows(con)
    assert all(r['traffic_limit_bytes'] == 5 * 1024 ** 3 and r['speed_limit_mbit'] == 20 and r['expires_at'].startswith('2030-01-01') for r in rows)
    assert all(r['telegram_id'] == '' and r['routed_subnets'] == '' for r in rows), 'owner and routes are personal, never copied'
    assert all(r['exported_hash'] for r in rows), 'the ZIP counts as handing the configurations out'
    assert ctl.CONF.read_text().count('[Peer]') == 12


@pytest.mark.parametrize('payload', [{'prefix': 'x', 'count': 0}, {'prefix': 'x', 'count': 51}, {'prefix': 'bad name', 'count': 2},
                                     {'prefix': 'p' * 30, 'count': 2}, {'prefix': 'x', 'count': 'many'}, {'prefix': '', 'count': 2}])
def test_batch_rejects_bad_requests_without_creating_anything(db, payload):
    con, call, _ = db
    with pytest.raises(ValueError):
        call(ctl.clients_add_batch, payload)
    assert ctl.peer_rows(con) == []


def test_batch_refuses_to_overwrite_and_is_all_or_nothing(db):
    con, call, _ = db
    call(ctl.clients_add, {'name': 'team-03'})
    with pytest.raises(ValueError, match='team-03'):
        call(ctl.clients_add_batch, {'prefix': 'team', 'count': 5})
    con.rollback()
    assert [r['name'] for r in ctl.peer_rows(con)] == ['team-03']


def test_batch_download_is_a_zip_of_configurations(ui):
    app, client, calls = ui
    original = app.ctl

    def fake(op, data=None):
        if op == 'add-batch':
            calls.append((op, dict(data)))
            return {'ok': True, 'clients': [{'name': f'team-0{n}', 'ip': f'10.0.0.{n}', 'config': f'[Interface]\n# {n}\n'} for n in (1, 2, 3)]}
        return original(op, data)
    app.ctl = fake
    page = client.get('/servers/awg0/clients')
    assert 'action="/servers/awg0/clients/batch"' in page.text
    reply = client.post('/servers/awg0/clients/batch', data={'csrf': token(page), 'prefix': 'team', 'count': '3', 'start': '1',
                                                             'quota_gib': '2', 'speed_limit_mbit': '15', 'quota_monthly': '1'})
    assert reply.status_code == 200 and reply.headers['content-type'] == 'application/zip'
    assert 'team-3-clients.zip' in reply.headers['content-disposition'] and reply.headers['cache-control'] == 'no-store'
    archive = zipfile.ZipFile(io.BytesIO(reply.content))
    assert archive.namelist() == ['team-01.conf', 'team-02.conf', 'team-03.conf'] and b'# 2' in archive.read('team-02.conf')
    sent = next(data for op, data in calls if op == 'add-batch')
    assert sent['traffic_limit_bytes'] == 2 * 1024 ** 3 and sent['speed_limit_mbit'] == 15 and sent['quota_period'] == 'monthly'
    assert client.post('/servers/awg0/clients/batch', data={'prefix': 'team', 'count': '3'}).status_code in (400, 403), 'CSRF token is required'


# ------------------------------------------------------------------ host protection
def input_rules(conf):
    """Replay PostUp on an empty INPUT chain and return it top to bottom."""
    chain = []
    for line in conf.splitlines():
        if not line.startswith('PostUp = iptables -w ') or ' INPUT ' not in line:
            continue
        words = line[len('PostUp = iptables -w '):].split(' 2>/dev/null')[0].split()
        if words[0] == '-I':
            chain.insert(0, ' '.join(words[3:]))
        elif words[0] == '-D' and ' '.join(words[2:]) in chain:
            chain.remove(' '.join(words[2:]))
    return chain


def test_host_access_off_drops_new_connections_to_the_server_but_keeps_replies_and_ping():
    cfg = p2p_config(host_access='off')
    net = ctl.parse_network(cfg['subnet'])
    chain = input_rules('\n'.join(ctl.firewall_lines(cfg, net, [])))
    assert chain == ['-i awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
                     '-i awg0 -p icmp --icmp-type echo-request -j ACCEPT',
                     '-i awg0 -j DROP']
    dns_here = input_rules('\n'.join(ctl.firewall_lines(p2p_config(host_access='off', dns='10.10.54.1'), net, [])))
    assert dns_here[-1] == '-i awg0 -j DROP' and sum('--dport 53 -j ACCEPT' in rule for rule in dns_here[:-1]) == 2


def test_host_access_default_adds_no_input_rules_and_cleans_up_old_ones():
    cfg = p2p_config()
    lines = ctl.firewall_lines(cfg, ctl.parse_network(cfg['subnet']), [])
    assert ctl.switch(cfg, 'host_access') == 'on' and input_rules('\n'.join(lines)) == []
    assert 'PostUp = iptables -w -D INPUT -i awg0 -j DROP 2>/dev/null || true' in lines, 'switching back removes the rule'
    off = ctl.firewall_lines(p2p_config(host_access='off'), ctl.parse_network(cfg['subnet']), [])
    assert 'PostDown = iptables -w -D INPUT -i awg0 -j DROP 2>/dev/null || true' in off, 'stopping the server removes it'


# ------------------------------------------------------------------ two-factor sign-in
def totp_now(secret, shift=0):
    step = int(time.time() // 30) + shift
    digest = hmac.new(base64.b32decode(secret), step.to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000:06d}'


def test_totp_matches_the_rfc_6238_vector():
    admin = load_admin('admin_totp_vector')
    secret = base64.b32encode(b'12345678901234567890').decode()
    assert admin.totp_counter_for(secret, '287082', now=59) == 1          # RFC 6238 appendix B, SHA-1, T=59
    assert admin.totp_counter_for(secret, '287082', now=59 + 90) is None
    assert admin.totp_counter_for(secret, 'abcdef', now=59) is None


@pytest.fixture
def auth(tmp_path, monkeypatch):
    admin = load_admin('admin_totp')
    salt = b'7' * 16
    file = tmp_path / 'auth.json'
    file.write_text(json.dumps({'salt': salt.hex(), 'session_key': 'S' * 48, 'auth_version': 'v1',
                                'password_hash': hashlib.scrypt(b'the-right-password', salt=salt, n=2**14, r=8, p=1, dklen=32).hex()}))
    monkeypatch.setenv('AWG31_AUTH', str(file))
    monkeypatch.setenv('AWG31_AUDIT', str(tmp_path / 'audit.jsonl'))
    return admin, file


def test_totp_needs_password_and_a_valid_code_to_turn_on_and_off(auth):
    admin, file = auth
    secret = base64.b32encode(os.urandom(20)).decode()
    with pytest.raises(ValueError, match='password'):
        admin.totp_enable({'password': 'wrong', 'secret': secret, 'code': totp_now(secret)})
    with pytest.raises(ValueError, match='code'):
        admin.totp_enable({'password': 'the-right-password', 'secret': secret, 'code': '000000'})
    with pytest.raises(ValueError):
        admin.totp_enable({'password': 'the-right-password', 'secret': 'short', 'code': '123456'})
    assert 'totp_secret' not in json.loads(file.read_text())
    admin.totp_enable({'password': 'the-right-password', 'secret': secret, 'code': totp_now(secret, -1)})   # one step of drift
    stored = json.loads(file.read_text())
    assert stored['totp_secret'] == secret and stored['auth_version'] != 'v1', 'every session ends when the rule changes'
    with pytest.raises(ValueError):
        admin.totp_disable({'password': 'the-right-password', 'code': '111111'})
    with pytest.raises(ValueError):
        admin.totp_disable({'password': 'wrong', 'code': totp_now(secret)})
    admin.totp_disable({'password': 'the-right-password', 'code': totp_now(secret)})
    assert 'totp_secret' not in json.loads(file.read_text())
    admin.totp_enable({'password': 'the-right-password', 'secret': secret, 'code': totp_now(secret)})
    admin.totp_reset()                                                    # console recovery: no code
    assert 'totp_secret' not in json.loads(file.read_text())
    assert 'console reset' in Path(os.environ['AWG31_AUDIT']).read_text()


def test_login_asks_for_the_code_and_refuses_a_replayed_one(ui):
    app, client, calls = ui
    secret = base64.b32encode(os.urandom(20)).decode()
    stored = json.loads(app.AUTH_FILE.read_text())
    client.get('/logout')
    assert 'name="code"' not in client.get('/login').text
    app.AUTH_FILE.write_text(json.dumps({**stored, 'totp_secret': secret}))
    app.login_attempts.clear()
    app.LAST_TOTP_STEP[0] = 0
    assert 'name="code"' in client.get('/login').text

    def sign_in(code):
        reply = client.post('/login', data={'password': 'correct-test-password', 'code': code}, follow_redirects=False)
        return reply.status_code == 303
    assert not sign_in('') and not sign_in('000000')
    assert ('audit', {'event': 'login_failed', 'target': 'testclient'}) in calls
    code = totp_now(secret)
    assert sign_in(code)
    client.get('/logout')
    assert not sign_in(code), 'a code works once'
    assert sign_in(totp_now(secret, 1)), 'the next code works'


def test_security_page_offers_setup_with_a_qr_and_then_the_switch_off(ui):
    app, client, calls = ui
    page = client.get('/maintenance?tab=security')
    assert 'action="/maintenance/totp/enable"' in page.text and 'src="data:image/png;base64,' in page.text
    secret = page.text.split('name="secret" value="')[1].split('"')[0]
    assert len(secret) == 32 and base64.b32decode(secret)
    reply = client.post('/maintenance/totp/enable', data={'csrf': token(page), 'secret': secret, 'password': 'pw', 'code': '123456'},
                        follow_redirects=False)
    assert reply.status_code == 303 and reply.headers['location'] == '/login'
    assert ('totp-enable', {'password': 'pw', 'code': '123456', 'secret': secret}) in calls
    stored = json.loads(app.AUTH_FILE.read_text())
    app.AUTH_FILE.write_text(json.dumps({**stored, 'totp_secret': secret}))
    app.LAST_TOTP_STEP[0] = 0
    client.post('/login', data={'password': 'correct-test-password', 'code': totp_now(secret)})
    page = client.get('/maintenance?tab=security')
    assert 'action="/maintenance/totp/disable"' in page.text and 'totp/enable' not in page.text


# ------------------------------------------------------------------ encrypted backups
needs_gpg = pytest.mark.skipif(shutil.which('gpg') is None, reason='gpg is not installed')


class Manager:
    """The two things create_backup asks the dispatcher for."""
    def __init__(self, tmp):
        self.tmp = tmp

    def interfaces(self):
        return []

    def db_path(self, iface):
        return self.tmp / f'{iface}.sqlite3'


@pytest.fixture
def backups(tmp_path, monkeypatch):
    admin = load_admin('admin_enc')
    for name, value in (('AWG31_BACKUP_DIR', tmp_path / 'full'), ('AWG31_BACKUP_KEY', tmp_path / 'etc' / 'backup-passphrase'),
                        ('AWG31_AUDIT', tmp_path / 'audit.jsonl'), ('AWG31_AUTH', tmp_path / 'auth.json'),
                        ('AWG31_ROOT', tmp_path / 'root')):
        monkeypatch.setenv(name, str(value))
    (tmp_path / 'auth.json').write_text('{"marker": "PANEL-SECRET"}')
    monkeypatch.setattr(admin, '_collect', lambda manager: {'auth/auth.json': tmp_path / 'auth.json'})
    monkeypatch.setattr(admin.os, 'chown', lambda *a: None)
    return admin, Manager(tmp_path), tmp_path


@needs_gpg
def test_backups_are_encrypted_once_a_passphrase_is_set(backups):
    admin, manager, tmp = backups
    plain = admin.create_backup(manager)
    assert plain['name'].endswith('.tar.gz') and plain['encrypted'] is False and admin.backup_encryption() == {'enabled': False}
    reply = admin.backup_encryption_set({})
    passphrase = reply['passphrase']
    assert len(passphrase) >= 16 and admin.backup_encryption() == {'enabled': True}
    key = tmp / 'etc' / 'backup-passphrase'
    assert key.read_text().strip() == passphrase and key.stat().st_mode & 0o777 == 0o600
    sealed = admin.create_backup(manager)
    assert sealed['name'].endswith('.tar.gz.gpg') and sealed['encrypted'] is True
    files = sorted(p.name for p in (tmp / 'full').iterdir())
    assert files == sorted([plain['name'], sealed['name']]), 'no plain copy of the encrypted archive is left behind'
    blob = (tmp / 'full' / sealed['name']).read_bytes()
    assert b'PANEL-SECRET' not in blob and b'auth.json' not in blob
    # Anybody with the passphrase and stock gpg can open it; a wrong passphrase cannot.
    home = tmp / 'gnupg'
    home.mkdir(mode=0o700)
    def decrypt(secret):
        return subprocess.run(['gpg', '--homedir', str(home), '--batch', '--quiet', '--pinentry-mode', 'loopback', '--passphrase', secret,
                               '--decrypt', str(tmp / 'full' / sealed['name'])], capture_output=True)
    opened = decrypt(passphrase)
    assert opened.returncode == 0
    with tarfile.open(fileobj=io.BytesIO(opened.stdout), mode='r:gz') as archive:
        assert b'PANEL-SECRET' in archive.extractfile('auth/auth.json').read()
    assert decrypt('not-the-passphrase').returncode != 0
    assert {b['name']: b['encrypted'] for b in admin.list_backups()['backups']} == {plain['name']: False, sealed['name']: True}


@needs_gpg
def test_only_encrypted_archives_can_go_to_the_bot(backups):
    admin, manager, tmp = backups
    plain = admin.create_backup(manager)
    admin.backup_encryption_set({'passphrase': 'a long passphrase of my own'})
    sealed = admin.create_backup(manager)
    with pytest.raises(ValueError, match='encrypted'):
        admin.export_backup({'name': plain['name']}, encrypted_only=True)
    content = base64.b64decode(admin.export_backup({'name': sealed['name']}, encrypted_only=True)['content'])
    assert content == (tmp / 'full' / sealed['name']).read_bytes()
    assert admin.export_backup({'name': plain['name']})['name'] == plain['name'], 'the panel still downloads either kind'
    with pytest.raises(ValueError):
        admin.backup_encryption_set({'passphrase': 'short'})
    admin.backup_encryption_set({'off': True})
    assert admin.backup_encryption() == {'enabled': False} and admin.create_backup(manager)['encrypted'] is False


@needs_gpg
def test_restore_check_opens_an_encrypted_archive_and_explains_a_missing_passphrase(backups, monkeypatch):
    admin, manager, tmp = backups
    admin.backup_encryption_set({'passphrase': 'restore test passphrase'})
    sealed = admin.create_backup(manager)['name']
    restore = SourceFileLoader('restore_v010', str(ROOT / 'scripts/restore-backup.py')).load_module()
    monkeypatch.setattr(restore, 'BACKUP_DIR', tmp / 'full')
    try:
        restore.validate(sealed)
    except ValueError as exc:                     # this archive has no interfaces; decryption itself must have worked
        assert 'decrypt' not in str(exc).lower() and 'passphrase' not in str(exc).lower()
    (tmp / 'etc' / 'backup-passphrase').write_text('another passphrase entirely\n')
    with pytest.raises(ValueError, match='wrong passphrase'):
        restore.validate(sealed)
    (tmp / 'etc' / 'backup-passphrase').unlink()
    with pytest.raises(ValueError, match='backup-encryption on'):
        restore.validate(sealed)


# ------------------------------------------------------------------ Telegram settings from the panel
def test_panel_edits_bot_settings_but_never_sees_the_token(tmp_path, monkeypatch):
    admin = load_admin('admin_tg')
    config = tmp_path / 'telegram.json'
    token_value = '123456789:' + 'T' * 35
    config.write_text(json.dumps({'token': token_value, 'admins': [111222333], 'lang': 'ru', 'api_base': 'http://x'}))
    monkeypatch.setenv('AWG31_BOT_CONFIG', str(config))
    monkeypatch.setenv('AWG31_AUDIT', str(tmp_path / 'audit.jsonl'))
    monkeypatch.setattr(admin.subprocess, 'run', lambda *a, **k: type('P', (), {'returncode': 0, 'stdout': 'active\n'})())
    monkeypatch.setattr(admin.os, 'chown', lambda *a: None)
    status = admin.telegram_status()
    assert token_value not in json.dumps(status) and status['admins'] == [111222333] and status['active'] == 'active'
    admin.telegram_set({'admins': '111222333, 444555666', 'viewers': '777888999 111222333', 'lang': 'en', 'digest': 'weekly',
                        'notify': {'server': True, 'backups': True}})
    saved = json.loads(config.read_text())
    assert saved['token'] == token_value and saved['api_base'] == 'http://x', 'token and API address are kept'
    assert saved['admins'] == [111222333, 444555666] and saved['viewers'] == [777888999], 'an administrator is not also a viewer'
    assert saved['notify'] == {'server': True, 'clients': False, 'security': False, 'backups': True} and saved['digest'] == 'weekly'
    assert config.stat().st_mode & 0o777 == 0o640
    for bad in ({'admins': ''}, {'admins': '@durov'}, {'admins': '111222333', 'lang': 'de'}, {'admins': '111222333', 'digest': 'hourly'},
                {'admins': ','.join(str(1000 + n) for n in range(11))}):
        with pytest.raises(ValueError):
            admin.telegram_set(bad)
    config.unlink()
    assert admin.telegram_status() == {'configured': False}
    with pytest.raises(ValueError):
        admin.telegram_set({'admins': '111222333'})


def test_telegram_tab_shows_the_form_and_posts_the_settings(ui):
    app, client, calls = ui
    assert 'sudo awg31 telegram' in client.get('/maintenance?tab=telegram').text
    original = app.ctl
    app.ctl = lambda op, data=None: ({'configured': True, 'active': 'active', 'admins': [111222333], 'viewers': [], 'lang': 'ru',
                                      'digest': 'off', 'notify': {'server': True, 'clients': False, 'security': True, 'backups': False}}
                                     if op == 'telegram-status' else original(op, data))
    page = client.get('/maintenance?tab=telegram')
    assert 'value="111222333"' in page.text and 'name="notify_server" value="1" checked' in page.text
    assert 'name="notify_clients" value="1">' in page.text
    reply = client.post('/maintenance/telegram', data={'csrf': token(page), 'admins': '111222333', 'viewers': '42424242', 'lang': 'en',
                                                       'digest': 'daily', 'notify_backups': '1'}, follow_redirects=False)
    assert reply.status_code == 303
    assert ('telegram-set', {'admins': '111222333', 'viewers': '42424242', 'lang': 'en', 'digest': 'daily',
                             'notify': {'server': False, 'clients': False, 'security': False, 'backups': True}}) in calls


# ------------------------------------------------------------------ bot: viewers, renewal, owner messages, digest, backup file
VIEWER = 321321321


@pytest.fixture
def env(tmp_path):
    api, controller, now = FakeApi(), FakeController(), [1_780_000_000.0]
    config = {'token': '1' * 9 + ':' + 'A' * 35, 'admins': {ADMIN}, 'viewers': {VIEWER}, 'lang': 'en', 'digest': 'off',
              'api_base': 'https://api.telegram.org', 'notify': {'server': True, 'clients': True, 'security': True, 'backups': True}}
    bot = bot_module.Bot(config, api=api, controller=controller, state_path=tmp_path / 'state.json', clock=lambda: now[0])
    return bot, api, controller, now


def test_viewer_sees_screens_without_action_buttons_and_cannot_act(env):
    bot, api, controller, now = env
    bot.handle_update(press('c:awg0:alice', user=VIEWER))
    assert 'alice' in api.texts()[-1]
    assert all(data.split(':')[0] in bot_module.READ_KINDS for data in api.buttons()) and api.buttons()
    bot.handle_update(press('bk', user=VIEWER))
    assert 'bky' not in api.buttons()
    before = len(controller.log)
    for update in [press('cy:awg0:alice:del', user=VIEWER), press('ca:awg0:alice:conf', user=VIEWER), press('sy:awg0:stop', user=VIEWER),
                   press('bky', user=VIEWER), press('ca:awg0:alice:off', user=VIEWER), press('cs:awg0:alice:5', user=VIEWER),
                   press('rn:awg0:alice:30', user=VIEWER), message('/add sneaky', user=VIEWER), press('add:awg0', user=VIEWER),
                   message('sneaky', user=VIEWER)]:
        bot.handle_update(update)
        assert 'read-only' in api.texts()[-1] or 'AmneziaWG' in api.texts()[-1]
    assert not {c for c, _ in controller.log[before:]} - {'servers', 'list'}, 'a viewer triggers nothing but reads'
    assert 'alice' in controller.clients['awg0'] and controller.running['awg0'] and api.files == []
    # The administrator, right after, still has every button.
    bot.handle_update(press('c:awg0:alice'))
    assert 'ca:awg0:alice:del' in api.buttons()


def test_viewers_get_notifications_too(env):
    bot, api, controller, _ = env
    bot.tick()
    controller.running['awg0'] = False
    start = len(api.calls)
    bot.tick()
    assert sorted(p['chat_id'] for m, p in api.calls[start:] if m == 'sendMessage') == sorted([ADMIN, VIEWER])


def test_owner_asks_for_more_time_and_the_admin_answers_with_one_button(env):
    bot, api, controller, now = env
    alice = controller.clients['awg0']['alice']
    expiry = (datetime.fromtimestamp(now[0], timezone.utc) + timedelta(days=2)).isoformat()
    alice.update(telegram_id=str(OWNER), expires_at=expiry)
    bot.handle_update(message('/start', user=OWNER))
    assert 'mr:awg0:alice' in api.buttons()
    now[0] += 10
    start = len(api.calls)
    bot.handle_update(press('mr:awg0:alice', user=OWNER))
    sent = [(p['chat_id'], p) for m, p in api.calls[start:] if m == 'sendMessage']
    request = next(p for chat, p in sent if chat == ADMIN)
    assert 'asks to extend' in request['text'] and str(OWNER) in request['text']
    assert [b['callback_data'] for row in request['reply_markup']['inline_keyboard'] for b in row] == \
        ['rn:awg0:alice:7', 'rn:awg0:alice:30', 'rn:awg0:alice:90', 'rn:awg0:alice:0']
    assert not any(chat == VIEWER for chat, _ in sent), 'viewers cannot grant it, so they are not asked'
    assert any(chat == OWNER and 'was sent' in p['text'] for chat, p in sent)
    now[0] += 10
    start = len(api.calls)
    bot.handle_update(press('mr:awg0:alice', user=OWNER))
    assert not any(p.get('chat_id') == ADMIN for m, p in api.calls[start:]), 'one request a day'
    # Granted: 30 days on top of the current date, the owner is told.
    start = len(api.calls)
    bot.handle_update(press('rn:awg0:alice:30'))
    expected = (datetime.fromisoformat(expiry) + timedelta(days=30)).date().isoformat()
    assert alice['expires_at'] == expected
    assert any(p.get('chat_id') == OWNER and expected in p['text'] for m, p in api.calls[start:] if m == 'sendMessage')
    # An expired, disabled client: counted from today and switched back on.
    alice.update(expires_at='2020-01-01T00:00:00+00:00', enabled=False, disabled_reason='expired')
    bot.handle_update(press('rn:awg0:alice:7'))
    assert alice['enabled'] is True
    assert alice['expires_at'] == (datetime.fromtimestamp(now[0], timezone.utc) + timedelta(days=7)).date().isoformat()
    # Refused: nothing changes, the owner is told.
    kept = alice['expires_at']
    start = len(api.calls)
    bot.handle_update(press('rn:awg0:alice:0'))
    assert alice['expires_at'] == kept
    assert any(p.get('chat_id') == OWNER and 'refused' in p['text'] for m, p in api.calls[start:] if m == 'sendMessage')


def test_owner_cannot_request_renewal_for_somebody_elses_client(env):
    bot, api, controller, now = env
    controller.clients['awg0']['alice'].update(telegram_id=str(OWNER), expires_at='2031-01-01T00:00:00+00:00')
    controller.clients['awg0']['boss'] = {**controller.new_client('10.8.0.9'), 'expires_at': '2031-01-01T00:00:00+00:00'}
    bot.handle_update(press('mr:awg0:boss', user=OWNER))
    assert not any(p.get('chat_id') == ADMIN for m, p in api.calls)


def test_owner_is_told_about_quota_and_automatic_switches(env):
    bot, api, controller, now = env
    alice = controller.clients['awg0']['alice']
    alice.update(telegram_id=str(OWNER), traffic_limit_bytes=1000, used_bytes=500)
    bot.tick()
    assert notifications(api, 0) == []
    alice['used_bytes'] = 850
    bot.tick()
    bot.tick()
    sent = [(p['chat_id'], p['text']) for m, p in api.calls if m == 'sendMessage']
    assert sorted(chat for chat, _ in sent) == sorted([ADMIN, VIEWER, OWNER]) and all('85%' in text for _, text in sent), 'once, not every minute'
    assert 'awg0' not in next(text for chat, text in sent if chat == OWNER)
    alice.update(used_bytes=0)                       # monthly reset re-arms the warning
    bot.tick()
    alice.update(used_bytes=900)
    start = len(api.calls)
    bot.tick()
    assert len([1 for m, p in api.calls[start:] if m == 'sendMessage']) == 3
    # Automatic disable and re-enable recorded by the sampler.
    start = len(api.calls)
    alice.update(enabled=False, disabled_reason='quota')
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'client_disabled', 'target': 'awg0/alice (auto)'})
    bot.tick()
    told = [p['text'] for m, p in api.calls[start:] if m == 'sendMessage' and p['chat_id'] == OWNER]
    assert len(told) == 1 and 'disabled' in told[0] and 'quota' in told[0]
    start = len(api.calls)
    alice.update(enabled=True, disabled_reason='', used_bytes=0)
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'client_enabled', 'target': 'awg0/alice (auto)'})
    bot.tick()
    texts = {p['chat_id']: p['text'] for m, p in api.calls[start:] if m == 'sendMessage'}
    assert 'works again' in texts[OWNER] and 'enabled automatically' in texts[ADMIN]


def test_encrypted_backup_arrives_as_a_file_and_a_plain_one_never_does(env):
    bot, api, controller, _ = env
    bot.tick()
    served = []

    def fake(command, data=None):
        if command == 'backup-export-encrypted':
            served.append(data['name'])
            return {'name': data['name'], 'content': base64.b64encode(b'GPG-BYTES').decode()}
        return FakeController.__call__(controller, command, data)
    bot.ctl = fake
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'backup_created', 'target': 'awg31-20260101T000000Z-aaaaaaaaaa.tar.gz'})
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'backup_created', 'target': 'awg31-20260102T000000Z-bbbbbbbbbb.tar.gz.gpg'})
    bot.tick()
    assert served == ['awg31-20260102T000000Z-bbbbbbbbbb.tar.gz.gpg']
    assert [(m, chat, name, content) for m, chat, name, content, _ in api.files] == \
        [('sendDocument', ADMIN, 'awg31-20260102T000000Z-bbbbbbbbbb.tar.gz.gpg', b'GPG-BYTES')], 'administrators only, not viewers'


def test_digest_is_sent_once_a_day_after_nine_with_traffic_since_the_last_one(env, monkeypatch):
    bot, api, controller, now = env
    bot.config['digest'] = 'daily'
    monkeypatch.setenv('TZ', 'UTC')
    time.tzset()
    now[0] = datetime(2026, 6, 2, 8, 0, tzinfo=timezone.utc).timestamp()
    controller.clients['awg0']['bob'] = {**controller.new_client('10.8.0.3'), 'used_bytes': 100}
    bot.tick()
    assert not any('Digest' in text for text in notifications(api, 0)), 'not before nine'
    now[0] += 3600 + 60
    bot.tick()
    first = [text for text in notifications(api, 0) if 'Digest' in text]
    assert len(first) == 2 and 'awg0' in first[0] and '2 clients' in first[0] and 'next digest' in first[0]
    now[0] += 3600
    bot.tick()
    assert len([text for text in notifications(api, 0) if 'Digest' in text]) == 2, 'once a day'
    controller.clients['awg0']['bob']['used_bytes'] = 100 + 3 * 1024 ** 3
    controller.clients['awg0']['alice']['used_bytes'] = 1024 ** 3
    controller.clients['awg0']['alice']['expires_at'] = (datetime.fromtimestamp(now[0], timezone.utc) + timedelta(days=5)).isoformat()
    now[0] += 86400
    start = len(api.calls)
    bot.tick()
    digest = next(text for text in notifications(api, start) if 'Digest' in text)
    assert 'Client traffic: 4.0 GiB' in digest and digest.index('bob') < digest.index('alice (awg0)')
    assert 'Expire within 7 days: alice' in digest
    # Weekly: only on Mondays (2026-06-08 is a Monday).
    bot.config['digest'] = 'weekly'
    now[0] = datetime(2026, 6, 6, 10, 0, tzinfo=timezone.utc).timestamp()
    start = len(api.calls)
    bot.tick()
    assert not any('Digest' in text for text in notifications(api, start))
    now[0] = datetime(2026, 6, 8, 10, 0, tzinfo=timezone.utc).timestamp()
    bot.tick()
    assert any('for the last week' in text for text in notifications(api, start))


def test_admin_sets_a_speed_limit_from_the_bot(env):
    bot, api, controller, _ = env
    bot.handle_update(press('ca:awg0:alice:speed'))
    assert 'cs:awg0:alice:20' in api.buttons()
    bot.handle_update(press('cs:awg0:alice:20'))
    assert controller.clients['awg0']['alice']['speed_limit_mbit'] == 20 and 'up to 20 Mbit/s' in api.texts()[-1]
    bot.handle_update(press('cs:awg0:alice:7'))
    assert controller.clients['awg0']['alice']['speed_limit_mbit'] == 20 and 'bad request' in api.texts()[-1]


def test_sudo_lists_keep_console_only_operations_out():
    script = f'. {ROOT}/scripts/sudoers.sh; printf "%s\\n" "${{AWG31_SUDO_COMMANDS[@]}}" "${{AWG31_BOT_SUDO_COMMANDS[@]}}"'
    allowed = set(subprocess.run(['bash', '-c', script], capture_output=True, text=True, check=True).stdout.split())
    assert not allowed & {'totp-reset', 'backup-encryption-set', 'password-reset', 'init', 'sample-all', 'backup-run'}
    assert {'totp-enable', 'totp-disable', 'telegram-status', 'telegram-set', 'add-batch', 'backup-encryption'} <= allowed


# ------------------------------------------------------------------ passphrase change, remote storage, next kernel
@needs_gpg
def test_changing_the_passphrase_reencrypts_what_the_old_one_opens(backups):
    admin, manager, tmp = backups
    admin.backup_encryption_set({'passphrase': 'the first passphrase 111'})
    first = admin.create_backup(manager)['name']
    admin.backup_encryption_set({'passphrase': 'the second passphrase 222'})
    second = admin.create_backup(manager)['name']
    plain = None
    with pytest.raises(ValueError):
        admin.backup_encryption_change({'passphrase': 'short'})
    reply = admin.backup_encryption_change({'passphrase': 'the third passphrase 333'})
    assert reply['reencrypted'] == 1 and reply['skipped'] == [first] and reply['passphrase'] is None
    key = tmp / 'etc' / 'backup-passphrase'
    assert key.read_text().strip() == 'the third passphrase 333' and key.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in (tmp / 'full').iterdir()) == sorted([first, second]), 'no temporary files left'
    home = tmp / 'gnupg2'
    home.mkdir(mode=0o700)

    def opens(name, secret):
        return subprocess.run(['gpg', '--homedir', str(home), '--batch', '--quiet', '--pinentry-mode', 'loopback', '--passphrase', secret,
                               '--decrypt', str(tmp / 'full' / name)], capture_output=True).returncode == 0
    assert opens(second, 'the third passphrase 333') and not opens(second, 'the second passphrase 222')
    assert opens(first, 'the first passphrase 111'), 'an archive of an earlier passphrase is left untouched'
    generated = admin.backup_encryption_change({})
    assert generated['reencrypted'] == 1 and opens(second, generated['passphrase'])


@needs_gpg
def test_failed_passphrase_change_leaves_everything_as_it_was(backups, monkeypatch):
    admin, manager, tmp = backups
    admin.backup_encryption_set({'passphrase': 'the first passphrase 111'})
    names = [admin.create_backup(manager)['name']]
    time.sleep(1.1)
    names.append(admin.create_backup(manager)['name'])
    before = {name: (tmp / 'full' / name).read_bytes() for name in names}
    real, calls = admin._gpg, []

    def failing(args, **kwargs):
        calls.append(args)
        if '--symmetric' in args and len([c for c in calls if '--symmetric' in c]) == 2:
            raise ValueError('disk full')
        return real(args, **kwargs)
    monkeypatch.setattr(admin, '_gpg', failing)
    with pytest.raises(ValueError, match='disk full'):
        admin.backup_encryption_change({'passphrase': 'the second passphrase 222'})
    assert (tmp / 'etc' / 'backup-passphrase').read_text().strip() == 'the first passphrase 111'
    assert {p.name: p.read_bytes() for p in (tmp / 'full').iterdir()} == before
    assert sorted(p.name for p in (tmp / 'etc').iterdir()) == ['backup-passphrase']


def test_s3_signature_matches_the_aws_documentation_example():
    admin = load_admin('admin_sigv4')
    empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    header = admin.s3_authorization('GET', 'examplebucket.s3.amazonaws.com', '/test.txt',
                                    {'Host': 'examplebucket.s3.amazonaws.com', 'Range': 'bytes=0-9', 'x-amz-content-sha256': empty,
                                     'x-amz-date': '20130524T000000Z'}, empty, 'us-east-1', 'AKIAIOSFODNN7EXAMPLE',
                                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', '20130524T000000Z')
    assert header == ('AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,'
                      'SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,'
                      'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41')


@pytest.fixture
def remote(backups, monkeypatch):
    admin, manager, tmp = backups
    monkeypatch.setenv('AWG31_BACKUP_REMOTE', str(tmp / 'etc' / 'backup-remote.json'))
    return admin, manager, tmp


S3 = {'type': 's3', 'endpoint': 'http://127.0.0.1:1', 'region': 'us-east-1', 'bucket': 'my-backups', 'prefix': 'vpn/',
      'access_key': 'AKIAEXAMPLE', 'secret_key': 'very-secret-key-123'}


@needs_gpg
def test_remote_storage_needs_encryption_and_never_reports_its_keys(remote):
    admin, manager, tmp = remote
    with pytest.raises(ValueError, match='encryption'):
        admin.backup_remote_set(dict(S3))
    assert admin.backup_remote_status() == {'configured': False}
    admin.backup_encryption_set({'passphrase': 'remote test passphrase 1'})
    for bad in ({**S3, 'endpoint': 'ftp://x'}, {**S3, 'bucket': 'Bad Bucket'}, {**S3, 'prefix': 'no-slash'}, {**S3, 'secret_key': ''},
                {'type': 'webdav'}, {'type': 'sftp', 'host': 'h;rm', 'user': 'u', 'path': '/'},
                {'type': 'sftp', 'host': 'h', 'user': 'u', 'path': '/a b'}, {'type': 'sftp', 'host': 'h', 'user': 'Root!', 'path': '/'},
                {'type': 'sftp', 'host': 'h', 'user': 'u', 'path': '/', 'port': '70000'}):
        with pytest.raises(ValueError):
            admin.backup_remote_set(bad)
    admin.backup_remote_set(dict(S3))
    file = tmp / 'etc' / 'backup-remote.json'
    assert file.stat().st_mode & 0o777 == 0o600
    status = admin.backup_remote_status()
    assert status == {'configured': True, 'type': 's3', 'target': 's3://my-backups/vpn/ (http://127.0.0.1:1)'}
    assert 'very-secret' not in json.dumps(status) and 'AKIAEXAMPLE' not in json.dumps(status)
    admin.backup_remote_set({'off': True})
    assert not file.exists() and admin.backup_remote_status() == {'configured': False}


class S3Stub(BaseHTTPRequestHandler):
    stored, reject = {}, False

    def do_PUT(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        good = (self.headers['x-amz-content-sha256'] == hashlib.sha256(body).hexdigest()
                and self.headers['Authorization'].startswith('AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/')
                and 'SignedHeaders=host;x-amz-content-sha256;x-amz-date' in self.headers['Authorization'])
        if S3Stub.reject or not good:
            reply = b'<Error><Code>SignatureDoesNotMatch</Code></Error>'
            self.send_response(403)
        else:
            S3Stub.stored[self.path] = body
            reply = b''
            self.send_response(200)
        self.send_header('Content-Length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


@needs_gpg
def test_new_backups_are_uploaded_to_s3_and_a_failure_does_not_fail_the_backup(remote):
    admin, manager, tmp = remote
    S3Stub.stored, S3Stub.reject = {}, False
    server = HTTPServer(('127.0.0.1', 0), S3Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        plain = admin.after_backup(admin.create_backup(manager))
        assert 'uploaded' not in plain, 'nothing is configured yet'
        admin.backup_encryption_set({'passphrase': 'remote test passphrase 1'})
        admin.backup_remote_set({**S3, 'endpoint': f'http://127.0.0.1:{server.server_port}'})
        assert admin.backup_remote_test()['file'] == 'awg31-connection-test.txt'
        result = admin.after_backup(admin.create_backup(manager))
        assert result['uploaded'] is True
        key = f"/my-backups/vpn/{result['name']}"
        assert S3Stub.stored[key] == (tmp / 'full' / result['name']).read_bytes() and b'PANEL-SECRET' not in S3Stub.stored[key]
        with pytest.raises(ValueError, match='encrypted'):
            admin.upload_backup(plain['name'])
        assert not any(plain['name'] in path for path in S3Stub.stored), 'a plain archive never leaves the server'
        S3Stub.reject = True
        time.sleep(1.1)
        failed = admin.after_backup(admin.create_backup(manager))
        assert failed['ok'] is True and failed['uploaded'] is False and 'SignatureDoesNotMatch' in failed['upload_error']
        assert (tmp / 'full' / failed['name']).is_file(), 'the local backup is kept'
        events = [json.loads(line) for line in (tmp / 'audit.jsonl').read_text().splitlines()]
        assert [e['event'] for e in events if e['event'].startswith('backup_upload')] == ['backup_uploaded', 'backup_upload_failed']
        assert events[-1]['target'].startswith(failed['name'] + ': S3 answered 403')
        assert 'very-secret' not in (tmp / 'audit.jsonl').read_text()
    finally:
        server.shutdown()


@needs_gpg
def test_sftp_upload_uses_its_own_key_and_pins_the_host_key(remote, monkeypatch):
    admin, manager, tmp = remote
    if shutil.which('ssh-keygen') is None:
        pytest.skip('OpenSSH client is not installed')
    monkeypatch.setattr(admin, 'shutil_which', lambda name: '/usr/bin/' + name)
    admin.backup_encryption_set({'passphrase': 'remote test passphrase 1'})
    reply = admin.backup_remote_set({'type': 'sftp', 'host': 'backup.example.net', 'port': '2222', 'user': 'vpnbackup', 'path': '/srv/backups/'})
    assert reply['public_key'].startswith('ssh-ed25519 ') and reply['target'] == 'sftp://vpnbackup@backup.example.net:2222/srv/backups/'
    key = tmp / 'etc' / 'backup-remote.key'
    assert key.stat().st_mode & 0o777 == 0o600
    again = admin.backup_remote_set({'type': 'sftp', 'host': 'backup.example.net', 'user': 'vpnbackup', 'path': '/srv/backups'})
    assert again['public_key'] == reply['public_key'], 'the key is kept when the settings change'
    name = admin.create_backup(manager)['name']
    seen = {}
    real_run = subprocess.run

    def fake_run(argv, **kwargs):
        if argv[0] != 'sftp':
            return real_run(argv, **kwargs)
        seen.update(argv=argv, batch=kwargs['input'])
        return type('P', (), {'returncode': seen.get('rc', 0), 'stdout': '', 'stderr': 'Permission denied (publickey).\n'})()
    monkeypatch.setattr(admin.subprocess, 'run', fake_run)
    admin.upload_backup(name)
    argv = seen['argv']
    assert argv[-1] == 'vpnbackup@backup.example.net' and argv[argv.index('-P') + 1] == '22' and argv[argv.index('-i') + 1] == str(key)
    for option in ('BatchMode=yes', 'IdentitiesOnly=yes', 'StrictHostKeyChecking=accept-new',
                   f'UserKnownHostsFile={tmp / "etc" / "backup-remote.known_hosts"}'):
        assert option in argv
    assert seen['batch'] == f'put "{tmp / "full" / name}" "/srv/backups/{name}"\n'
    seen['rc'] = 1
    with pytest.raises(ValueError, match='Permission denied'):
        admin.upload_backup(name)


def test_kernel_check_reports_a_new_kernel_without_the_module(tmp_path):
    modules, fake = tmp_path / 'modules', tmp_path / 'bin'
    fake.mkdir()
    for version in ('6.8.0-40-generic', '6.8.0-51-generic'):
        (modules / version / 'kernel').mkdir(parents=True)
    (fake / 'uname').write_text('#!/bin/sh\necho 6.8.0-40-generic\n')
    (fake / 'modinfo').write_text(f'#!/bin/sh\n[ -e "{tmp_path}/built-$2" ] && echo 1.0.0 || exit 1\n')
    (fake / 'dkms').write_text(f'#!/bin/sh\necho "$@" >> {tmp_path}/dkms.log\n[ -e {tmp_path}/dkms-works ] && [ "$1" = install ] && touch "{tmp_path}/built-$7"\nexit 0\n')
    (fake / 'lsmod').write_text('#!/bin/sh\necho "amneziawg 1 0"\n')
    (fake / 'mokutil').write_text('#!/bin/sh\nexit 1\n')
    for tool in fake.iterdir():
        tool.chmod(0o755)
    (tmp_path / 'built-6.8.0-40-generic').touch()
    state = tmp_path / 'next-kernel'
    env = {'PATH': f'{fake}:/usr/bin:/bin', 'AWG31_NEXT_KERNEL': str(state), 'AWG31_MODULES_DIR': str(modules)}

    def check():
        return subprocess.run(['bash', str(ROOT / 'scripts/kernel-check.sh')], env=env, capture_output=True, text=True)
    run = check()
    assert run.returncode == 1 and state.read_text() == 'missing 6.8.0-51-generic\n' and 'will not start' in run.stderr
    assert 'install -m amneziawg -v 1.0.0 -k 6.8.0-51-generic' in (tmp_path / 'dkms.log').read_text(), 'one rebuild is attempted'
    admin = load_admin('admin_next_kernel')
    os.environ['AWG31_NEXT_KERNEL'] = str(state)
    try:
        assert admin.next_kernel_state() == {'ok': False, 'output': '6.8.0-51-generic'}
        (tmp_path / 'dkms-works').touch()                       # this time DKMS builds the module
        run = check()
        assert run.returncode == 0 and state.read_text() == 'ok 6.8.0-51-generic\n'
        assert admin.next_kernel_state() == {'ok': True, 'output': '6.8.0-51-generic'}
        (fake / 'uname').write_text('#!/bin/sh\necho 6.8.0-51-generic\n')      # rebooted into the new kernel
        assert check().returncode == 0 and state.read_text() == '\n'
        assert admin.next_kernel_state() == {'ok': True, 'output': ''}
        state.write_text('missing ../../etc; rm -rf /\n')
        assert admin.next_kernel_state()['ok'] is True, 'only a plain version string is believed'
    finally:
        del os.environ['AWG31_NEXT_KERNEL']


def test_bot_warns_once_about_a_kernel_without_the_module_and_about_failed_uploads(env):
    bot, api, controller, _ = env
    upcoming = {'ok': True, 'output': ''}
    real = controller.__class__.__call__

    def fake(command, data=None):
        reply = real(controller, command, data)
        if command == 'diagnostics':
            reply['next_kernel'] = dict(upcoming)
        return reply
    bot.ctl = fake
    bot.tick()
    assert notifications(api, 0) == []
    upcoming.update(ok=False, output='7.0.0-50-generic')
    bot.tick()
    bot.tick()
    sent = notifications(api, 0)
    assert len(sent) == 2 and all('7.0.0-50-generic' in text and 'sudo awg31 update' in text for text in sent), 'admin and viewer, once'
    bot.handle_update(message('/status'))
    assert '7.0.0-50-generic' in api.texts()[-1]
    upcoming.update(ok=True, output='7.0.0-50-generic')
    start = len(api.calls)
    bot.tick()
    assert all('can be rebooted' in text for text in notifications(api, start)) and len(notifications(api, start)) == 2
    start = len(api.calls)
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'backup_upload_failed', 'target': 'awg31-x.tar.gz.gpg: S3 answered 403'})
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'backup_uploaded', 'target': 'awg31-y.tar.gz.gpg'})
    bot.tick()
    sent = notifications(api, start)
    assert len(sent) == 2 and all('S3 answered 403' in text for text in sent), 'success is silent, failure is reported'


def test_backups_page_shows_the_remote_storage_and_the_kernel_warning(ui):
    app, client, calls = ui
    assert 'sudo awg31 backup-remote s3' in client.get('/maintenance?tab=backups').text
    original = app.ctl

    def fake(op, data=None):
        if op == 'backup-remote':
            return {'configured': True, 'type': 's3', 'target': 's3://my-backups/vpn/ (https://s3.example.com)'}
        reply = original(op, data)
        if op == 'diagnostics':
            reply['next_kernel'] = {'ok': False, 'output': '7.0.0-50-generic'}
        return reply
    app.ctl = fake
    assert 's3://my-backups/vpn/' in client.get('/maintenance?tab=backups').text
    system = client.get('/maintenance?tab=system').text
    assert '7.0.0-50-generic' in system and 'sudo awg31 update' in system


def test_batch_form_is_marked_for_the_download_script():
    assert 'data-batch-download' in (ROOT / 'src/web.py').read_text() and 'form[data-batch-download]' in (ROOT / 'src/panel.js').read_text()


def test_missing_tc_does_not_break_saving_a_client(db, monkeypatch):
    con, call, _ = db
    call(ctl.clients_add, {'name': 'c1'})

    def no_tc(argv, *args, **kwargs):
        if argv[0] == 'tc':
            raise FileNotFoundError(2, 'No such file or directory', 'tc')
        return type('P', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()
    monkeypatch.setattr(ctl.subprocess, 'run', no_tc)
    ctl.shape_now(ctl.get_settings(con), [{**ctl.peer_rows(con)[0], 'speed_limit_mbit': 10}])
