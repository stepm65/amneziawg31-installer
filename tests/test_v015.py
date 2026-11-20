"""0.15: Telegram invitations, key replacement, TOTP recovery codes, bulk actions and the CSV export."""
import csv
import hashlib
import io
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader
from io import StringIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from test_peer_routes_i import profile
from test_password_guards import admin, totp, PASSWORD  # noqa: F401  (pytest fixture)
from test_telegram_bot import FakeApi, FakeController, bot_module, message, press, ADMIN, STRANGER, TOKEN
from test_workflows import ui, token  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
ctl = SourceFileLoader('awg31_v015_test', str(ROOT / 'src/awg31ctl')).load_module()


# ------------------------------------------------------------------ controller
@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, 'DB', tmp_path / 'state.sqlite3')
    monkeypatch.setattr(ctl, 'CONF', tmp_path / 'awg0.conf')
    monkeypatch.setattr(ctl, 'IFACE', 'awg0')
    monkeypatch.setenv('AWG31_PEER_BACKUPS', str(tmp_path / 'backups'))
    con = ctl.get_conn(True)
    ctl.put_settings(con, profile())
    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    rows = (('alpha', 1, '', '', 0, 0), ('beta', 0, 'expired', past, 0, 0), ('gamma', 0, 'quota', '', 10, 50),
            ('delta', 1, '', future, 0, 0), ('omega', 0, 'manual', '', 0, 0))
    for n, (name, enabled, reason, expires, limit, used) in enumerate(rows, 2):
        con.execute('''INSERT INTO clients (name,ip,private_key,public_key,psk,enabled,created_at,disabled_reason,expires_at,
                       traffic_limit_bytes,used_bytes,telegram_id,last_rx,last_tx) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (name, f'10.77.10.{n}', 'old-private', f'old-public-{name}', 'old-psk', enabled, f'2026-11-1{n}',
                     reason, expires, limit, used, '123456789' if name == 'alpha' else '', 500, 600))
    con.commit()
    applied = []
    keys = iter(range(1000))
    monkeypatch.setattr(ctl, 'apply', lambda cfg, c, **k: applied.append(True))
    monkeypatch.setattr(ctl, 'keygen', lambda: f'new-private-{next(keys)}')
    monkeypatch.setattr(ctl, 'pubkey', lambda private: private.replace('private', 'public'))
    monkeypatch.setattr(ctl, 'pskgen', lambda: 'new-psk')
    monkeypatch.setattr(ctl.subprocess, 'run', lambda *a, **k: types.SimpleNamespace(returncode=1, stdout='', stderr=''))

    def call(fn, payload):
        monkeypatch.setattr(sys, 'stdin', StringIO(json.dumps(payload)))
        return fn(con)
    yield con, call, applied
    con.close()


def row(con, name):
    return dict(con.execute('SELECT * FROM clients WHERE name=?', (name,)).fetchone())


def test_rekey_replaces_only_the_keys(db):
    con, call, applied = db
    before = row(con, 'alpha')
    con.execute('UPDATE clients SET exported_hash=? WHERE name=?',
                (ctl.config_fingerprint(ctl.client_config(profile(), before, ctl.peer_rows(con))), 'alpha'))
    con.commit()
    result = call(ctl.client_rekey, {'name': 'alpha'})
    after = row(con, 'alpha')
    assert result['ok'] and 'PrivateKey = new-private-0' in result['config'] and applied
    assert (after['private_key'], after['public_key'], after['psk']) == ('new-private-0', 'new-public-0', 'new-psk')
    for key in ('ip', 'telegram_id', 'expires_at', 'traffic_limit_bytes', 'used_bytes', 'created_at', 'enabled'):
        assert after[key] == before[key], key
    assert (after['last_rx'], after['last_tx']) == (0, 0)       # the new key's counters start from zero
    stale = {c['name']: c['config_stale'] for c in ctl.get_status(con, True)['clients']}
    assert stale['alpha'] is True
    with pytest.raises(ValueError):
        call(ctl.client_rekey, {'name': 'ghost'})


def test_bulk_enable_disable_extend_limit(db):
    con, call, applied = db
    names = ['alpha', 'beta', 'gamma', 'delta', 'omega']
    result = call(ctl.client_batch, {'names': names, 'action': 'enable'})
    assert result['enabled'] == ['omega']
    assert result['skipped'] == {'alpha': 'already', 'beta': 'expired', 'gamma': 'quota', 'delta': 'already'}
    result = call(ctl.client_batch, {'names': ['alpha', 'omega'], 'action': 'disable'})
    assert result['disabled'] == ['alpha', 'omega'] and row(con, 'alpha')['disabled_reason'] == 'manual'
    # Extending counts from the current end, or from today when it is over; an expired client comes back.
    result = call(ctl.client_batch, {'names': ['beta', 'delta', 'alpha'], 'action': 'extend', 'days': 30})
    assert result['changed'] == ['beta', 'delta'] and result['enabled'] == ['beta'] and result['skipped'] == {'alpha': 'no_expiry'}
    today = datetime.now(timezone.utc)
    assert datetime.fromisoformat(row(con, 'beta')['expires_at']).date() == (today + timedelta(days=30)).date()
    assert datetime.fromisoformat(row(con, 'delta')['expires_at']).date() == (today + timedelta(days=35)).date()
    # A larger quota brings back a client stopped by the old one; a smaller one does not.
    assert call(ctl.client_batch, {'names': ['gamma'], 'action': 'limit', 'traffic_limit_bytes': 40})['enabled'] == []
    assert row(con, 'gamma')['traffic_limit_bytes'] == 40 and not row(con, 'gamma')['enabled']
    assert call(ctl.client_batch, {'names': ['gamma'], 'action': 'limit', 'traffic_limit_bytes': 0})['enabled'] == ['gamma']
    for bad in ({'names': names, 'action': 'purge'}, {'names': ['ghost'], 'action': 'enable'},
                {'names': names, 'action': 'extend', 'days': 0}, {'names': names, 'action': 'limit', 'traffic_limit_bytes': -1},
                {'names': ['../x'], 'action': 'enable'}):
        with pytest.raises(ValueError):
            call(ctl.client_batch, bad)


def test_invitations_are_one_time_hashed_and_expire(db):
    con, call, _ = db
    first = call(ctl.client_invite, {'name': 'delta', 'days': 7, 'export': True})
    assert ctl.INVITE_RE.fullmatch(first['code'])
    stored = row(con, 'delta')
    assert first['code'] not in json.dumps(stored) and stored['invite_hash'] == hashlib.sha256(first['code'].encode()).hexdigest()
    shown = call(lambda c: ctl.clients_action(c, 'download'), {'name': 'delta'})
    assert shown['invite_expires'] == first['expires_at'] and 'invite_hash' not in shown
    second = call(ctl.client_invite, {'name': 'delta', 'days': 1, 'export': False})          # replaces the first
    assert call(ctl.invite_redeem, {'code': first['code'], 'telegram_id': '555000111'}) == {'found': False}
    used = call(ctl.invite_redeem, {'code': second['code'], 'telegram_id': '555000111'})
    assert used == {'found': True, 'name': 'delta', 'export': False}
    assert (row(con, 'delta')['telegram_id'], row(con, 'delta')['owner_export'], row(con, 'delta')['invite_hash']) == ('555000111', 0, '')
    assert call(ctl.invite_redeem, {'code': second['code'], 'telegram_id': '555000222'}) == {'found': False}
    # An expired code is refused and forgotten.
    third = call(ctl.client_invite, {'name': 'alpha', 'days': 1, 'export': True})
    con.execute("UPDATE clients SET invite_expires=? WHERE name='alpha'", ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),))
    assert call(ctl.invite_redeem, {'code': third['code'], 'telegram_id': '555000111'}) == {'found': False, 'expired': True}
    assert row(con, 'alpha')['invite_hash'] == '' and row(con, 'alpha')['telegram_id'] == '123456789'
    fourth = call(ctl.client_invite, {'name': 'alpha', 'days': 30, 'export': True})
    call(ctl.client_invite, {'name': 'alpha', 'action': 'revoke'})
    assert call(ctl.invite_redeem, {'code': fourth['code'], 'telegram_id': '555000111'}) == {'found': False}
    for bad in ({'name': 'alpha', 'days': 31}, {'name': 'alpha', 'days': 0}, {'name': 'ghost'}):
        with pytest.raises(ValueError):
            call(ctl.client_invite, bad)
    for bad in ({'code': 'short', 'telegram_id': '555000111'}, {'code': fourth['code'], 'telegram_id': '12'},
                {'code': fourth['code'] + '!', 'telegram_id': '555000111'}):
        with pytest.raises(ValueError):
            call(ctl.invite_redeem, bad)


def test_new_operations_are_wired_and_allowed_to_the_right_users():
    mgr = (ROOT / 'src/awg31mgr').read_text()
    from test_telegram_bot import sudo_list
    panel, bot = sudo_list('AWG31_SUDO_COMMANDS'), sudo_list('AWG31_BOT_SUDO_COMMANDS')
    for op in ('client-rekey', 'client-batch', 'client-invite', 'invite-redeem', 'totp-recovery-new', 'totp-recovery-use'):
        assert f"'{op}'" in mgr, op
    assert {'client-rekey', 'client-batch', 'client-invite', 'totp-recovery-new', 'totp-recovery-use'} <= panel
    assert 'invite-redeem' not in panel                       # only the bot turns a code into an owner
    assert {'client-rekey', 'client-invite', 'invite-redeem'} <= bot
    assert not {'client-batch', 'totp-recovery-new', 'totp-recovery-use'} & bot


# ------------------------------------------------------------------ recovery codes
def test_recovery_codes_work_once_and_need_the_password(admin):
    module, tmp = admin
    secret = 'A' * 32
    result = module.totp_enable({'password': PASSWORD, 'secret': secret, 'code': totp(secret)})
    codes = result['recovery_codes']
    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(len(c) == 11 and c[5] == '-' and not set(c) & set('01lio') for c in codes)
    stored = json.loads((tmp / 'auth.json').read_text())
    assert not any(code in json.dumps(stored) or code.replace('-', '') in json.dumps(stored) for code in codes)
    with pytest.raises(ValueError, match='password'):
        module.totp_recovery_use({'password': 'wrong', 'code': codes[0]})
    assert module.totp_recovery_use({'password': PASSWORD, 'code': codes[0].upper().replace('-', ' ')}) == {'ok': True, 'left': 9}
    with pytest.raises(ValueError, match='recovery code'):
        module.totp_recovery_use({'password': PASSWORD, 'code': codes[0]})
    with pytest.raises(ValueError, match='code'):
        module.totp_recovery_new({'password': PASSWORD, 'code': '000000'})
    fresh = module.totp_recovery_new({'password': PASSWORD, 'code': totp(secret)})['recovery_codes']
    with pytest.raises(ValueError):
        module.totp_recovery_use({'password': PASSWORD, 'code': codes[1]})         # the old set is gone
    assert module.totp_recovery_use({'password': PASSWORD, 'code': fresh[3]})['left'] == 9
    audit = (tmp / 'audit.jsonl').read_text()
    assert 'totp_recovery_used' in audit and 'totp_recovery_new' in audit
    module.totp_disable({'password': PASSWORD, 'code': totp(secret)})
    assert 'totp_recovery' not in json.loads((tmp / 'auth.json').read_text())


def test_login_accepts_a_recovery_code_through_the_helper(ui):
    app, client, calls = ui
    auth = json.loads(app.AUTH_FILE.read_text())
    auth['totp_secret'] = 'A' * 32
    auth['totp_recovery'] = ['x']
    app.AUTH_FILE.write_text(json.dumps(auth))
    client.cookies.clear()
    form = client.get('/login').text
    assert 'abcde-fghjk' in form and 'maxlength="11"' in form
    answers = {'ok': True}
    real = app.ctl

    def fake(op, data=None):
        if op == 'totp-recovery-use':
            calls.append((op, dict(data)))
            if not answers['ok']:
                raise RuntimeError('Incorrect recovery code')
            return {'ok': True, 'left': 4}
        return real(op, data)
    app.ctl = fake
    assert client.post('/login', data={'password': 'correct-test-password', 'code': 'abcde-fghjk'},
                       follow_redirects=False).status_code == 303
    assert ('totp-recovery-use', {'password': 'correct-test-password', 'code': 'abcde-fghjk'}) in calls
    client.cookies.clear()
    answers['ok'] = False
    assert client.post('/login', data={'password': 'correct-test-password', 'code': 'abcde-fghjk'},
                       follow_redirects=False).status_code == 200
    # Without the password the helper is not even asked.
    before = len(calls)
    client.post('/login', data={'password': 'wrong-password-123', 'code': 'abcde-fghjk'})
    assert not [c for c in calls[before:] if c[0] == 'totp-recovery-use']


def test_enabling_totp_shows_the_codes_once(ui):
    app, client, calls = ui
    real = app.ctl

    def fake(op, data=None):
        if op == 'totp-enable':
            return {'ok': True, 'recovery_codes': ['abcde-fghjk', 'mnpqr-stuvw']}
        if op == 'totp-recovery-new':
            return {'ok': True, 'recovery_codes': ['zzzzz-yyyyy']}
        return real(op, data)
    app.ctl = fake
    page = client.get('/maintenance?tab=security')
    shown = client.post('/maintenance/totp/enable', data={'csrf': token(page), 'password': 'x', 'code': '123456', 'secret': 'A' * 32})
    assert shown.status_code == 200 and 'abcde-fghjk' in shown.text and 'mnpqr-stuvw' in shown.text
    assert 'href="/login"' in shown.text
    assert client.get('/maintenance?tab=security', follow_redirects=False).status_code in (302, 303, 401)    # signed out
    assert client.post('/login', data={'password': 'correct-test-password'}).status_code == 200
    again = client.get('/maintenance?tab=security')
    new = client.post('/maintenance/totp-recovery', data={'csrf': token(again), 'password': 'x', 'code': '123456'})
    assert 'zzzzz-yyyyy' in new.text and 'href="/maintenance?tab=security"' in new.text


def test_security_tab_counts_the_codes(ui):
    app, client, _ = ui
    auth = json.loads(app.AUTH_FILE.read_text())
    auth['totp_secret'] = 'A' * 32
    for codes, text in (([], 'Резервных кодов нет'), (['a', 'b'], 'осталось мало'), (['x'] * 9, 'осталось: 9 из 10')):
        auth['totp_recovery'] = codes
        app.AUTH_FILE.write_text(json.dumps(auth))
        page = client.get('/maintenance?tab=security').text
        assert text in page and 'action="/maintenance/totp-recovery"' in page


# ------------------------------------------------------------------ panel: client page, bulk, CSV
def detail_ui(ui, bot):
    app, client, calls = ui
    real = app.ctl

    def fake(op, data=None):
        if op == 'telegram-status':
            return bot
        if op == 'download':
            return {**real(op, data), 'name': 'alpha', 'telegram_id': '123456789', 'invite_expires': '', 'server_ip': '10.77.10.1',
                    'subnet': '10.77.10.0/24', 'client_public_key': 'B' * 44}
        if op == 'client-invite':
            calls.append((op, dict(data)))
            return {'ok': True, 'code': 'C' * 24, 'expires_at': '2026-11-27T10:00:00+00:00', 'export': True}
        if op == 'client-batch':
            calls.append((op, dict(data)))
            return {'ok': True, 'changed': ['alpha'], 'enabled': ['alpha'], 'disabled': [],
                    'skipped': {'beta': 'expired', 'gamma': 'already', 'evil<b>': 'already'}}
        return real(op, data)
    app.ctl = fake
    return app, client, calls


def test_client_page_offers_invitation_and_rekey(ui):
    app, client, calls = detail_ui(ui, {'configured': False})
    page = client.get('/servers/awg0/clients/alpha').text
    assert 'Telegram-бота, а он не подключён' in page and 'href="/maintenance?tab=telegram"' in page
    assert 'clients/alpha/rekey"' in page and 'data-confirm=' in page.split('clients/alpha/rekey"')[1][:20]
    app, client, calls = detail_ui(ui, {'configured': True, 'username': 'my_vpn_bot'})
    page = client.get('/servers/awg0/clients/alpha')
    assert 'clients/alpha/invite"' in page.text and 'Telegram ID 123456789' in page.text
    made = client.post('/servers/awg0/clients/alpha/invite', data={'csrf': token(page), 'days': '30', 'export': '1'})
    assert 'https://t.me/my_vpn_bot?start=' + 'C' * 24 in made.text and 'data:image/png;base64,' in made.text
    assert ('client-invite', {'name': 'alpha', 'days': 30, 'export': True, 'interface': 'awg0'}) in calls
    assert client.post('/servers/awg0/clients/alpha/invite', data={'csrf': token(page), 'days': '5'}).status_code == 422
    assert client.post('/servers/awg0/clients/alpha/invite', data={'csrf': 'bad', 'days': '7'}).status_code == 403
    revoked = client.post('/servers/awg0/clients/alpha/invite/revoke', data={'csrf': token(page)}, follow_redirects=False)
    assert revoked.status_code == 303 and ('client-invite', {'name': 'alpha', 'action': 'revoke', 'interface': 'awg0'}) in calls
    rekeyed = client.post('/servers/awg0/clients/alpha/rekey', data={'csrf': token(page)}, follow_redirects=False)
    assert rekeyed.headers['location'] == '/servers/awg0/clients/alpha?rekeyed=1'
    assert ('client-rekey', {'name': 'alpha', 'interface': 'awg0'}) in calls
    assert 'Ключ перевыпущен' in client.get(rekeyed.headers['location']).text


def test_bulk_actions_and_their_report(ui):
    app, client, calls = detail_ui(ui, {'configured': False})
    listing = client.get('/servers/awg0/clients')
    for marker in ('id="bulk-enable-form"', 'id="bulk-disable-form"', 'id="bulk-extend-modal"', 'id="bulk-limit-modal"',
                   'data-needs-selection', 'href="/servers/awg0/export/clients.csv"'):
        assert marker in listing.text, marker
    csrf = token(listing)
    done = client.post('/servers/awg0/clients/bulk-action', data={'csrf': csrf, 'action': 'extend', 'days': '30', 'names': ['alpha', 'beta']},
                       follow_redirects=False)
    assert done.status_code == 303 and ('client-batch', {'names': ['alpha', 'beta'], 'action': 'extend', 'days': 30, 'interface': 'awg0'}) in calls
    report = client.get(done.headers['location']).text
    assert 'Продлено клиентов: 1' in report and 'Не включены, истёк срок' in report and 'beta' in report
    assert 'evil<b>' not in report
    client.post('/servers/awg0/clients/bulk-action', data={'csrf': csrf, 'action': 'limit', 'quota_gib': '1.5', 'names': 'alpha'})
    assert ('client-batch', {'names': ['alpha'], 'action': 'limit', 'traffic_limit_bytes': int(1.5 * 1024 ** 3), 'interface': 'awg0'}) in calls
    for data, code in (({'csrf': csrf, 'action': 'purge', 'names': 'alpha'}, 422), ({'csrf': csrf, 'action': 'enable'}, 422),
                       ({'csrf': csrf, 'action': 'enable', 'names': '../x'}, 422), ({'csrf': 'bad', 'action': 'enable', 'names': 'alpha'}, 403),
                       ({'csrf': csrf, 'action': 'limit', 'quota_gib': '-1', 'names': 'alpha'}, 422)):
        assert client.post('/servers/awg0/clients/bulk-action', data=data).status_code == code


def test_csv_export_has_no_keys_and_no_formulas(ui):
    app, client, calls = ui
    real = app.ctl

    def fake(op, data=None):
        if op == 'list':
            state = real(op, data)
            state['clients'] = [{'name': 'alpha', 'ip': '10.77.10.2', 'enabled': True, 'comment': '=HYPERLINK("x")',
                                 'public_key': 'PUB', 'private_key': 'SECRET', 'traffic_limit_bytes': 2 * 1024 ** 3,
                                 'used_bytes': 1024 ** 3, 'telegram_id': '555', 'stats': {'received': 10, 'sent': 20, 'handshake': 1780000000}}]
            return state
        return real(op, data)
    app.ctl = fake
    reply = client.get('/servers/awg0/export/clients.csv')
    assert reply.status_code == 200 and reply.headers['content-type'].startswith('text/csv')
    assert 'attachment; filename="clients-awg0-' in reply.headers['content-disposition']
    text = reply.content.decode('utf-8-sig')
    assert 'SECRET' not in text and 'PUB' not in text
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]['name'] == 'alpha' and rows[0]['comment'] == "'=HYPERLINK(\"x\")"
    assert rows[0]['traffic_limit_gib'] == '2' and rows[0]['used_gib'] == '1' and rows[0]['last_handshake_utc'].startswith('2026-')
    assert ('audit', {'event': 'clients_exported', 'target': 'awg0 (1)'}) in calls
    client.cookies.clear()
    assert client.get('/servers/awg0/export/clients.csv', follow_redirects=False).status_code in (401, 303)


# ------------------------------------------------------------------ bot
class InviteController(FakeController):
    def __init__(self):
        super().__init__()
        self.running['awg1'] = True
        self.clients['awg1'] = {'bob': self.new_client('10.9.0.2')}
        self.codes = {}

    def __call__(self, command, data=None):
        data = data or {}
        if command == 'client-invite' and command in bot_module_allowed():
            self.log.append((command, data))
            code = 'K' * 24
            self.codes[code] = (data['interface'], data['name'], data.get('export'))
            return {'ok': True, 'code': code, 'expires_at': '2026-12-01T10:00:00+00:00'}
        if command == 'invite-redeem':
            self.log.append((command, data))
            found = self.codes.get(data['code'])
            if not found or found[0] != data['interface']:
                return {'found': False}
            del self.codes[data['code']]
            client = self.clients[found[0]][found[1]]
            client.update(telegram_id=data['telegram_id'], owner_export=bool(found[2]))
            return {'found': True, 'name': found[1], 'export': bool(found[2])}
        if command == 'client-rekey':
            self.log.append((command, data))
            return {'ok': True, 'name': data['name'], 'config': '[Interface]\n'}
        return super().__call__(command, data)


def bot_module_allowed():
    from test_telegram_bot import BOT_ALLOWED
    return BOT_ALLOWED


@pytest.fixture
def ibot(tmp_path):
    api, controller, now = FakeApi(), InviteController(), [1_780_000_000.0]
    config = {'token': TOKEN, 'admins': {ADMIN}, 'lang': 'en', 'api_base': 'https://api.telegram.org', 'username': 'my_vpn_bot'}
    bot = bot_module.Bot(config, api=api, controller=controller, state_path=tmp_path / 'state.json', clock=lambda: now[0])
    return bot, api, controller, now


def test_admin_invites_from_the_bot_and_the_person_claims_the_client(ibot):
    bot, api, controller, _ = ibot
    bot.handle_update(press('c:awg1:bob'))
    assert 'ca:awg1:bob:inv' in api.buttons() and 'ca:awg1:bob:key' in api.buttons()
    bot.handle_update(press('ca:awg1:bob:inv'))
    assert {'iv:awg1:bob:1', 'iv:awg1:bob:7', 'iv:awg1:bob:30'} <= set(api.buttons())
    bot.handle_update(press('iv:awg1:bob:7'))
    assert ('client-invite', {'interface': 'awg1', 'name': 'bob', 'days': 7, 'export': True}) in controller.log
    assert 'https://t.me/my_vpn_bot?start=' + 'K' * 24 in api.texts()[-1]
    assert any(e['event'] == 'client_invite_created' for e in controller.audit)
    api.calls.clear()
    stranger = {'update_id': 9, 'message': {'message_id': 3, 'text': '/start ' + 'K' * 24,
                                            'from': {'id': STRANGER, 'first_name': 'Анна', 'username': 'anna_v'},
                                            'chat': {'id': STRANGER, 'type': 'private'}}}
    bot.handle_update(stranger)
    assert controller.clients['awg1']['bob']['telegram_id'] == str(STRANGER)
    to_person = [p['text'] for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == STRANGER]
    assert any('bob' in text and 'yours' in text for text in to_person)
    assert any('Your VPN' in text or 'bob' in text for text in to_person[1:])                 # their screen follows
    to_admin = [p['text'] for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == ADMIN]
    assert any('Invitation used' in text and 'Анна @anna_v' in text and str(STRANGER) in text for text in to_admin)
    assert any(e['event'] == 'client_invite_used' and str(STRANGER) in e['target'] for e in controller.audit)
    # The same link works once.
    api.calls.clear()
    bot.handle_update({**stranger, 'update_id': 10})
    assert 'not valid' in api.texts()[-1]


def test_invitation_guesses_are_limited_and_viewers_cannot_invite(ibot):
    bot, api, controller, _ = ibot
    for n in range(8):
        bot.handle_update(message('/start ' + f'{n:024d}', user=STRANGER))
    redeems = [c for c in controller.commands() if c == 'invite-redeem']
    assert len(redeems) == bot_module.INVITE_TRIES * 2            # five tries, each asked on both servers
    replies = api.texts()
    assert replies.count(bot.plain('invite_wait')) == 1 and replies.count(bot.plain('invite_bad')) == 5
    # Plain /start of a stranger still gets nothing.
    api.calls.clear()
    bot.handle_update(message('/start', user=STRANGER + 1))
    assert api.calls == []
    bot.config['viewers'] = {STRANGER + 2}
    bot.handle_update(press('iv:awg1:bob:7', user=STRANGER + 2))
    assert 'client-invite' not in controller.commands()


def test_rekey_from_the_bot_sends_the_new_config_and_tells_the_owner(ibot):
    bot, api, controller, _ = ibot
    controller.clients['awg0']['alice'].update(telegram_id='777000111', owner_export=True)
    bot.handle_update(press('ca:awg0:alice:key'))
    assert 'ky:awg0:alice:yes' in api.buttons() and 'client-rekey' not in controller.commands()
    bot.handle_update(press('ky:awg0:alice:yes'))
    assert ('client-rekey', {'interface': 'awg0', 'name': 'alice'}) in controller.log
    assert [f[2] for f in api.files][-2:] == ['alice.conf', 'alice-qr.png']
    owner = [p['text'] for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == 777000111]
    assert owner and 'Config button' in owner[-1]
    assert any(e['event'] == 'client_rekeyed' for e in controller.audit)


def test_recovery_sign_in_is_reported(ibot):
    bot, api, controller, _ = ibot
    bot.check_audit()                                   # first start: history is not replayed
    controller.audit.append({'timestamp': '2026-01-02T00:00:00+00:00', 'event': 'totp_recovery_used', 'target': '3 left'})
    bot.check_audit()
    assert 'recovery code' in api.texts()[-1] and '3' in api.texts()[-1]
