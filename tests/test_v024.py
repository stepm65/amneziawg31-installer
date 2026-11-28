"""0.24: several panel accounts with the roles administrator and viewer, the account in the audit log,
and the list of signed-in sessions with ending one of them."""
import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from test_v010_features import auth, totp_now  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)
from test_telegram_bot import sudo_list

ROOT = Path(__file__).resolve().parents[1]


def record(password, role='viewer', **extra):
    salt = os.urandom(16)
    return {'role': role, 'created': '2026-11-28T10:00:00+00:00', 'salt': salt.hex(),
            'password_hash': hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex(), **extra}


# ------------------------------------------------------------------ root side
def test_accounts_are_created_changed_and_deleted_by_an_administrator(auth, monkeypatch):
    admin, file = auth
    monkeypatch.setenv('AWG31_CALLER', 'awgpanel'); monkeypatch.setenv('AWG31_ACTOR', 'admin')
    me = {'actor': 'admin', 'password': 'the-right-password'}
    with pytest.raises(ValueError, match='password'):
        admin.account_set({'actor': 'admin', 'password': 'wrong', 'create': True, 'name': 'olga', 'new_password': 'x' * 12})
    admin.account_set({**me, 'create': True, 'name': 'olga', 'role': 'viewer', 'new_password': 'olga-password-1'})
    admin.account_set({**me, 'create': True, 'name': 'ivan', 'role': 'admin', 'new_password': 'ivan-password-1'})
    stored = json.loads(file.read_text())
    assert stored['auth_version'] == 'v1'                                   # nobody is signed out
    assert stored['users']['olga']['role'] == 'viewer' and 'olga-password-1' not in file.read_text()
    assert admin._password_ok(stored['users']['olga'], 'olga-password-1')
    for bad, why in (({'name': 'olga', 'new_password': 'y' * 12}, 'exists'), ({'name': 'admin', 'new_password': 'y' * 12}, 'exists'),
                     ({'name': 'Bad Name', 'new_password': 'y' * 12}, 'name'), ({'name': 'petr', 'new_password': 'short'}, '12'),
                     ({'name': 'petr', 'role': 'root', 'new_password': 'y' * 12}, 'Role')):
        with pytest.raises(ValueError, match=why):
            admin.account_set({**me, 'create': True, **bad})
    # A viewer cannot manage accounts, even with its own password.
    with pytest.raises(ValueError, match='password'):
        admin.account_set({'actor': 'olga', 'password': 'olga-password-1', 'create': True, 'name': 'petr', 'new_password': 'y' * 12})
    # Another administrator can.
    result = admin.account_set({'actor': 'ivan', 'password': 'ivan-password-1', 'name': 'olga', 'role': 'admin', 'new_password': 'olga-password-2'})
    assert result['ended'] is True
    stored = json.loads(file.read_text())
    assert stored['users']['olga']['role'] == 'admin' and admin._password_ok(stored['users']['olga'], 'olga-password-2')
    with pytest.raises(ValueError, match='main account'):
        admin.account_set({**me, 'name': 'admin', 'role': 'viewer'})
    with pytest.raises(ValueError, match='yourself'):
        admin.account_set({'actor': 'ivan', 'password': 'ivan-password-1', 'name': 'ivan', 'role': 'viewer'})
    with pytest.raises(ValueError, match='main account'):
        admin.account_delete({**me, 'name': 'admin'})
    with pytest.raises(ValueError, match='yourself'):
        admin.account_delete({'actor': 'ivan', 'password': 'ivan-password-1', 'name': 'ivan'})
    admin.account_delete({**me, 'name': 'olga'})
    assert 'olga' not in json.loads(file.read_text())['users']
    log = [json.loads(x) for x in Path(os.environ['AWG31_AUDIT']).read_text().splitlines()]
    assert [x['event'] for x in log] == ['account_created', 'account_created', 'account_changed', 'account_deleted']
    assert {x['actor'] for x in log} == {'admin'} and log[2]['target'] == 'olga: role admin, password'


def test_own_credentials_per_account_and_the_actor(auth, monkeypatch):
    admin, file = auth
    stored = json.loads(file.read_text())
    stored['users'] = {'olga': record('olga-password-1')}
    file.write_text(json.dumps(stored))
    admin.password_change({'account': 'olga', 'old_password': 'olga-password-1', 'new_password': 'olga-password-2'})
    stored = json.loads(file.read_text())
    assert admin._password_ok(stored['users']['olga'], 'olga-password-2') and admin._password_ok(stored, 'the-right-password')
    secret = base64.b32encode(os.urandom(20)).decode()
    codes = admin.totp_enable({'account': 'olga', 'password': 'olga-password-2', 'secret': secret, 'code': totp_now(secret)})['recovery_codes']
    stored = json.loads(file.read_text())
    assert stored['users']['olga']['totp_secret'] == secret and 'totp_secret' not in stored and stored['auth_version'] == 'v1'
    assert admin.totp_recovery_use({'account': 'olga', 'password': 'olga-password-2', 'code': codes[0]})['left'] == 9
    with pytest.raises(ValueError):
        admin.totp_recovery_use({'password': 'the-right-password', 'code': codes[1]})           # not the main account's code
    with pytest.raises(ValueError, match='No such'):
        admin.password_change({'account': 'ghost', 'old_password': 'x', 'new_password': 'y' * 12})
    # Who did it: the panel's account, the bot, root at the console, or nobody for a timer.
    for env, expected in (({'AWG31_CALLER': 'awgpanel', 'AWG31_ACTOR': 'olga'}, 'olga'), ({'AWG31_CALLER': 'awgpanel', 'AWG31_ACTOR': '../x'}, ''),
                          ({'AWG31_CALLER': 'awgbot', 'AWG31_ACTOR': 'olga'}, 'telegram'), ({'SUDO_USER': 'ubuntu'}, 'console'), ({}, '')):
        for key in ('AWG31_CALLER', 'AWG31_ACTOR', 'SUDO_USER'): monkeypatch.delenv(key, raising=False)
        for key, value in env.items(): monkeypatch.setenv(key, value)
        assert admin.actor() == expected
    # Panel-password checks use the signed-in account, and a viewer never passes them.
    monkeypatch.setenv('AWG31_CALLER', 'awgpanel'); monkeypatch.setenv('AWG31_ACTOR', 'olga')
    with pytest.raises(ValueError):
        admin.require_panel_password({'password': 'olga-password-2'})
    stored = json.loads(file.read_text()); stored['users']['olga']['role'] = 'admin'; file.write_text(json.dumps(stored))
    admin.require_panel_password({'password': 'olga-password-2'})
    with pytest.raises(ValueError):
        admin.require_panel_password({'password': 'the-right-password'})


def test_session_list_is_validated_and_kept_beside_auth(auth):
    admin, file = auth
    entry = {'hash': 'a' * 64, 'account': 'admin', 'addr': '203.0.113.5', 'agent': 'Firefox', 'created': 1, 'seen': 2}
    assert admin.session_save({'sessions': [entry], 'ended': 'admin: logout'})['count'] == 1
    saved = file.with_name('sessions.json')
    assert json.loads(saved.read_text())['sessions'] == [entry] and oct(saved.stat().st_mode & 0o777) == '0o640'
    for bad in ({'sessions': 'x'}, {'sessions': [{**entry, 'hash': 'short'}]}, {'sessions': [{**entry, 'account': '../x'}]},
                {'sessions': [{**entry, 'agent': 'a\nb'}]}, {'sessions': [entry] * 201}):
        with pytest.raises(ValueError):
            admin.session_save(bad)
    assert 'session_ended' in Path(os.environ['AWG31_AUDIT']).read_text()
    admin.session_revoke()                                     # sign out everywhere: the list goes too
    assert not saved.exists() and json.loads(file.read_text())['auth_version'] != 'v1'


def test_new_operations_are_wired_for_the_panel_only():
    panel, bot = sudo_list('AWG31_SUDO_COMMANDS'), sudo_list('AWG31_BOT_SUDO_COMMANDS')
    assert {'account-set', 'account-delete', 'session-save'} <= set(panel)
    assert not {'account-set', 'account-delete', 'session-save'} & set(bot)
    manager = (ROOT / 'src/awg31mgr').read_text()
    assert "'account-set','account-delete','session-save'" in manager and "data.pop('_actor',None)" in manager
    assert "caller=='awgpanel'" in manager


# ------------------------------------------------------------------ panel
def with_users(app, **users):
    stored = json.loads(app.AUTH_FILE.read_text())
    stored['users'] = users
    app.AUTH_FILE.write_text(json.dumps(stored))


def sign_in(app, username, password, code=''):
    browser = TestClient(app.app, follow_redirects=False)
    app.login_attempts.clear()
    reply = browser.post('/login', data={'username': username, 'password': password, 'code': code})
    return browser, reply.status_code == 303


def test_login_asks_for_the_account_once_there_are_several(ui):
    app, client, calls = ui
    assert 'name="username"' not in TestClient(app.app).get('/login').text
    with_users(app, olga=record('olga-password-1'))
    assert 'name="username"' in TestClient(app.app).get('/login').text
    _, ok = sign_in(app, 'olga', 'olga-password-1'); assert ok
    _, ok = sign_in(app, 'OLGA ', 'olga-password-1'); assert ok
    _, ok = sign_in(app, 'olga', 'correct-test-password'); assert not ok             # someone else's password
    _, ok = sign_in(app, 'ghost', 'olga-password-1'); assert not ok
    _, ok = sign_in(app, 'admin', 'correct-test-password'); assert ok
    _, ok = sign_in(app, '', 'correct-test-password'); assert ok                   # an empty name is the main account
    secret = base64.b32encode(os.urandom(20)).decode()
    with_users(app, olga=record('olga-password-1', totp_secret=secret))
    _, ok = sign_in(app, 'olga', 'olga-password-1'); assert not ok
    _, ok = sign_in(app, 'olga', 'olga-password-1', totp_now(secret)); assert ok
    _, ok = sign_in(app, 'olga', 'olga-password-1', totp_now(secret)); assert not ok  # a code works once
    _, ok = sign_in(app, 'admin', 'correct-test-password'); assert ok                # the main account has no 2FA
    _, ok = sign_in(app, 'olga', 'olga-password-1', 'abcde-fghjk'); assert ok        # a recovery code (the fake accepts it)
    assert ('totp-recovery-use', {'password': 'olga-password-1', 'code': 'abcde-fghjk', 'account': 'olga'}) in calls


def test_a_viewer_sees_but_changes_nothing_and_gets_no_keys(ui):
    app, client, calls = ui
    with_users(app, olga=record('olga-password-1'))
    viewer, ok = sign_in(app, 'olga', 'olga-password-1'); assert ok
    home = viewer.get('/')
    assert home.status_code == 200 and 'class="role-viewer"' in home.text and 'Режим наблюдателя' in home.text
    assert 'class="account-chip"' in home.text and '<span>olga</span><small>наблюдатель</small>' in home.text
    page = viewer.get('/servers/awg0/clients/alpha')
    assert page.status_code == 200 and 'TEST_ONLY' not in page.text and 'доступны только администраторам' in page.text
    for path in ('/servers/awg0/clients/alpha/download', '/client/alpha/qr', '/servers/awg0/clients/alpha/vpn-link',
                 '/maintenance/backup/awg31-20261112T030000Z-0123456789.tar.gz', '/servers/awg0/settings/profile',
                 '/servers/awg0/export/clients.csv', '/maintenance?tab=backups', '/maintenance?tab=accounts', '/maintenance?tab=telegram'):
        assert viewer.get(path).status_code == 403, path
    security = viewer.get('/maintenance?tab=security')
    assert security.status_code == 200 and 'tab=backups' not in security.text and 'tab=audit' in security.text
    csrf = token(security)
    before = len(calls)
    for path, data in (('/servers/awg0/clients/alpha/delete', {}), ('/maintenance/backup', {}), ('/servers/awg0/clients', {'name': 'x'}),
                       ('/maintenance/accounts', {'name': 'petr'}), ('/maintenance/sessions/all', {})):
        assert viewer.post(path, data={'csrf': csrf, **data}).status_code == 403, path
    assert len(calls) == before                                     # nothing reached the controller
    # Its own password, yes.
    done = viewer.post('/maintenance/password', data={'csrf': csrf, 'old': 'olga-password-1', 'new': 'n' * 12, 'confirm': 'n' * 12})
    assert done.status_code == 303 and ('password-change', {'old_password': 'olga-password-1', 'new_password': 'n' * 12, 'account': 'olga'}) in calls
    assert viewer.get('/servers').status_code == 303                # its sessions ended
    # The administrator's page has no viewer class and still gets the configuration.
    assert 'role-viewer' not in client.get('/').text and 'TEST_ONLY' in client.get('/servers/awg0/clients/alpha').text


def test_sessions_are_listed_and_one_can_be_ended(ui):
    app, client, calls = ui
    with_users(app, olga=record('olga-password-1'))
    olga, _ = sign_in(app, 'olga', 'olga-password-1')
    second, _ = sign_in(app, 'admin', 'correct-test-password')
    page = client.get('/maintenance?tab=security')
    html = page.text.split('id="panel-sessions"')[1]
    assert html.count('<tr') == 4 and 'Эта сессия' in html and '<td>olga</td>' in html and 'Выйти везде' in html
    own = olga.get('/maintenance?tab=security').text.split('id="panel-sessions"')[1]
    assert own.count('<tr') == 2 and '<td>admin</td>' not in own and 'Выйти везде' not in own
    olga_id = next(k for k, e in app.PANEL_SESSIONS.items() if e['account'] == 'olga')[:16]
    admin_ids = [k[:16] for k, e in app.PANEL_SESSIONS.items() if e['account'] == 'admin']
    # A viewer cannot end someone else's session.
    assert olga.post('/maintenance/sessions/end', data={'csrf': token(olga.get('/maintenance?tab=security')), 'id': admin_ids[0]}).status_code == 404
    done = client.post('/maintenance/sessions/end', data={'csrf': token(page), 'id': olga_id}, follow_redirects=False)
    assert done.status_code == 303 and olga.get('/servers').status_code == 303
    assert [d for op, d in calls if op == 'session-save'][-1]['ended'] == 'olga: ended by admin'
    client.post('/maintenance/sessions/others', data={'csrf': token(page)})
    assert second.get('/servers').status_code == 303 and client.get('/servers').status_code == 200
    gone = client.post('/maintenance/sessions/all', data={'csrf': token(page)}, follow_redirects=False)
    assert gone.headers['location'] == '/login' and ('session-revoke', {}) in calls and not app.PANEL_SESSIONS


def test_sessions_survive_a_panel_restart(ui, tmp_path):
    app, client, calls = ui
    saved = [d for op, d in calls if op == 'session-save'][-1]
    app.SESSIONS_FILE.write_text(json.dumps({'sessions': saved['sessions'] + [{'hash': 'b' * 64, 'account': 'admin', 'seen': 0, 'created': 0}]}))
    import importlib.util
    spec = importlib.util.spec_from_file_location('web024', ROOT / 'src/web.py')
    again = importlib.util.module_from_spec(spec); spec.loader.exec_module(again)
    again.ctl = app.ctl
    assert list(again.PANEL_SESSIONS) == [saved['sessions'][0]['hash']]       # the stale one is dropped
    restarted = TestClient(again.app, follow_redirects=False)
    restarted.cookies.update(dict(client.cookies))
    assert restarted.get('/servers').status_code == 200


def test_accounts_tab_sends_the_actor_and_its_password(ui):
    app, client, calls = ui
    with_users(app, olga=record('olga-password-1'))
    olga, _ = sign_in(app, 'olga', 'olga-password-1')
    page = client.get('/maintenance?tab=accounts')
    assert page.status_code == 200 and '<strong>admin</strong>' in page.text and '<strong>olga</strong>' in page.text
    assert 'action="/maintenance/accounts/olga/delete"' in page.text and 'action="/maintenance/accounts/admin/delete"' not in page.text
    csrf = token(page)
    made = client.post('/maintenance/accounts', data={'csrf': csrf, 'name': 'Petr', 'role': 'admin', 'new': 'p' * 12, 'confirm': 'p' * 12,
                                                      'password': 'correct-test-password'}, follow_redirects=False)
    assert made.headers['location'] == '/maintenance?tab=accounts&account=created'
    assert ('account-set', {'create': True, 'name': 'petr', 'role': 'admin', 'new_password': 'p' * 12, 'actor': 'admin',
                            'password': 'correct-test-password'}) in calls
    count = len([op for op, _ in calls if op == 'account-set'])
    assert 'не совпадают' in client.post('/maintenance/accounts', data={'csrf': csrf, 'name': 'x', 'new': 'p' * 12, 'confirm': 'q' * 12}).text
    assert len([op for op, _ in calls if op == 'account-set']) == count
    original = app.ctl
    app.ctl = lambda op, data=None: {'ok': True, 'ended': True} if op == 'account-set' else original(op, data)
    client.post('/maintenance/accounts/olga', data={'csrf': csrf, 'role': 'viewer', 'new': '', 'confirm': '', 'password': 'pw'})
    assert olga.get('/servers').status_code == 303                   # a changed account signs in again
    olga, _ = sign_in(app, 'olga', 'olga-password-1')
    client.post('/maintenance/accounts/olga/delete', data={'csrf': csrf, 'password': 'pw'})
    assert olga.get('/servers').status_code == 303
    assert client.post('/maintenance/accounts/..%2Fx/delete', data={'csrf': csrf}).status_code == 404


def test_the_panel_names_the_account_to_the_helper(ui, monkeypatch):
    app, client, calls = ui
    sent = []
    monkeypatch.setattr(app.awg31client, 'call', lambda op, payload, timeout: sent.append((op, payload)) or (0, '{"ok": true}', ''))
    token_ = app.ACTOR.set('olga')
    try:
        app._ctl_call('audit', {'event': 'client_added', 'target': 'x'})
        app._ctl_call('list', {'interface': 'awg0'})
    finally:
        app.ACTOR.reset(token_)
    app._ctl_call('audit', {'event': 'client_added', 'target': 'x'})
    assert json.loads(sent[0][1])['_actor'] == 'olga' and '_actor' not in json.loads(sent[1][1]) and '_actor' not in json.loads(sent[2][1])


def test_audit_page_and_csv_show_the_account(ui):
    app, client, calls = ui
    original = app.ctl
    app.ctl = lambda op, data=None: ({'entries': [{'timestamp': '2026-11-28T10:00:00', 'event': 'client_added', 'target': 'alpha', 'actor': 'olga'}],
                                      'events': ['client_added'], 'page': 1, 'pages': 1, 'total': 1}
                                     if op == 'audit-search' else original(op, data))
    assert '<span class="audit-actor">' in client.get('/maintenance?tab=audit').text
    assert client.get('/maintenance/audit.csv').text.splitlines() == ['timestamp,event,target,account', '2026-11-28T10:00:00,client_added,alpha,olga']
