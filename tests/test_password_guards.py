"""0.12.5: changes with a lasting effect ask the panel for its password again.

A stolen panel session must not be enough to attach somebody else's Telegram
account to the server, to switch off backup encryption or to move the second
factor to another phone. The root console is not asked: whoever is root there
already owns the server.
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from test_regressions import load_admin
from test_workflows import ui, token  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'panel-password-1'


def totp(secret, shift=0):
    step = int(time.time() // 30) + shift
    digest = hmac.new(base64.b32decode(secret), step.to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000:06d}'


@pytest.fixture
def admin(tmp_path, monkeypatch):
    module = load_admin('admin_guards')
    salt = b'6' * 16
    (tmp_path / 'auth.json').write_text(json.dumps({
        'salt': salt.hex(), 'session_key': 'K' * 48, 'auth_version': 'v1',
        'password_hash': hashlib.scrypt(PASSWORD.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()}))
    (tmp_path / 'bot').mkdir()
    for name, value in (('AWG31_AUTH', 'auth.json'), ('AWG31_AUDIT', 'audit.jsonl'), ('AWG31_BOT_CONFIG', 'bot/telegram.json'),
                        ('AWG31_BACKUP_KEY', 'etc/backup-passphrase'), ('AWG31_BACKUP_DIR', 'full')):
        monkeypatch.setenv(name, str(tmp_path / value))
    for name in ('AWG31_CALLER', 'SUDO_USER'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(module.os, 'chown', lambda *a: None)
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: type('P', (), {'returncode': 0, 'stdout': '', 'stderr': ''})())
    return module, tmp_path


def as_panel(monkeypatch, how='helper'):
    monkeypatch.setenv('AWG31_CALLER' if how == 'helper' else 'SUDO_USER', 'awgpanel')


@pytest.mark.parametrize('how', ['helper', 'sudo'])
def test_requests_from_the_panel_are_recognised_both_ways(admin, monkeypatch, how):
    module, _ = admin
    assert module.from_service() is False, 'the root console'
    monkeypatch.setenv('SUDO_USER', 'ubuntu')
    assert module.from_service() is False, 'an administrator who typed sudo is still the console'
    monkeypatch.delenv('SUDO_USER')
    as_panel(monkeypatch, how)
    assert module.from_service() is True


def bot_config(tmp, admins=(111222333,), viewers=()):
    (tmp / 'bot' / 'telegram.json').write_text(json.dumps({'token': '1' * 9 + ':' + 'A' * 35, 'admins': list(admins),
                                                         'viewers': list(viewers), 'lang': 'ru'}))


def test_bot_administrators_change_only_with_the_password(admin, monkeypatch):
    module, tmp = admin
    bot_config(tmp)
    as_panel(monkeypatch)
    for change in ({'admins': '111222333, 999000111'}, {'admins': '999000111'}, {'admins': '111222333', 'viewers': '444555666'}):
        for password in (None, 'wrong'):
            with pytest.raises(ValueError, match='panel password'):
                module.telegram_set({**change, **({'password': password} if password else {})})
    assert json.loads((tmp / 'bot' / 'telegram.json').read_text())['admins'] == [111222333]
    module.telegram_set({'admins': '111222333', 'lang': 'en', 'digest': 'daily', 'notify': {'server': True}})
    assert json.loads((tmp / 'bot' / 'telegram.json').read_text())['lang'] == 'en', 'other settings need no password'
    module.telegram_set({'admins': '111222333, 999000111', 'password': PASSWORD})
    assert json.loads((tmp / 'bot' / 'telegram.json').read_text())['admins'] == [111222333, 999000111]


def test_console_changes_bot_administrators_without_the_panel_password(admin):
    module, tmp = admin
    bot_config(tmp)
    module.telegram_set({'admins': '555666777'})
    assert json.loads((tmp / 'bot' / 'telegram.json').read_text())['admins'] == [555666777]


def test_connecting_or_disconnecting_the_bot_needs_the_password(admin, monkeypatch):
    module, tmp = admin
    bot_config(tmp)
    pending = tmp / 'bot' / 'telegram-pending.json'
    pending.write_text('{"kept": true}')
    as_panel(monkeypatch)
    with pytest.raises(ValueError, match='panel password'):
        module.telegram_connect({'token': '987654321:' + 'Q' * 35, 'password': 'wrong'})
    assert pending.exists(), 'nothing is touched before the password is checked'
    with pytest.raises(ValueError, match='panel password'):
        module.telegram_disconnect({'password': 'wrong'})
    with pytest.raises(ValueError, match='panel password'):
        module.telegram_disconnect(None)
    assert (tmp / 'bot' / 'telegram.json').exists(), 'the bot stays connected'

    class Reached(Exception):
        pass

    def stop_here(*args):
        raise Reached()      # the first real step: never touch /etc/sudoers.d or /var/lib on the test machine
    monkeypatch.setattr(module, '_systemctl', stop_here)
    with pytest.raises(Reached):
        module.telegram_disconnect({'password': PASSWORD})
    # Cancelling a pending setup removes only the pending token: no password needed.
    pending.write_text('{}')
    assert module.telegram_connect({'cancel': True})['cancelled'] is True and not pending.exists()


def test_encryption_from_the_panel_needs_the_password(admin, monkeypatch):
    module, tmp = admin
    key = tmp / 'etc' / 'backup-passphrase'
    key.parent.mkdir()
    key.write_text('the current passphrase 111\n')
    as_panel(monkeypatch, 'sudo')
    for call in (lambda d: module.backup_encryption_set({'enabled': False, **d}), lambda d: module.backup_encryption_set({'off': True, **d}),
                 lambda d: module.backup_encryption_change({'passphrase': 'a brand new passphrase', **d})):
        with pytest.raises(ValueError, match='panel password'):
            call({'password': 'wrong'})
    assert key.read_text() == 'the current passphrase 111\n'
    module.backup_encryption_set({'enabled': False, 'password': PASSWORD})
    assert not key.exists()


def test_console_keeps_managing_encryption_without_the_panel_password(admin):
    module, tmp = admin
    key = tmp / 'etc' / 'backup-passphrase'
    key.parent.mkdir()
    key.write_text('x\n')
    module.backup_encryption_set({'off': True})
    assert not key.exists()


def test_replacing_the_totp_key_needs_a_code_of_the_current_key(admin):
    module, tmp = admin
    old, new = (base64.b32encode(os.urandom(20)).decode() for _ in range(2))
    module.totp_enable({'password': PASSWORD, 'secret': old, 'code': totp(old)})          # first time: no current key
    replacement = {'password': PASSWORD, 'secret': new, 'code': totp(new), 'current_code': totp(old)}
    for bad, reason in (({'current_code': ''}, 'current key'), ({'current_code': '000000'}, 'current key'),
                        ({'secret': old, 'code': totp(old)}, 'differ'), ({'password': 'wrong'}, 'password'), ({'code': '000000'}, 'code')):
        with pytest.raises(ValueError, match=reason):
            module.totp_enable({**replacement, **bad})
    assert json.loads((tmp / 'auth.json').read_text())['totp_secret'] == old
    module.totp_enable(replacement)
    assert json.loads((tmp / 'auth.json').read_text())['totp_secret'] == new


# ------------------------------------------------------------------ the helper tells the controller who asked
@pytest.mark.skipif(os.geteuid() != 0, reason='awg31mgr and the helper run as root only')
def test_helper_names_the_real_caller_and_drops_its_own_sudo_user(tmp_path):
    from test_helper import MGR, HELPER, sudo_rule, raw_request
    key = tmp_path / 'backup-passphrase'
    key.write_text('passphrase of the test 1\n')
    salt = b'6' * 16
    (tmp_path / 'auth.json').write_text(json.dumps({'salt': salt.hex(), 'password_hash': hashlib.scrypt(
        PASSWORD.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()}))
    (tmp_path / 'sudoers').write_text(sudo_rule('root', ['backup-encryption-set', 'backup-encryption']))
    (tmp_path / 'sudoers').chmod(0o440)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(tmp_path), 'AWG31_ROOT': str(tmp_path / 'root'), 'AWG31_CONFIG_DIR': str(tmp_path),
           'AWG31_AUDIT': str(tmp_path / 'audit.jsonl'), 'AWG31_MGR_PATH': str(MGR), 'AWG31_CTL_PATH': str(ROOT / 'src' / 'awg31ctl'),
           'AWG31_HELPER_SOCKET': str(tmp_path / 'control.sock'), 'AWG31_HELPER_SUDOERS': str(tmp_path / 'sudoers'),
           'AWG31_HELPER_GROUP': 'root', 'AWG31_BACKUP_KEY': str(key), 'AWG31_AUTH': str(tmp_path / 'auth.json')}
    # Through sudo as the panel user the password is required ...
    direct = subprocess.run([sys.executable, str(MGR), 'backup-encryption-set'], input='{"off": true}', capture_output=True, text=True,
                            env={**env, 'SUDO_USER': 'awgpanel'})
    assert direct.returncode == 1 and 'panel password' in direct.stderr and key.exists()
    # ... and a helper that itself was started with SUDO_USER=awgpanel still reports the real peer (root here).
    helper = subprocess.Popen([sys.executable, str(HELPER)], env={**env, 'SUDO_USER': 'awgpanel'}, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if (tmp_path / 'control.sock').exists():
                break
            time.sleep(0.05)
        rc, out, err = raw_request(env, {'op': 'backup-encryption-set', 'input': '{"off": true}'})
        assert rc == 0, err
        assert not key.exists()
    finally:
        helper.terminate()
        helper.wait(10)


# ------------------------------------------------------------------ panel forms
def test_panel_forms_send_the_password(ui):
    app, client, calls = ui
    original = app.ctl
    def fake(op, data=None):
        if op == 'backup-encryption':
            return {'enabled': True}
        if op in ('backup-encryption-set', 'backup-encryption-change'):
            calls.append((op, data))
            return {'ok': True, 'reencrypted': 2, 'skipped': []}
        return original(op, data)
    app.ctl = fake
    page = client.get('/maintenance?tab=backups')
    assert page.text.count('name="password"') >= 2 and 'action="/maintenance/backup/encryption/change"' in page.text
    client.post('/maintenance/backup/encryption/disable', data={'csrf': token(page), 'password': 'pw'})
    client.post('/maintenance/backup/encryption/change', data={'csrf': token(page), 'password': 'pw',
                                                               'passphrase': 'a brand new passphrase', 'confirm': 'a brand new passphrase'})
    mismatch = client.post('/maintenance/backup/encryption/change', data={'csrf': token(page), 'password': 'pw',
                                                                          'passphrase': 'a brand new passphrase', 'confirm': 'other'})
    assert mismatch.status_code == 400
    app.ctl = original
    seen = [(op, data) for op, data in calls if op.startswith('backup-encryption')]
    assert ('backup-encryption-set', {'enabled': False, 'password': 'pw'}) in seen
    assert ('backup-encryption-change', {'passphrase': 'a brand new passphrase', 'password': 'pw'}) in seen
    assert len([1 for op, _ in seen if op == 'backup-encryption-change']) == 1, 'a mismatch never reaches the controller'


def test_totp_replacement_form_asks_for_both_codes(ui):
    app, client, calls = ui
    stored = json.loads(app.AUTH_FILE.read_text())
    app.AUTH_FILE.write_text(json.dumps({**stored, 'totp_secret': base64.b32encode(os.urandom(20)).decode()}))
    page = client.get('/maintenance?tab=security')
    form = page.text.split('action="/maintenance/totp/regenerate"')[1].split('</form>')[0]
    assert 'name="current_code"' in form and 'name="code"' in form and 'name="password"' in form
    secret = form.split('name="secret" value="')[1].split('"')[0]
    client.post('/maintenance/totp/regenerate', data={'csrf': token(page), 'secret': secret, 'password': 'pw', 'code': '222222',
                                                      'current_code': '111111'})
    assert ('totp-enable', {'password': 'pw', 'code': '222222', 'secret': secret, 'current_code': '111111'}) in calls
