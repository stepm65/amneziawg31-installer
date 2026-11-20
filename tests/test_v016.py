"""0.16: snapshots before every update, rollback, and updating from the panel."""
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import types
from pathlib import Path

import pytest

from test_password_guards import admin, PASSWORD  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)
from test_telegram_bot import FakeApi, FakeController, bot_module, ADMIN, TOKEN, sudo_list

ROOT = Path(__file__).resolve().parents[1]


def load_snapshot(root, monkeypatch):
    monkeypatch.setenv('AWG31_SNAPSHOT_ROOT', str(root))
    spec = importlib.util.spec_from_file_location('awg31_snapshot_test', ROOT / 'scripts/awg31-snapshot.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()                          # a read-only file (a sudo rule) is replaced, not rewritten
    path.write_text(text)
    path.chmod(mode)


def install_version(root, version, extra=()):
    write(root / 'opt/awg31-panel/VERSION', version + '\n')
    write(root / 'opt/awg31-panel/web.py', f'# web {version}\n')
    write(root / 'opt/awg31-panel/fonts/a.woff2', f'font {version}')
    write(root / 'usr/local/sbin/awg31ctl', f'# ctl {version}\n', 0o755)
    write(root / 'usr/local/sbin/awg31mgr', f'# mgr {version}\n', 0o755)
    write(root / 'usr/local/bin/awg31', f'# menu {version}\n', 0o755)
    write(root / 'usr/local/libexec/awg31/install.sh', f'# install {version}\n', 0o755)
    write(root / 'etc/sudoers.d/awg31-panel', f'# sudo {version}\n', 0o440)
    write(root / 'etc/systemd/system/awg31-sampler.timer', f'# timer {version}\n')
    write(root / 'etc/systemd/system/awg31-panel.service', 'ExecStart=uvicorn web:app --port 18080\n')
    for rel in extra:
        write(root / rel, f'# {rel} {version}\n')


@pytest.fixture
def fake_root(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    install_version(root, '0.15.0')
    write(root / 'opt/awg31-panel/.venv/bin/python3', 'venv', 0o755)
    write(root / 'opt/awg31-panel/__pycache__/web.cpython-312.pyc', 'cache')
    import sqlite3
    (root / 'var/lib/awg31-panel/servers').mkdir(parents=True)
    with sqlite3.connect(root / 'var/lib/awg31-panel/servers/awg0.sqlite3') as con:
        con.execute('CREATE TABLE clients (name TEXT)')
        con.execute("INSERT INTO clients VALUES ('alpha')")
    write(root / 'etc/amnezia/amneziawg/awg0.conf', '[Interface]\nPrivateKey = secret\n', 0o600)
    return root, load_snapshot(root, monkeypatch)


def test_snapshot_holds_the_program_and_the_data_but_not_the_venv(fake_root):
    root, snap = fake_root
    path = snap.create('upgrade', '0.16.0')
    assert path.name.startswith('awg31-upgrade.') and oct(path.stat().st_mode)[-3:] == '700'
    manifest = json.loads((path / 'manifest.json').read_text())
    assert manifest['version'] == '0.15.0' and manifest['to'] == '0.16.0' and manifest['format'] == 1
    names = tarfile.open(path / 'code.tar').getnames()
    assert 'opt/awg31-panel/web.py' in names and 'usr/local/libexec/awg31/install.sh' in names
    assert 'etc/sudoers.d/awg31-panel' in names and 'etc/systemd/system/awg31-sampler.timer' in names
    assert not [n for n in names if '.venv' in n or '__pycache__' in n]
    assert 'etc/systemd/system/awg31-panel.service' not in names            # the port stays as it is
    assert (path / 'databases/awg0.sqlite3').is_file() and (path / 'configs/awg0.conf').is_file()
    listed = snap.snapshots()
    assert listed[0]['name'] == path.name and listed[0]['usable'] and listed[0]['version'] == '0.15.0'


def test_rollback_restores_the_program_and_can_be_undone(fake_root):
    root, snap = fake_root
    old = snap.create('upgrade', '0.16.0')
    # The update: new files, a new script, a new unit, a changed port and new clients.
    install_version(root, '0.16.0', extra=('opt/awg31-panel/newfile.py', 'usr/local/libexec/awg31/scripts/update-run.sh',
                                            'etc/systemd/system/awg31-new.timer'))
    write(root / 'etc/systemd/system/awg31-panel.service', 'ExecStart=uvicorn web:app --port 19090\n')
    import sqlite3
    with sqlite3.connect(root / 'var/lib/awg31-panel/servers/awg0.sqlite3') as con:
        con.execute("INSERT INTO clients VALUES ('beta')")
    assert snap.restore(old.name) == '0.15.0'
    assert (root / 'opt/awg31-panel/VERSION').read_text().strip() == '0.15.0'
    assert (root / 'opt/awg31-panel/web.py').read_text() == '# web 0.15.0\n'
    assert not (root / 'opt/awg31-panel/newfile.py').exists()
    assert not (root / 'usr/local/libexec/awg31/scripts/update-run.sh').exists()
    assert not (root / 'etc/systemd/system/awg31-new.timer').exists()
    assert (root / 'opt/awg31-panel/.venv/bin/python3').exists()                  # packages stay
    assert oct((root / 'etc/sudoers.d/awg31-panel').stat().st_mode)[-3:] == '440'
    assert '19090' in (root / 'etc/systemd/system/awg31-panel.service').read_text()
    with sqlite3.connect(root / 'var/lib/awg31-panel/servers/awg0.sqlite3') as con:
        assert [r[0] for r in con.execute('SELECT name FROM clients')] == ['alpha', 'beta']   # data is not rolled back
    # The state before the rollback was saved and is the newest snapshot: going forward again works.
    newest = snap.snapshots()[0]
    assert newest['version'] == '0.16.0' and newest['reason'] == 'before rollback to 0.15.0'
    assert snap.restore('latest') == '0.16.0'
    assert (root / 'opt/awg31-panel/newfile.py').exists() and (root / 'etc/systemd/system/awg31-new.timer').exists()


def test_old_partial_copies_and_bad_archives_are_refused(fake_root):
    root, snap = fake_root
    legacy = root / 'var/backups/awg31-upgrade.AbCd1234'
    write(legacy / 'web.py', 'old')
    assert snap.snapshots()[0]['usable'] is False
    with pytest.raises(SystemExit, match='older version'):
        snap.restore(legacy.name)
    with pytest.raises(SystemExit, match='no snapshot'):
        snap.restore('latest')
    with pytest.raises(SystemExit, match='Invalid'):
        snap.restore('../../etc')
    evil = snap.create('upgrade', '0.16.0')
    with tarfile.open(evil / 'code.tar', 'w') as archive:
        info = tarfile.TarInfo('etc/shadow')
        archive.addfile(info, io.BytesIO(b''))
    with pytest.raises(SystemExit, match='unexpected entry'):
        snap.restore(evil.name)
    assert (root / 'opt/awg31-panel/web.py').exists()                              # nothing was touched


def test_only_the_five_newest_snapshots_stay(fake_root):
    root, snap = fake_root
    made = []
    for n in range(7):
        path = snap.create('upgrade', f'0.16.{n}')
        stamp = 1_780_000_000 + n
        manifest = json.loads((path / 'manifest.json').read_text())
        manifest['created'] = f'2026-11-2{n}T10:00:00+00:00'
        (path / 'manifest.json').write_text(json.dumps(manifest))
        os.utime(path, (stamp, stamp))
        made.append(path.name)
    snap.prune()
    left = [x['name'] for x in snap.snapshots()]
    assert left == list(reversed(made))[:5]


def test_upgrade_takes_a_snapshot_and_installs_the_tools():
    core = (ROOT / 'scripts/upgrade-core.sh').read_text()
    assert 'awg31-snapshot.py" create --reason upgrade' in core and 'awg31-snapshot.py" restore' in core
    for script in ('awg31-snapshot.py', 'update-run.sh'):
        assert f'/usr/local/libexec/awg31/scripts/{script}' in core
        assert f'/usr/local/libexec/awg31/scripts/{script}' in (ROOT / 'scripts/setup-wizard.sh').read_text()
    menu = (ROOT / 'scripts/awg31-menu').read_text()
    assert 'rollback)' in menu and 'Type ROLLBACK' in menu and 'awg31 rollback [list|NAME]' in menu


# ------------------------------------------------------------------ the runner
def runner(tmp_path, code, action='update', target='v9.9.9'):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(parents=True, exist_ok=True)
    write(tmp_path / 'VERSION', '0.16.0\n')
    write(bin_dir / 'awg31', f'#!/bin/bash\necho "menu $*"; [ {code} -eq 0 ] && echo 9.9.9 > "{tmp_path}/VERSION"; exit {code}\n', 0o755)
    write(bin_dir / 'mgr', f'#!/bin/bash\necho "$1 $(cat)" >> "{tmp_path}/audit.txt"\n', 0o755)
    env = {'PATH': '/usr/bin:/bin', 'AWG31_UPDATE_STATE': str(tmp_path / 'state.json'), 'AWG31_UPDATE_LOG': str(tmp_path / 'log/update.log'),
           'AWG31_APP_VERSION': str(tmp_path / 'VERSION'), 'AWG31_MENU': str(bin_dir / 'awg31'), 'AWG31_MGR': str(bin_dir / 'mgr'),
           'AWG31_SNAPSHOT_TOOL': str(bin_dir / 'snap.py')}
    write(bin_dir / 'snap.py', f'import sys\nprint("restore", sys.argv[2])\nsys.exit({code})\n')
    done = subprocess.run(['bash', str(ROOT / 'scripts/update-run.sh'), action, target], env=env, capture_output=True, text=True)
    state = json.loads((tmp_path / 'state.json').read_text())
    audit = (tmp_path / 'audit.txt').read_text() if (tmp_path / 'audit.txt').exists() else ''
    return done.returncode, state, (tmp_path / 'log/update.log').read_text(), audit


def test_runner_records_success_and_failure(tmp_path):
    code, state, log, audit = runner(tmp_path / 'ok', 0)
    assert code == 0 and state['status'] == 'ok' and state['from'] == '0.16.0' and state['version'] == '9.9.9'
    assert 'menu update v9.9.9' in log and 'done: 0.16.0 → 9.9.9' in log
    assert '"event":"panel_updated","target":"0.16.0 → 9.9.9"' in audit
    code, state, log, audit = runner(tmp_path / 'bad', 3)
    assert code == 3 and state['status'] == 'failed' and state['code'] == 3 and 'panel_update_failed' in audit
    code, state, log, _ = runner(tmp_path / 'back', 0, 'rollback', 'awg31-upgrade.20261120T100000Z-abcd')
    assert state['status'] == 'ok' and 'restore awg31-upgrade.20261120T100000Z-abcd' in log
    for action, target in (('update', 'v1.2'), ('update', 'main; rm -rf /'), ('rollback', '../x'), ('purge', 'v1.2.3')):
        assert subprocess.run(['bash', str(ROOT / 'scripts/update-run.sh'), action, target], capture_output=True).returncode == 2


# ------------------------------------------------------------------ root operations
@pytest.fixture
def updater(admin, tmp_path, monkeypatch):
    module, _ = admin
    write(tmp_path / 'VERSION', '0.16.0\n')
    write(tmp_path / 'update-run.sh', '#!/bin/bash\n', 0o755)
    write(tmp_path / 'snapshot.py', '')
    monkeypatch.setattr(module, 'APP_VERSION', tmp_path / 'VERSION')
    monkeypatch.setattr(module, 'UPDATE_RUNNER', tmp_path / 'update-run.sh')
    monkeypatch.setattr(module, 'SNAPSHOT_TOOL', tmp_path / 'snapshot.py')
    monkeypatch.setattr(module, 'UPDATE_STATE', tmp_path / 'state.json')
    monkeypatch.setattr(module, 'UPDATE_LOG', tmp_path / 'update.log')
    monkeypatch.setattr(module.tempfile, 'mkstemp', lambda **k: os.open(tmp_path / 'copy.sh', os.O_CREAT | os.O_WRONLY), raising=False)
    calls, active = [], {'on': False}
    snapshots = [{'name': 'awg31-upgrade.20261120T100000Z-abcd', 'version': '0.15.0', 'usable': True},
                 {'name': 'awg31-upgrade.Legacy01', 'version': '', 'usable': False}]

    def run(args, **kwargs):
        calls.append(args)
        if args[:2] == ['systemctl', 'is-active']:
            return types.SimpleNamespace(returncode=0 if active['on'] else 3, stdout='', stderr='')
        if len(args) > 2 and args[2] == 'list':
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(snapshots), stderr='')
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    monkeypatch.setattr(module.tempfile, 'mkstemp', lambda **k: (os.open(tmp_path / 'copy.sh', os.O_CREAT | os.O_WRONLY), str(tmp_path / 'copy.sh')))
    return module, tmp_path, calls, active


def test_update_start_checks_password_version_and_snapshot(updater):
    module, tmp, calls, active = updater
    with pytest.raises(ValueError, match='password'):
        module.update_start({'password': 'wrong', 'action': 'update', 'target': 'v0.17.0'})
    for target in ('v0.16.0', 'v0.15.9', 'v1.0', 'main'):
        with pytest.raises(ValueError):
            module.update_start({'password': PASSWORD, 'action': 'update', 'target': target})
    with pytest.raises(ValueError, match='No such snapshot'):
        module.update_start({'password': PASSWORD, 'action': 'rollback', 'target': 'awg31-upgrade.Legacy01'})
    result = module.update_start({'password': PASSWORD, 'action': 'update', 'target': 'v0.17.0'})
    assert result == {'ok': True, 'action': 'update', 'target': 'v0.17.0'}
    started = [c for c in calls if c[0] == 'systemd-run'][-1]
    assert started[started.index('--unit') + 1] == 'awg31-update' and started[-3:] == [str(tmp / 'copy.sh'), 'update', 'v0.17.0']
    assert (tmp / 'copy.sh').read_text() == '#!/bin/bash\n'                      # a private copy of the runner
    assert 'panel_update_started' in (tmp / 'audit.jsonl').read_text()
    module.update_start({'password': PASSWORD, 'action': 'rollback', 'target': 'awg31-upgrade.20261120T100000Z-abcd'})
    active['on'] = True
    with pytest.raises(ValueError, match='already running'):
        module.update_start({'password': PASSWORD, 'action': 'update', 'target': 'v0.17.0'})


def test_update_status_reads_state_log_and_notices_a_dead_run(updater):
    module, tmp, calls, active = updater
    (tmp / 'state.json').write_text(json.dumps({'status': 'running', 'action': 'update', 'target': 'v0.17.0'}))
    (tmp / 'update.log').write_text('\n'.join(f'line {n}' for n in range(400)) + '\nEndpoint = 203.0.113.7:51820\n')
    status = module.update_status()
    assert status['state']['status'] == 'failed' and not status['running']           # the unit is gone
    assert status['log'].splitlines()[-1] != 'Endpoint = 203.0.113.7:51820' and len(status['log'].splitlines()) == 200
    assert status['version'] == '0.16.0' and status['available'] and len(status['snapshots']) == 2
    active['on'] = True
    assert module.update_status()['state']['status'] == 'running'


def test_operations_are_wired_for_the_panel_only():
    mgr = (ROOT / 'src/awg31mgr').read_text()
    assert "'update-status','update-start'" in mgr and 'admin.update_start(data)' in mgr
    assert {'update-status', 'update-start'} <= sudo_list('AWG31_SUDO_COMMANDS')
    assert not {'update-status', 'update-start'} & sudo_list('AWG31_BOT_SUDO_COMMANDS')


# ------------------------------------------------------------------ the panel
def update_ui(ui, status):
    app, client, calls = ui
    real = app.ctl

    def fake(op, data=None):
        if op == 'update-status':
            return status
        if op == 'update-start':
            calls.append((op, dict(data)))
            return {'ok': True}
        return real(op, data)
    app.ctl = fake
    return app, client, calls


def test_update_tab_offers_the_newer_release_and_the_snapshots(ui, monkeypatch):
    status = {'state': {}, 'running': False, 'log': '', 'version': '0.16.0', 'available': True,
              'snapshots': [{'name': 'awg31-upgrade.20261120T100000Z-abcd', 'version': '0.15.0', 'to': '0.16.0', 'reason': 'upgrade',
                             'created': '2026-11-20T10:00:00+00:00', 'usable': True},
                            {'name': 'awg31-upgrade.Legacy01', 'usable': False}]}
    app, client, calls = update_ui(ui, status)
    monkeypatch.setenv('AWG31_UPDATE_CHECK', '1')
    monkeypatch.setattr(app, 'panel_version', lambda: '0.16.0')
    app._latest.update(checked=app.time.time(), tag='v0.17.0', body='## What changed\n**Faster** <script>alert(1)</script>',
                       url='https://github.com/stepm65/amneziawg31-installer/releases/tag/v0.17.0')
    page = client.get('/maintenance?tab=update')
    html = page.text
    assert 'Доступна v0.17.0' in html and 'Обновить до v0.17.0' in html and 'value="v0.17.0"' in html
    assert 'What changed\nFaster &lt;script&gt;' in html and '<script>alert' not in html
    assert 'awg31-upgrade.20261120T100000Z-abcd' in html and 'Legacy01' not in html and 'до обновления на 0.16.0' in html
    assert 'class="sidebar-update" href="/maintenance?tab=update"' in html
    started = client.post('/maintenance/update', data={'csrf': token(page), 'action': 'update', 'target': 'v0.17.0', 'password': 'pw'},
                          follow_redirects=False)
    assert started.status_code == 303 and ('update-start', {'action': 'update', 'target': 'v0.17.0', 'password': 'pw'}) in calls
    for bad in ({'action': 'purge', 'target': 'v0.17.0'}, {'action': 'update', 'target': 'main'},
                {'action': 'rollback', 'target': '../../x'}):
        assert client.post('/maintenance/update', data={'csrf': token(page), 'password': 'pw', **bad}).status_code == 422
    assert client.post('/maintenance/update', data={'csrf': 'bad', 'action': 'update', 'target': 'v0.17.0'}).status_code == 403
    app._latest.update(tag='v0.16.0')
    assert 'Установлена последняя версия' in client.get('/maintenance?tab=update').text


def test_update_progress_is_followed_live(ui):
    status = {'state': {'status': 'running', 'action': 'update', 'target': 'v0.17.0', 'started': '2026-11-21T10:00:00Z'},
              'running': True, 'log': '[AWG31] Downloading release v0.17.0 <b>', 'version': '0.16.0', 'available': True, 'snapshots': []}
    app, client, calls = update_ui(ui, status)
    html = client.get('/maintenance?tab=update').text
    assert 'id="update-progress"' in html and 'data-update-running="1"' in html and 'Downloading release v0.17.0 &lt;b&gt;' in html
    assert 'Снимков пока нет' in html and 'type="submit" disabled>' in html
    api = client.get('/api/update-status').json()
    assert api['running'] is True and api['state']['target'] == 'v0.17.0' and 'snapshots' not in api
    client.cookies.clear()
    assert client.get('/api/update-status').status_code == 401
    js = (ROOT / 'src/panel.js').read_text()
    assert "fetch('/api/update-status'" in js and 'textRestarting' in js


def test_unavailable_runner_and_check_now(ui, monkeypatch):
    app, client, _ = update_ui(ui, {'state': {}, 'running': False, 'log': '', 'version': '0.15.0', 'available': False, 'snapshots': []})
    page = client.get('/maintenance?tab=update')
    assert 'sudo awg31 update' in page.text and 'Обновить до' not in page.text
    monkeypatch.setattr(app, '_fetch_latest_release', lambda force=False: False)
    checked = client.post('/maintenance/update/check', data={'csrf': token(page)}, follow_redirects=False)
    assert checked.headers['location'] == '/maintenance?tab=update&checked=0'
    assert 'GitHub не ответил' in client.get(checked.headers['location']).text


def test_bot_reports_updates_and_rollbacks(tmp_path):
    api, controller = FakeApi(), FakeController()
    bot = bot_module.Bot({'token': TOKEN, 'admins': {ADMIN}, 'lang': 'en', 'api_base': 'https://api.telegram.org'},
                         api=api, controller=controller, state_path=tmp_path / 'state.json', clock=lambda: 1_780_000_000.0)
    bot.check_audit()
    for event, target in (('panel_updated', '0.16.0 → 0.17.0'), ('panel_update_failed', 'v0.17.0 (exit 1)'),
                          ('panel_rolled_back', '0.17.0 → 0.16.0')):
        controller.audit.append({'timestamp': '2026-11-21T10:00:00+00:00', 'event': event, 'target': target})
    bot.check_audit()
    texts = api.texts()[-3:]
    assert 'updated: 0.16.0 → 0.17.0' in texts[0] and 'update failed' in texts[1] and 'rolled back: 0.17.0 → 0.16.0' in texts[2]
