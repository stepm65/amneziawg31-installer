"""0.27: backups checked on schedule, database housekeeping, Prometheus metrics."""
import hashlib
import json
import time
from pathlib import Path

import pytest

from test_password_guards import admin, as_panel, PASSWORD  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)
from test_telegram_bot import sudo_list
from test_v015 import ctl, db, row  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
NAME = 'awg31-20261128T030000Z-0123456789.tar.gz.gpg'


def audit_events(tmp):
    path = tmp / 'audit.jsonl'
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


# ------------------------------------------------------------------ backup checks
def backup(tmp, name=NAME, body=b'archive-bytes'):
    (tmp / 'full').mkdir(exist_ok=True)
    (tmp / 'full' / name).write_bytes(body)
    return tmp / 'full' / name


def test_the_newest_backup_is_checked_and_the_remote_copy_compared(admin, monkeypatch):
    module, tmp = admin
    backup(tmp, 'awg31-20261127T030000Z-aaaaaaaaaa.tar.gz.gpg')
    local = backup(tmp)
    runs = []
    monkeypatch.setattr(module.subprocess, 'run', lambda argv, **k: runs.append(argv) or type('P', (), {'returncode': 0, 'stdout': '{}', 'stderr': ''})())
    state = module.verify_backup()
    assert runs[-1][-2:] == ['--check', NAME] and state['ok'] and state['local'] == 'ok' and state['remote'] == 'skipped'
    assert json.loads((tmp / 'verify.json').read_text())['name'] == NAME
    # A remote storage: the copy there is downloaded and compared byte for byte.
    monkeypatch.setattr(module, '_remote', lambda: {'type': 's3'})
    for stored, remote, ok in ((local.read_bytes(), 'ok', True), (None, 'missing', False), (b'other', 'mismatch', False)):
        monkeypatch.setattr(module, '_s3_get', lambda remote_, name, body=stored: body)
        state = module.verify_backup({'name': NAME})
        assert (state['remote'], state['ok']) == (remote, ok)
    assert 'remote storage is mismatch' in state['error']
    # The local check failing.
    monkeypatch.setattr(module.subprocess, 'run', lambda argv, **k: type('P', (), {'returncode': 1, 'stdout': '', 'stderr': 'ERROR: Backup checksum mismatch'})())
    state = module.verify_backup({'name': NAME})
    assert not state['ok'] and state['local'] == 'failed' and state['error'] == 'Backup checksum mismatch'
    events = [x['event'] for x in audit_events(tmp)]
    assert events == ['backup_verified', 'backup_verified', 'backup_verify_failed', 'backup_verify_failed', 'backup_verify_failed']
    with pytest.raises(ValueError):
        module.verify_backup({'name': '../x'})
    for item in (tmp / 'full').iterdir(): item.unlink()
    with pytest.raises(ValueError, match='no backup'):
        module.verify_backup({})


def test_scheduled_backups_are_checked_as_the_policy_says(admin, monkeypatch):
    module, tmp = admin
    monkeypatch.setenv('AWG31_BACKUP_POLICY', str(tmp / 'policy.json'))
    backup(tmp)
    checked = []
    monkeypatch.setattr(module, 'verify_backup', lambda data: checked.append(data['name']) or {'ok': True, 'checked_at': int(time.time())})
    assert module.backup_policy()['verify'] == 'weekly'                           # the default, also for old policy files
    (tmp / 'policy.json').write_text(json.dumps({'frequency': 'daily', 'hour': 3, 'minute': 0, 'weekday': 0, 'retention_days': 30, 'max_copies': 20}))
    assert module.backup_policy()['verify'] == 'weekly'
    module.verify_after_backup({'name': NAME})
    (tmp / 'verify.json').write_text(json.dumps({'checked_at': int(time.time()) - 86400}))
    module.verify_after_backup({'name': NAME})                                    # checked yesterday: not again this week
    assert checked == [NAME]
    for mode, expected in (('each', 2), ('off', 2)):
        (tmp / 'policy.json').write_text(json.dumps({'frequency': 'daily', 'hour': 3, 'minute': 0, 'weekday': 0, 'retention_days': 30,
                                                     'max_copies': 20, 'verify': mode}))
        module.verify_after_backup({'name': NAME})
        assert len(checked) == expected
    with pytest.raises(ValueError, match='check mode'):
        module._policy_values({'frequency': 'daily', 'hour': 3, 'minute': 0, 'weekday': 0, 'retention_days': 30, 'max_copies': 20, 'verify': 'hourly'})
    manager = (ROOT / 'src/awg31mgr').read_text()
    assert 'admin.verify_after_backup(admin.after_backup(admin.scheduled_backup(' in manager


def test_backups_tab_shows_the_last_check_and_runs_one(ui):
    app, client, calls = ui
    original = app.ctl

    def fake(op, data=None):
        if op == 'backup-policy':
            return {'policy': {'frequency': 'daily', 'hour': 3, 'minute': 0, 'weekday': 0, 'retention_days': 30, 'max_copies': 20, 'verify': 'each'},
                    'verify': {'checked_at': 1795836000, 'name': NAME, 'ok': False, 'error': 'Backup checksum mismatch', 'remote': 'skipped'}}
        if op == 'backup-verify':
            calls.append((op, dict(data))); return {'ok': True}
        return original(op, data)
    app.ctl = fake
    page = client.get('/maintenance?tab=backups')
    assert 'Проверка резервных копий' in page.text and 'Не пройдена 2026-11-28' in page.text and 'Backup checksum mismatch' in page.text
    assert '<option value="each" selected>Каждую новую</option>' in page.text
    done = client.post('/maintenance/backup/verify', data={'csrf': token(page)}, follow_redirects=False)
    assert done.status_code == 303 and ('backup-verify', {}) in calls


# ------------------------------------------------------------------ databases
def test_history_is_kept_as_long_as_set_and_the_file_compacted(db, monkeypatch, tmp_path):
    con, call, _ = db
    settings = tmp_path / 'logging.json'
    monkeypatch.setattr(ctl, 'LOGGING', settings)
    now = int(time.time())
    for age in (5, 20, 40):
        con.execute('INSERT INTO traffic_samples(measured_at, rx_delta, tx_delta) VALUES(?,?,?)', (now - age * 86400, 1, 1))
    con.commit()
    ctl.sample_usage(con)
    assert con.execute('SELECT COUNT(*) FROM traffic_samples').fetchone()[0] == 3           # 5 and 20 days, plus this minute
    settings.write_text(json.dumps({'traffic_days': 10}))
    ctl.sample_usage(con)
    assert con.execute('SELECT COUNT(*) FROM traffic_samples').fetchone()[0] == 3           # 5 days, the two new minutes
    settings.write_text(json.dumps({'traffic_days': 1, 'client_traffic_days': 9999}))
    assert ctl.logging_settings()['traffic_days'] == 7 and ctl.logging_settings()['client_traffic_days'] == 730
    # Compaction: the first sample only starts the clock; a week later it runs, at 03:xx UTC or a day after that.
    assert ctl.vacuumed_at(con) > 0
    con.execute("UPDATE maintenance SET value='1' WHERE key='vacuumed_at'"); con.commit()
    at_noon = 1795867200          # 2026-11-28 12:00 UTC
    at_three = at_noon - 9 * 3600
    con.execute("UPDATE maintenance SET value=? WHERE key='vacuumed_at'", (str(at_three - 7 * 86400 - 3600),)); con.commit()
    assert ctl.vacuum_due(con, at_three - 3600) is None                       # a week, but not the quiet hour (02:00)
    assert ctl.vacuum_due(con, at_three)['ok']                                # 03:00 UTC
    con.execute("UPDATE maintenance SET value=? WHERE key='vacuumed_at'", (str(at_noon - 8 * 86400 - 60),)); con.commit()
    assert ctl.vacuum_due(con, at_noon)['ok']                                    # overdue: any hour
    info = call(ctl.db_maintain, {})
    assert info['size'] > 0 and info['rows']['traffic_samples'] >= 1 and info['vacuumed_at'] == at_noon
    assert call(ctl.db_maintain, {'vacuum': True})['ok']


def test_admin_reports_and_compacts_every_database(admin, monkeypatch):
    module, tmp = admin
    monkeypatch.setenv('AWG31_ROOT', str(tmp / 'base'))
    monkeypatch.setenv('AWG31_LOGGING', str(tmp / 'logging.json'))
    (tmp / 'base').mkdir()
    import sqlite3
    con = sqlite3.connect(tmp / 'base/owners.sqlite3'); con.execute('CREATE TABLE owners(x)'); con.commit(); con.close()
    sent = []

    class Manager:
        @staticmethod
        def interfaces(): return ['awg0', 'awg1']
        @staticmethod
        def child(iface, op, payload):
            sent.append((iface, op, payload))
            if iface == 'awg1': raise RuntimeError('database is locked')
            return {'ok': True, 'size': 4096, 'vacuumed_at': 1, 'before': 8192, 'after': 4096} if payload.get('vacuum') else {'size': 4096, 'vacuumed_at': 1, 'rows': {}}
    status = module.db_status(Manager)['databases']
    assert [d['name'] for d in status] == ['awg0', 'awg1', 'owners'] and status[1]['error'] == 'database is locked'
    result = module.db_vacuum(Manager)
    assert result['freed'] >= 4096 and ('awg0', 'db-maintain', {'vacuum': True}) in sent
    assert audit_events(tmp)[-1]['event'] == 'databases_compacted'
    with pytest.raises(ValueError, match='7 to 730'):
        module.logging_set({'traffic_days': 3})
    assert module.logging_set({'traffic_days': 90, 'client_traffic_days': 365})['settings']['traffic_days'] == 90


def test_logs_tab_has_retention_and_a_compact_button(ui):
    app, client, calls = ui
    original = app.ctl

    def fake(op, data=None):
        if op == 'db-status': return {'databases': [{'name': 'awg0', 'size': 2 << 20, 'vacuumed_at': 1795836000}]}
        if op == 'db-vacuum': calls.append((op, {})); return {'ok': True, 'freed': 1 << 20}
        return original(op, data)
    app.ctl = fake
    page = client.get('/maintenance?tab=logs')
    assert 'name="traffic_days"' in page.text and 'name="client_traffic_days"' in page.text and 'id="databases"' in page.text
    assert '<td class="mono">awg0</td><td>2.0 MiB</td><td>2026-11-28 03:20</td>' in page.text
    done = client.post('/maintenance/databases/vacuum', data={'csrf': token(page)}, follow_redirects=False)
    assert done.headers['location'] == '/maintenance?tab=logs&compacted=1048576#databases' and ('db-vacuum', {}) in calls
    assert 'Базы сжаты, освобождено' in client.get('/maintenance?tab=logs&compacted=1048576').text


# ------------------------------------------------------------------ metrics
def test_metrics_settings_need_the_password_and_keep_only_a_hash(admin, monkeypatch):
    module, tmp = admin
    monkeypatch.setenv('AWG31_METRICS', str(tmp / 'metrics.json'))
    as_panel(monkeypatch)
    with pytest.raises(ValueError, match='password'):
        module.metrics_set({'enabled': True, 'password': 'wrong'})
    made = module.metrics_set({'enabled': True, 'per_client': False, 'password': PASSWORD})
    stored = json.loads((tmp / 'metrics.json').read_text())
    assert made['token'] and made['token'] not in json.dumps(stored) and stored['token_hash'] == hashlib.sha256(made['token'].encode()).hexdigest()
    assert oct((tmp / 'metrics.json').stat().st_mode & 0o777) == '0o640' and stored['per_client'] is False
    again = module.metrics_set({'enabled': True, 'per_client': True, 'password': PASSWORD})
    assert again['token'] == '' and json.loads((tmp / 'metrics.json').read_text())['token_hash'] == stored['token_hash']
    new = module.metrics_set({'enabled': True, 'regenerate': True, 'password': PASSWORD})['token']
    assert new and new != made['token']
    assert module.metrics_set({'enabled': False, 'password': PASSWORD})['enabled'] is False
    assert [x['event'] for x in audit_events(tmp)].count('metrics_changed') == 4


def test_metrics_collect_gathers_servers_and_backups(admin, monkeypatch):
    module, tmp = admin
    monkeypatch.setenv('AWG31_METRICS', str(tmp / 'metrics.json'))
    backup(tmp)
    (tmp / 'verify.json').write_text(json.dumps({'checked_at': 5, 'ok': True}))

    class Manager:
        @staticmethod
        def interfaces(): return ['awg0', 'awg1']
        @staticmethod
        def child(iface, op, payload):
            if iface == 'awg1': raise RuntimeError('down')
            return {'interface': 'awg0', 'running': True, 'port': 51820, 'clients': [{'name': 'phone', 'enabled': True}]}
    data = module.metrics_collect(Manager)
    assert data['servers'][1] == {'interface': 'awg1', 'running': False, 'error': True, 'clients': []}
    assert data['backups'] == {'count': 1, 'last': 1795834800, 'verified_at': 5, 'verify_ok': True}


SNAPSHOT = {'servers': [{'interface': 'awg0', 'running': True, 'port': 51820, 'clients': [
    {'name': 'phone', 'enabled': True, 'used': 10, 'limit': 0, 'handshake': int(time.time()) - 30, 'received': 100, 'sent': 200, 'group': ''},
    {'name': 'my "tv"', 'enabled': False, 'used': 0, 'limit': 5, 'handshake': 0, 'received': 0, 'sent': 0, 'group': ''}]},
    {'interface': 'awg1', 'running': False, 'error': True, 'clients': []}],
    'per_client': True, 'backups': {'count': 2, 'last': 1795834800, 'verified_at': 5, 'verify_ok': False}}


def metrics_app(ui, tmp_path, per_client=True):
    app, client, calls = ui
    token_ = 'T' * 43
    file = tmp_path / 'metrics.json'
    file.write_text(json.dumps({'enabled': True, 'per_client': per_client, 'token_hash': hashlib.sha256(token_.encode()).hexdigest()}))
    app.METRICS_FILE = file
    app.METRICS_CACHE.update(at=0.0, body='')
    original = app.ctl
    app.ctl = lambda op, data=None: (calls.append((op, {})) or {**SNAPSHOT, 'per_client': per_client}) if op == 'metrics' else original(op, data)
    app._sub_hits.clear(); app._sub_failures.clear()
    return app, client, calls, token_


def test_metrics_endpoint_needs_the_token_and_speaks_prometheus(ui, tmp_path):
    from fastapi.testclient import TestClient
    app, client, calls, token_ = metrics_app(ui, tmp_path)
    scraper = TestClient(app.app)                                   # not signed in: Prometheus has no session
    assert scraper.get('/metrics').status_code == 401
    assert scraper.get('/metrics', headers={'Authorization': 'Bearer wrong'}).status_code == 401
    reply = scraper.get('/metrics', headers={'Authorization': 'Bearer ' + token_})
    assert reply.status_code == 200 and reply.headers['content-type'].startswith('text/plain; version=0.0.4')
    text = reply.text
    for line in ('awg31_server_up{server="awg0"} 1', 'awg31_server_up{server="awg1"} 0', 'awg31_server_clients_online{server="awg0"} 1',
                 'awg31_server_clients{server="awg0",state="disabled"} 1', 'awg31_server_receive_bytes_total{server="awg0"} 100',
                 'awg31_client_transmit_bytes_total{server="awg0",client="phone"} 200', 'awg31_client_enabled{server="awg0",client="my \\"tv\\""} 0',
                 'awg31_backup_verify_ok 0', 'awg31_backups 2', '# TYPE awg31_server_receive_bytes_total counter'):
        assert line in text, line
    assert 'PrivateKey' not in text and 'public_key' not in text
    scraper.get('/metrics', headers={'Authorization': 'Bearer ' + token_})
    assert [op for op, _ in calls].count('metrics') == 1                          # cached for a few seconds
    app.METRICS_FILE.write_text(json.dumps({'enabled': False, 'token_hash': 'x'}))
    assert scraper.get('/metrics', headers={'Authorization': 'Bearer ' + token_}).status_code == 404


def test_metrics_without_client_names(ui, tmp_path):
    from fastapi.testclient import TestClient
    app, client, calls, token_ = metrics_app(ui, tmp_path, per_client=False)
    text = TestClient(app.app).get('/metrics', headers={'Authorization': 'Bearer ' + token_}).text
    assert 'awg31_server_up' in text and 'awg31_client_' not in text and 'phone' not in text


def test_metrics_tab_turns_it_on_and_shows_the_token_once(ui, tmp_path):
    app, client, calls = ui
    app.METRICS_FILE = tmp_path / 'metrics.json'
    original = app.ctl
    app.ctl = lambda op, data=None: (calls.append((op, dict(data))) or {'ok': True, 'token': 'S' * 43}) if op == 'metrics-set' else original(op, data)
    page = client.get('/maintenance?tab=metrics')
    assert page.status_code == 200 and 'scrape_configs:' in page.text and "targets: [&#x27;127.0.0.1" in page.text
    made = client.post('/maintenance/metrics', data={'csrf': token(page), 'enabled': '1', 'per_client': '1', 'password': 'pw'})
    assert 'value="' + 'S' * 43 + '"' in made.text
    assert ('metrics-set', {'enabled': True, 'per_client': True, 'regenerate': False, 'password': 'pw'}) in calls


def test_new_operations_are_for_the_panel_only():
    panel, bot = set(sudo_list('AWG31_SUDO_COMMANDS')), set(sudo_list('AWG31_BOT_SUDO_COMMANDS'))
    new = {'backup-verify', 'db-status', 'db-vacuum', 'metrics', 'metrics-set'}
    assert new <= panel and not new & bot
    bot_source = (ROOT / 'src/awg31bot.py').read_text()
    assert "'verify_failed': 'backups'" in bot_source and "event == 'backup_verify_failed'" in bot_source
    menu = (ROOT / 'scripts/awg31-menu').read_text()
    assert 'backup-verify)' in menu and 'db-vacuum)' in menu
