"""0.14.0: logs — address masking, connection history, the journal viewer, handshake debug,
the audit log with paging and filters, and the support report.
"""
import base64
import gzip
import io
import json
import sqlite3
import tarfile
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from test_password_guards import admin  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
ctl = SourceFileLoader('awg31ctl_logs', str(ROOT / 'src/awg31ctl')).load_module()
# Public resolver addresses stand in for client addresses: they are global, as real ones are.
PUBLIC_A, PUBLIC_B = '8.8.8.8', '1.1.1.1'


@pytest.fixture
def logs(admin, monkeypatch):
    module, tmp = admin
    monkeypatch.setenv('AWG31_LOGGING', str(tmp / 'etc/logging.json'))
    monkeypatch.setenv('AWG31_IP_MASK_KEY', str(tmp / 'etc/ip-mask.key'))
    (tmp / 'etc').mkdir(exist_ok=True)
    return module, tmp


# ------------------------------------------------------------------ masking
def test_masking_modes_and_only_public_addresses(logs):
    module, tmp = logs
    assert module.mask_ip(PUBLIC_A, 'none') == PUBLIC_A
    assert module.mask_ip(PUBLIC_A, 'partial') == '8.8.8.x'
    assert module.mask_ip('2a00:1450:4001:80b::200e', 'partial') == '2a00:1450:4001:…'
    full = module.mask_ip(PUBLIC_A, 'full')
    assert full.startswith('IP-') and len(full) == 9 and full == module.mask_ip(PUBLIC_A, 'full'), 'stable'
    assert full != module.mask_ip(PUBLIC_B, 'full')
    key = tmp / 'etc/ip-mask.key'
    assert key.stat().st_mode & 0o777 == 0o600 and len(key.read_bytes()) == 32
    text = f'failed sign-in from {PUBLIC_A}, client 10.77.10.2 via 192.168.1.5, local 127.0.0.1, v6 2a00:1450:4001:80b::200e'
    masked = module.mask_text(text, 'partial')
    assert '8.8.8.x' in masked and '10.77.10.2' in masked and '192.168.1.5' in masked and '127.0.0.1' in masked
    assert '2a00:1450:4001:…' in masked and PUBLIC_A not in masked
    assert module.mask_text(text, 'none') == text
    assert PUBLIC_A not in module.mask_text(text, 'full') and 'IP-' in module.mask_text(text, 'full')


def test_controller_and_admin_mask_the_same_way(logs, monkeypatch):
    module, tmp = logs
    monkeypatch.setattr(ctl, 'MASK_KEY', tmp / 'etc/ip-mask.key')
    for mode in ('none', 'partial', 'full'):
        assert ctl.mask_endpoint(f'{PUBLIC_A}:51820', mode).split(':51820')[0] == module.mask_ip(PUBLIC_A, mode)
    assert ctl.mask_endpoint('[2a00:1450:4001:80b::200e]:51820', 'partial') == module.mask_ip('2a00:1450:4001:80b::200e', 'partial')
    assert ctl.mask_endpoint('', 'partial') == '' and ctl.mask_endpoint('(none)', 'full') == ''
    monkeypatch.setattr(ctl, 'LOGGING', tmp / 'etc/logging.json')
    module.logging_set({'history': True, 'retention_days': 7, 'masking': 'full'})
    assert ctl.logging_settings() == module.logging_settings() == {'history': True, 'retention_days': 7, 'masking': 'full',
                                                                    'traffic_days': 32, 'client_traffic_days': 62}


def test_logging_settings_are_checked_and_audited(logs):
    module, tmp = logs
    assert module.logging_settings() == {'history': False, 'retention_days': 30, 'masking': 'partial', 'traffic_days': 32, 'client_traffic_days': 62}
    for bad in ({'retention_days': 0}, {'retention_days': 400}, {'retention_days': 'x'}, {'masking': 'some'}):
        with pytest.raises(ValueError):
            module.logging_set(bad)
    module.logging_set({'history': True, 'retention_days': '14', 'masking': 'none'})
    assert json.loads((tmp / 'etc/logging.json').read_text()) == {'history': True, 'retention_days': 14, 'masking': 'none', 'traffic_days': 32, 'client_traffic_days': 62}
    assert 'logging_changed' in (tmp / 'audit.jsonl').read_text()


def test_sign_in_addresses_in_the_audit_log_follow_the_masking(logs):
    module, tmp = logs
    module.audit({'event': 'login_failed', 'target': PUBLIC_A})
    module.logging_set({'masking': 'full'})
    module.audit({'event': 'login_success', 'target': PUBLIC_A})
    module.logging_set({'masking': 'none'})
    module.audit({'event': 'login_success', 'target': PUBLIC_B})
    entries = [json.loads(x) for x in (tmp / 'audit.jsonl').read_text().splitlines()]
    targets = [e['target'] for e in entries if e['event'].startswith('login')]
    assert targets[0] == '8.8.8.x' and targets[1].startswith('IP-') and targets[2] == PUBLIC_B
    assert PUBLIC_A not in (tmp / 'audit.jsonl').read_text(), 'never stored while masking was on'


# ------------------------------------------------------------------ connection history
@pytest.fixture
def server(logs, tmp_path, monkeypatch):
    module, tmp = logs
    monkeypatch.setattr(ctl, 'DB', tmp / 'state.sqlite3')
    monkeypatch.setattr(ctl, 'LOGGING', tmp / 'etc/logging.json')
    monkeypatch.setattr(ctl, 'MASK_KEY', tmp / 'etc/ip-mask.key')
    con = ctl.get_conn(create=True)
    con = ctl.get_conn()                         # the migration adds the history table
    con.execute("INSERT INTO clients(name, ip, private_key, public_key, psk, created_at) VALUES('phone','10.77.10.2','x','P1','y','now')")
    con.execute("INSERT INTO clients(name, ip, private_key, public_key, psk, created_at) VALUES('laptop','10.77.10.3','x','P2','y','now')")
    con.commit()
    return module, con


def rows(con, name='phone'):
    return [dict(r) for r in con.execute('SELECT * FROM sessions WHERE client=? ORDER BY id', (name,))]


def test_history_records_connections_from_handshakes(server):
    module, con = server
    seen = lambda when, address=f'{PUBLIC_A}:40000': {'handshake': when, 'endpoint': address}
    ctl.track_sessions(con, {'phone': (seen(1000), 10, 20)}, 1010)
    assert rows(con) == [], 'history is off by default'
    module.logging_set({'history': True, 'masking': 'partial'})
    ctl.track_sessions(con, {'phone': (seen(1000), 10, 20), 'laptop': (None, 0, 0)}, 1010)
    first = rows(con)
    assert len(first) == 1 and first[0]['address'] == '8.8.8.x' and first[0]['ended'] == 0 and first[0]['rx'] == 10
    assert rows(con, 'laptop') == []
    ctl.track_sessions(con, {'phone': (seen(1110), 5, 5)}, 1070)
    ctl.track_sessions(con, {'phone': (seen(1110), 0, 0)}, 1130)
    assert len(rows(con)) == 1 and rows(con)[0]['last_seen'] == 1110 and rows(con)[0]['rx'] == 15
    # Another address: the old connection ends, a new one starts.
    ctl.track_sessions(con, {'phone': (seen(1250, f'{PUBLIC_B}:5000'), 1, 1)}, 1250)
    sessions = rows(con)
    assert len(sessions) == 2 and sessions[0]['ended'] == 1110 and sessions[1]['address'] == '1.1.1.x'
    # No handshake for longer than three minutes: closed at the last one seen.
    ctl.track_sessions(con, {'phone': (seen(1250, f'{PUBLIC_B}:5000'), 0, 0)}, 1250 + 181)
    assert rows(con)[1]['ended'] == 1250
    # Switching the history off closes what is open and records nothing new.
    ctl.track_sessions(con, {'phone': (seen(2000), 0, 0)}, 2000)
    module.logging_set({'history': False})
    ctl.track_sessions(con, {'phone': (seen(2060), 0, 0)}, 2060)
    assert all(r['ended'] for r in rows(con)) and len(rows(con)) == 3


def test_full_masking_never_stores_the_address_and_old_entries_expire(server):
    module, con = server
    module.logging_set({'history': True, 'masking': 'full', 'retention_days': 1})
    ctl.track_sessions(con, {'phone': ({'handshake': 1000, 'endpoint': f'{PUBLIC_A}:40000'}, 0, 0)}, 1000)
    ctl.track_sessions(con, {'phone': ({'handshake': 1000, 'endpoint': f'{PUBLIC_A}:40000'}, 0, 0)}, 1000 + 200)
    stored = json.dumps(rows(con))
    assert PUBLIC_A not in stored and '"IP-' in stored
    ctl.track_sessions(con, {'phone': (None, 0, 0)}, 1000 + 86400 + 300)
    assert rows(con) == [], 'removed after the retention period'


def test_sessions_operation_lists_newest_first(server, monkeypatch):
    module, con = server
    module.logging_set({'history': True})
    for start in (1000, 5000, 9000):
        con.execute('INSERT INTO sessions(client, started, last_seen, ended, address) VALUES(?,?,?,?,?)',
                    ('phone', start, start + 60, start + 60, '8.8.8.x'))
    monkeypatch.setattr(ctl, 'read_json', lambda: {'name': 'phone', 'limit': 2})
    result = ctl.client_sessions(con)
    assert [r['started'] for r in result['sessions']] == [9000, 5000] and result['history'] is True
    monkeypatch.setattr(ctl, 'read_json', lambda: {'name': 'nobody'})
    with pytest.raises(ValueError):
        ctl.client_sessions(con)


def test_live_stats_read_the_endpoint(monkeypatch):
    dump = ('priv\tpub\t51820\toff\n'
            f'P1\tpsk\t{PUBLIC_A}:40000\t10.77.10.2/32\t1700000000\t100\t200\t25\n'
            'P2\tpsk\t(none)\t10.77.10.3/32\t0\t0\t0\toff\n')
    monkeypatch.setattr(ctl, 'run', lambda *a, **k: dump)
    stats = ctl.live_stats()
    assert stats['P1']['endpoint'] == f'{PUBLIC_A}:40000' and stats['P2']['endpoint'] == ''


# ------------------------------------------------------------------ journal viewer
class Manager:
    @staticmethod
    def interfaces():
        return ['awg0']

    @staticmethod
    def conf_path(iface):
        return Path('/nonexistent') / f'{iface}.conf'


def test_journal_reading_is_limited_to_known_sources(logs, monkeypatch):
    module, tmp = logs
    calls = []
    output = (f'2026-11-20T10:00 kernel: amneziawg: awg0: Receiving handshake initiation from peer 3 ({PUBLIC_A}:51820)\n'
              '2026-11-20T10:00 kernel: usb 1-1: new device\n'
              '2026-11-20T10:01 kernel: amneziawg: awg0: Keypair 4 created for peer 3\n')

    def journal(cmd, **kwargs):
        calls.append(cmd)
        return type('P', (), {'returncode': 0, 'stdout': output, 'stderr': ''})()
    monkeypatch.setattr(module.subprocess, 'run', journal)
    result = module.logs_read({'source': 'kernel', 'lines': 100, 'level': 'warning'})
    assert result['lines'] == [output.splitlines()[0].replace(PUBLIC_A, '8.8.8.x'), output.splitlines()[2]]
    assert calls[-1][:3] == ['journalctl', '--no-pager', '--no-hostname'] and '-k' in calls[-1] and calls[-1][calls[-1].index('-p') + 1] == '4'
    module.logs_read({'source': 'server:awg0', 'lines': 5}, Manager)
    assert 'awg-quick@awg0.service' in calls[-1] and calls[-1][calls[-1].index('-n') + 1] == '20', 'at least 20 lines'
    result = module.logs_read({'source': 'kernel', 'query': 'KEYPAIR'})
    assert len(result['lines']) == 1
    for bad in ({'source': 'sshd'}, {'source': 'server:awg5'}, {'source': '-u ssh'}, {'source': 'panel', 'level': 'debug'},
                {'source': 'panel', 'query': 'a\nb'}):
        with pytest.raises(ValueError):
            module.logs_read(bad, Manager)
    assert all(c[0] == 'journalctl' for c in calls)


# ------------------------------------------------------------------ handshake debug
def test_handshake_debug_switches_itself_off(logs, monkeypatch):
    module, tmp = logs
    control = tmp / 'control'
    control.write_text('')
    monkeypatch.setattr(module, 'DEBUG_CONTROL', control)
    monkeypatch.setattr(module, 'MODULE_DIR', tmp)
    monkeypatch.setenv('AWG31_DEBUG_UNTIL', str(tmp / 'debug-until'))
    commands = []
    monkeypatch.setattr(module.subprocess, 'run', lambda cmd, **k: commands.append(cmd) or
                        type('P', (), {'returncode': 0, 'stdout': '', 'stderr': ''})())
    assert module.handshake_debug() == {'enabled': False, 'until': 0, 'available': True}
    state = module.handshake_debug({'enable': True})
    assert state['enabled'] and control.read_text() == 'module amneziawg +p\n'
    timer = next(c for c in commands if c[0] == 'systemd-run')
    assert '--on-active=15min' in timer and "module amneziawg -p" in timer[-1]
    assert module.handshake_debug()['enabled'] is True
    assert module.handshake_debug({'enable': False})['enabled'] is False and control.read_text() == 'module amneziawg -p\n'
    assert not (tmp / 'debug-until').exists()
    monkeypatch.setattr(module, 'MODULE_DIR', tmp / 'missing')
    with pytest.raises(ValueError, match='not loaded'):
        module.handshake_debug({'enable': True})


# ------------------------------------------------------------------ audit log
def test_audit_log_pages_filters_and_rotated_files(logs):
    module, tmp = logs
    old = '\n'.join(json.dumps({'timestamp': f'2026-10-0{d}T10:00:00+00:00', 'event': 'backup_created', 'target': f'old {d}'})
                    for d in range(1, 4)) + '\n'
    with gzip.open(tmp / 'audit.jsonl.2.gz', 'wt') as f:
        f.write(old)
    with gzip.open(tmp / 'audit.jsonl.1.gz', 'wt') as f:
        f.write(json.dumps({'timestamp': '2026-11-01T10:00:00+00:00', 'event': 'login_failed', 'target': '8.8.8.x'}) + '\n')
    for n in range(60):
        module.audit({'event': 'client_added', 'target': f'awg0/c{n}'})
    first = module.audit_list({'page': 1})
    assert first['total'] == 64 and first['pages'] == 2 and first['entries'][0]['target'] == 'awg0/c59', 'newest first'
    assert module.audit_list({'page': 2})['entries'][-1]['target'] == 'old 1', 'the oldest rotated file last'
    assert [e['target'] for e in module.audit_list({'event': 'backup_created'})['entries']] == ['old 3', 'old 2', 'old 1']
    assert module.audit_list({'until': '2026-10-02'})['total'] == 2 and module.audit_list({'since': '2026-11-01', 'until': '2026-11-01'})['total'] == 1
    assert module.audit_list({'query': 'C7'})['total'] == 1
    for bad in ({'event': 'rm'}, {'since': '01.11.2026'}):
        with pytest.raises(ValueError):
            module.audit_list(bad)
    # The bot reads only the end of a big file.
    recent = module.audit_recent()['entries']
    assert len(recent) == 60 and recent[-1]['target'] == 'awg0/c59'
    with open(tmp / 'audit.jsonl', 'a') as f:
        for n in range(4000):
            f.write(json.dumps({'timestamp': '2026-11-20T10:00:00+00:00', 'event': 'client_added', 'target': 'x' * 80}) + '\n')
    assert len(module.audit_recent()['entries']) == 100


# ------------------------------------------------------------------ support report
def test_support_report_holds_no_secrets(logs, monkeypatch):
    module, tmp = logs
    conf = tmp / 'awg0.conf'
    conf.write_text('[Interface]\nPrivateKey = ' + 'A' * 43 + '=\nHeaderProtectionKey = ' + 'B' * 43 + '=\nListenPort = 51820\n'
                    '[Peer]\nPublicKey = ' + 'C' * 43 + '=\nPresharedKey = ' + 'D' * 43 + '=\nAllowedIPs = 10.77.10.2/32\n')

    class Server(Manager):
        @staticmethod
        def conf_path(iface):
            return conf
    token = '123456789:' + 'T' * 35

    def run(cmd, **kwargs):
        text = {'awg': f'peer: {"E" * 43}=\n  endpoint: {PUBLIC_A}:40000\n  allowed ips: 10.77.10.2/32\n',
                'ip': f'eth0 UP {PUBLIC_B}/24\n', 'journalctl': f'2026-11-20 awg31bot: token {token} failed\n'}.get(cmd[0], 'ok\n')
        return type('P', (), {'returncode': 0, 'stdout': text, 'stderr': ''})()
    monkeypatch.setattr(module.subprocess, 'run', run)
    monkeypatch.setattr(module, 'diagnose', lambda manager, iface: {'kernel': {'ok': True, 'output': '6.8'}})
    report = module.support_report(Server)
    archive = tarfile.open(fileobj=io.BytesIO(base64.b64decode(report['data'])))
    names = [m.name.split('/', 1)[1] for m in archive.getmembers()]
    assert {'system.txt', 'awg0.conf', 'awg-show-awg0.txt', 'journal-bot.txt', 'audit.jsonl', 'README.txt'} <= set(names)
    everything = ''.join(archive.extractfile(m).read().decode() for m in archive.getmembers())
    for secret in ('A' * 43, 'B' * 43, 'C' * 43, 'D' * 43, 'E' * 43, token, PUBLIC_A, PUBLIC_B):
        assert secret not in everything, secret
    assert 'ListenPort = 51820' in everything and '10.77.10.2/32' in everything, 'what helps stays'
    assert all(m.mode == 0o600 for m in archive.getmembers())


# ------------------------------------------------------------------ panel
def test_panel_logs_pages(monkeypatch, tmp_path):
    import hashlib
    from importlib.util import module_from_spec, spec_from_file_location
    salt = b'5' * 16
    (tmp_path / 'auth.json').write_text(json.dumps({'salt': salt.hex(), 'session_key': 'F' * 48, 'password_hash':
        hashlib.scrypt(b'testpassword1234', salt=salt, n=2**14, r=8, p=1, dklen=32).hex()}))
    monkeypatch.setenv('AWG31_AUTH', str(tmp_path / 'auth.json')); monkeypatch.setenv('AWG31_COOKIE_SECURE', '0')
    spec = spec_from_file_location('web_logs', ROOT / 'src/web.py')
    web = module_from_spec(spec); spec.loader.exec_module(web)
    calls = []
    report = io.BytesIO()
    with tarfile.open(fileobj=report, mode='w:gz'):
        pass

    def fake(op, data=None):
        calls.append((op, data))
        return {'servers': {'servers': [{'interface': 'awg0'}]},
                'logging-status': {'settings': {'history': True, 'retention_days': 30, 'masking': 'partial'},
                                   'debug': {'enabled': True, 'until': 1795000000, 'available': True}},
                'logs-read': {'lines': ['2026-11-20 uvicorn: =cmd started <b>']},
                'audit-search': {'entries': [{'timestamp': '2026-11-20T10:00:00', 'event': 'client_added', 'target': '=HYPERLINK("x")'}],
                                 'total': 1, 'page': 1, 'pages': 1, 'events': ['client_added']},
                'support-report': {'name': 'awg31-support-20261120T100000Z.tar.gz', 'data': base64.b64encode(report.getvalue()).decode()},
                'download': {'config': '[Interface]\n', 'name': 'phone'},
                'sessions': {'sessions': [{'started': 1795000000, 'last_seen': 1795003600, 'ended': 1795003600,
                                           'address': '8.8.8.x', 'rx': 1024 ** 3, 'tx': 0}], 'history': True, 'retention_days': 30}
                }.get(op, {'ok': True})
    web.ctl = fake
    from fastapi.testclient import TestClient
    client = TestClient(web.app)
    client.post('/login', data={'password': 'testpassword1234'})
    page = client.get('/maintenance?tab=logs&source=server:awg0&level=error&lines=500&query=handshake')
    assert page.status_code == 200 and '=cmd started &lt;b&gt;' in page.text and 'Сервер awg0 (awg-quick)' in page.text
    assert ('logs-read', {'source': 'server:awg0', 'level': 'error', 'lines': 500, 'query': 'handshake'}) in calls
    assert 'Включена до' in page.text and 'value="0">Выключить сейчас' in page.text
    odd = client.get('/maintenance?tab=logs&source=;rm&lines=7&level=x')
    assert ('logs-read', {'source': 'panel', 'level': 'all', 'lines': 200, 'query': ''}) in calls and odd.status_code == 200
    api = client.get('/api/logs?source=bot')
    assert api.json()['lines'] == ['2026-11-20 uvicorn: =cmd started <b>']
    text = client.get('/maintenance/logs/download?source=kernel')
    assert text.headers['content-type'].startswith('text/plain') and 'attachment; filename="awg31-kernel-' in text.headers['content-disposition']
    token = __import__('re').search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    client.post('/maintenance/logs/settings', data={'csrf': token, 'history': '1', 'retention_days': '7', 'masking': 'full'})
    assert ('logging-set', {'history': True, 'retention_days': '7', 'masking': 'full', 'traffic_days': '32', 'client_traffic_days': '62'}) in calls
    client.post('/maintenance/logs/debug', data={'csrf': token, 'enable': '1'})
    assert ('handshake-debug', {'enable': True}) in calls
    archive = client.post('/maintenance/logs/report', data={'csrf': token})
    assert archive.headers['content-type'] == 'application/gzip' and archive.content == report.getvalue()
    csv = client.get('/maintenance/audit.csv?event=client_added').text
    assert csv.splitlines()[1].endswith('"\'=HYPERLINK(""x"")",'), 'no spreadsheet formulas'
    audit = client.get('/maintenance?tab=audit&event=client_added&since=2026-11-01&page=1')
    assert 'Страница 1 из 1' in audit.text and ('audit-search', {'event': 'client_added', 'since': '2026-11-01', 'until': '',
                                                                 'query': '', 'page': '1'}) in calls
    detail = client.get('/servers/awg0/clients/phone')
    assert 'История подключений' in detail.text and '8.8.8.x' in detail.text and '1.0 GiB' in detail.text
