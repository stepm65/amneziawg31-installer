"""The root control helper: same answers as `sudo awg31mgr`, the same permissions, and the clients' fallback.

The end-to-end part starts the real helper on a private socket over a small
real state (SQLite database and configuration of awg0), with fake `ip` and `awg`
on PATH, and compares every answer with a direct run of awg31mgr.
"""
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MGR = ROOT / 'src' / 'awg31mgr'
HELPER = ROOT / 'src' / 'awg31helper'
sys.path.insert(0, str(ROOT / 'src'))
import awg31client  # noqa: E402

helper = SourceFileLoader('awg31helper_test', str(HELPER)).load_module()
needs_root = pytest.mark.skipif(os.geteuid() != 0, reason='awg31mgr and the helper run as root only')

FAKE_AWG = '''#!/bin/sh
case "$1" in
  genkey|genpsk) python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())' ;;
  pubkey) python3 -c 'import base64,hashlib,sys;print(base64.b64encode(hashlib.sha256(sys.stdin.read().encode()).digest()).decode())' ;;
  *) exit 1 ;;
esac
'''


def sudo_rule(user, operations, manager=MGR):
    return f'{user} ALL=(root) NOPASSWD: ' + ', '.join(f'{manager} {op}' for op in operations) + '\n'


PANEL_OPS = subprocess.run(['bash', '-c', f'. {ROOT}/scripts/sudoers.sh; printf "%s\\n" "${{AWG31_SUDO_COMMANDS[@]}}"'],
                           capture_output=True, text=True, check=True).stdout.split()


@pytest.fixture
def world(tmp_path):
    """A one-server installation in tmp_path and the environment both ways of calling need."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    (bin_dir / 'awg').write_text(FAKE_AWG)
    (bin_dir / 'ip').write_text('#!/bin/sh\nexit 1\n')          # every interface is down: nothing live to sync
    for tool in ('awg', 'ip'):
        (bin_dir / tool).chmod(0o755)
    env = {'PATH': f'{bin_dir}:/usr/bin:/bin', 'HOME': str(tmp_path), 'AWG31_ROOT': str(tmp_path / 'root'),
           'AWG31_CONFIG_DIR': str(tmp_path / 'conf'), 'AWG31_CTL_PATH': str(ROOT / 'src' / 'awg31ctl'),
           'AWG31_AUDIT': str(tmp_path / 'audit.jsonl'), 'AWG31_MGR_PATH': str(MGR),
           'AWG31_HELPER_SOCKET': str(tmp_path / 'control.sock'), 'AWG31_HELPER_SUDOERS': str(tmp_path / 'sudoers'),
           'AWG31_HELPER_GROUP': 'root'}
    (tmp_path / 'conf').mkdir()
    (tmp_path / 'root').mkdir()
    setup = f'''
import json, sys
from importlib.machinery import SourceFileLoader
ctl = SourceFileLoader('ctl', {str(ROOT / 'src' / 'awg31ctl')!r}).load_module()
con = ctl.get_conn(True)
cfg = dict(subnet='10.10.54.0/24', server_ip='10.10.54.1', port=45678, mtu=1380, endpoint='vpn.example.net', dns='1.1.1.1',
           mode='full', uplink='ens3', private_key='a' * 44, public_key='b' * 44)
ctl.put_settings(con, {{**cfg, **ctl.fresh_obfuscation()}})
con.commit()
ctl.apply(ctl.get_settings(con), con)
'''
    subprocess.run([sys.executable, '-c', setup], check=True, env={**env, 'AWG31_DB': str(tmp_path / 'root' / 'state.sqlite3'),
                                                                    'AWG31_CONF': str(tmp_path / 'conf' / 'awg0.conf'),
                                                                    'AWG31_INTERFACE': 'awg0'})
    sudoers = tmp_path / 'sudoers'
    sudoers.write_text(sudo_rule('root', PANEL_OPS))
    sudoers.chmod(0o440)
    return tmp_path, env


@pytest.fixture
def running(world):
    tmp_path, env = world
    process = subprocess.Popen([sys.executable, str(HELPER)], env=env, stderr=subprocess.PIPE, text=True)
    sock = Path(env['AWG31_HELPER_SOCKET'])
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.05)
    assert sock.exists(), process.stderr.read() if process.poll() is not None else 'no socket'
    yield tmp_path, env, process
    process.terminate()
    process.wait(10)


def direct(env, op, data=None):
    proc = subprocess.run([sys.executable, str(MGR), op], input=json.dumps(data) if data is not None else '',
                          capture_output=True, text=True, env=env, timeout=60)
    return proc.returncode, proc.stdout, proc.stderr


def through_helper(env, op, data=None):
    return raw_request(env, {'op': op, 'input': json.dumps(data) if data is not None else None})


def raw_request(env, request, *, frame=None):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(60)
    connection.connect(env['AWG31_HELPER_SOCKET'])
    try:
        body = json.dumps(request).encode() if frame is None else frame
        connection.sendall(struct.pack('>I', len(body)) + body if frame is None else frame)
        header = connection.recv(4)
        if not header:
            return None
        size = struct.unpack('>I', header)[0]
        data = b''
        while len(data) < size:
            data += connection.recv(size - len(data))
        reply = json.loads(data)
        return reply['rc'], reply['stdout'], reply['stderr']
    finally:
        connection.close()


def answer(result):
    rc, out, err = result
    return rc, json.loads(out) if out.strip() else None, json.loads(err) if err.strip() else None


@needs_root
def test_helper_gives_the_same_answers_as_awg31mgr(running):
    tmp_path, env, _ = running
    for op, data in [('servers', None), ('list', {'interface': 'awg0'}), ('status', {'interface': 'awg0'}),
                     ('backup-policy', None), ('obfuscation-generate', None)]:
        mine, reference = answer(through_helper(env, op, data)), answer(direct(env, op, data))
        if op == 'obfuscation-generate':                    # random by design: compare the shape
            assert mine[0] == 0 and set(mine[1]) == set(reference[1])
        else:
            assert mine == reference, op
    assert answer(through_helper(env, 'servers'))[1]['servers'][0]['interface'] == 'awg0'


@needs_root
def test_changes_through_the_helper_are_real_and_errors_match(running):
    tmp_path, env, _ = running
    rc, out, err = through_helper(env, 'add', {'interface': 'awg0', 'name': 'phone'})
    assert rc == 0, err
    created = json.loads(out)
    assert created['name'] == 'phone' and 'PrivateKey = ' in created['config']
    listed = answer(direct(env, 'list', {'interface': 'awg0'}))[1]
    assert [c['name'] for c in listed['clients']] == ['phone'], 'the helper changed the real database'
    assert '[Peer]' in (tmp_path / 'conf' / 'awg0.conf').read_text()
    assert through_helper(env, 'disable', {'interface': 'awg0', 'name': 'phone'})[0] == 0
    assert answer(direct(env, 'list', {'interface': 'awg0'}))[1]['clients'][0]['enabled'] in (0, False)
    for op, data in [('add', {'interface': 'awg0', 'name': 'bad name!'}), ('add', {'interface': 'awg0', 'name': 'phone'}),
                     ('list', {'interface': 'awg7'}), ('list', {'interface': '../etc'})]:
        mine, reference = answer(through_helper(env, op, data)), answer(direct(env, op, data))
        assert mine[0] == reference[0] == 1 and mine[2] == reference[2], (op, data, mine, reference)
    assert through_helper(env, 'delete', {'interface': 'awg0', 'name': 'phone'})[0] == 0
    assert answer(direct(env, 'list', {'interface': 'awg0'}))[1]['clients'] == []


@needs_root
def test_helper_grants_exactly_what_the_sudo_rules_grant(running):
    tmp_path, env, _ = running
    sudoers = tmp_path / 'sudoers'
    sudoers.chmod(0o640)
    sudoers.write_text(sudo_rule('root', ['servers', 'list']) + sudo_rule('somebody', ['delete', 'add']))
    sudoers.chmod(0o440)
    assert through_helper(env, 'servers')[0] == 0
    for op in ('add', 'delete', 'server-delete', 'password-reset', 'totp-reset', 'backup-encryption-set', 'init'):
        rc, out, err = through_helper(env, op, {'interface': 'awg0', 'name': 'x'})
        assert rc == 1 and out == '' and json.loads(err) == {'error': 'Operation not permitted'}, op
    assert answer(direct(env, 'list', {'interface': 'awg0'}))[1]['clients'] == [], 'nothing was created'
    # A rule naming another program, or extra arguments, grants nothing.
    sudoers.chmod(0o640)
    sudoers.write_text('root ALL=(root) NOPASSWD: /usr/bin/awg31mgr add, ' + f'{MGR} add --force, {MGR} list\n')
    sudoers.chmod(0o440)
    assert through_helper(env, 'add', {'interface': 'awg0', 'name': 'x'})[0] == 1
    assert through_helper(env, 'list', {'interface': 'awg0'})[0] == 0
    # A rule file others can write is not trusted at all; a removed file revokes everything.
    sudoers.chmod(0o666)
    assert through_helper(env, 'list', {'interface': 'awg0'})[0] == 1
    sudoers.unlink()
    assert through_helper(env, 'servers')[0] == 1


@needs_root
def test_malformed_requests_get_nothing(running):
    tmp_path, env, process = running
    assert raw_request(env, {'op': 'list; rm -rf /', 'input': None})[0] == 1
    assert raw_request(env, {'op': 'list', 'input': {'not': 'a string'}})[0] == 1
    assert raw_request(env, ['list'])[0] == 1
    assert raw_request(env, None, frame=struct.pack('>I', 10 * 1024 * 1024)) is None, 'oversized: closed without an answer'
    assert raw_request(env, None, frame=struct.pack('>I', 5) + b'{oops') is None
    assert process.poll() is None and through_helper(env, 'servers')[0] == 0, 'the helper keeps serving'


@needs_root
def test_socket_is_private_to_the_group(running):
    tmp_path, env, _ = running
    info = os.stat(env['AWG31_HELPER_SOCKET'])
    assert stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o660 and info.st_uid == 0 and info.st_gid == 0


@needs_root
def test_the_client_uses_the_helper_and_falls_back_to_sudo(running, monkeypatch):
    tmp_path, env, _ = running
    monkeypatch.setattr(awg31client, 'SOCKET', env['AWG31_HELPER_SOCKET'])
    fallback = []
    monkeypatch.setattr(awg31client, 'via_sudo', lambda *a: fallback.append(a) or (0, '{"via": "sudo"}', ''))
    rc, out, _ = awg31client.call('servers', None)
    assert rc == 0 and 'servers' in json.loads(out) and fallback == []
    monkeypatch.setattr(awg31client, 'SOCKET', str(tmp_path / 'missing.sock'))
    assert awg31client.call('list', '{"interface": "awg0"}') == (0, '{"via": "sudo"}', '')
    assert fallback == [('list', '{"interface": "awg0"}', 35)]


def test_no_fallback_once_the_request_was_sent(tmp_path, monkeypatch):
    """If the helper dies mid-request, the operation may have run: it must not be run again through sudo."""
    path = tmp_path / 'dying.sock'
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    monkeypatch.setattr(awg31client, 'SOCKET', str(path))
    monkeypatch.setattr(awg31client, 'via_sudo', lambda *a: pytest.fail('ran twice'))
    import threading

    def accept_and_drop():
        connection, _ = server.accept()
        connection.recv(100)
        connection.close()
    threading.Thread(target=accept_and_drop, daemon=True).start()
    with pytest.raises(ConnectionError):
        awg31client.call('delete', '{"name": "x"}', timeout=5)
    server.close()


def test_run_program_behaves_like_a_fresh_process(tmp_path):
    code = compile('import os, sys\nprint(sys.argv[1:], os.environ.get("ONLY"), sys.stdin.read())\n'
                   'print("to stderr", file=sys.stderr)\nsys.exit(int(sys.argv[1]))', 'prog', 'exec')
    rc, out, err = helper.run_program(code, 'prog', ['3'], 'payload', {'ONLY': 'this'}, timeout=10)
    assert (rc, out, err) == (3, "['3'] this payload\n", 'to stderr\n')
    assert 'ONLY' not in os.environ, 'the environment of the caller is untouched'
    rc, out, err = helper.run_program(compile('raise KeyError("boom")', 'p', 'exec'), 'p', [], None, timeout=10)
    assert rc == 1 and 'KeyError' in err
    rc, _, err = helper.run_program(compile('import sys; sys.exit("bye")', 'p', 'exec'), 'p', [], None, timeout=10)
    assert rc == 1 and err == 'bye\n'
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        helper.run_program(compile('import time; time.sleep(30)', 'p', 'exec'), 'p', [], None, timeout=0.5)
    assert time.monotonic() - started < 5


def test_changed_sources_are_recompiled(tmp_path):
    source = tmp_path / 'prog'
    source.write_text('VALUE = 1\n')
    cache = helper.Code()
    first = cache.get(str(source))
    assert cache.get(str(source)) is first
    time.sleep(0.01)
    source.write_text('VALUE = 22\n')
    namespace = {}
    exec(cache.get(str(source)), namespace)
    assert namespace['VALUE'] == 22


def test_permission_parser_reads_only_our_rule_format(tmp_path, monkeypatch):
    rules = tmp_path / 'rules'
    rules.write_text(sudo_rule('awgpanel', ['servers', 'list']) + sudo_rule('awgbot', ['list'])
                     + '# comment\nawgpanel ALL=(ALL) NOPASSWD: ALL\nDefaults env_reset\n')
    monkeypatch.setattr(helper, 'SUDOERS', [rules, tmp_path / 'absent'])
    monkeypatch.setattr(helper, 'MGR', str(MGR))
    if os.geteuid() == 0:
        rules.chmod(0o440)
        assert helper.permissions() == {'awgpanel': {'servers', 'list'}, 'awgbot': {'list'}}
    else:
        assert helper.permissions() == {}, 'a rule file not owned by root grants nothing'


def test_installed_sudo_rule_and_helper_agree_on_the_manager_path():
    rendered = subprocess.run(['bash', '-c', f'. {ROOT}/scripts/sudoers.sh; awg31_render_sudoers; awg31_render_bot_sudoers'],
                              capture_output=True, text=True, check=True).stdout
    for line in rendered.splitlines():
        match = helper.RULE.fullmatch(line)
        assert match, line
        assert all(item.split()[0] == '/usr/local/sbin/awg31mgr' for item in match.group(2).split(','))
    assert subprocess.run([sys.executable, '-c', f'from importlib.machinery import SourceFileLoader as L; '
                           f'print(L("h", {str(HELPER)!r}).load_module().MGR)'], capture_output=True, text=True,
                          env={'PATH': '/usr/bin:/bin'}).stdout.strip() == '/usr/local/sbin/awg31mgr'


# ------------------------------------------------------------------ panel side: one answer per request
def test_panel_asks_once_per_request_for_the_same_read(monkeypatch):
    import importlib.util
    import hashlib
    salt = b'8' * 16
    auth = {'salt': salt.hex(), 'session_key': 'Z' * 48,
            'password_hash': hashlib.scrypt(b'pw-for-cache-test', salt=salt, n=2**14, r=8, p=1, dklen=32).hex()}
    path = Path(os.environ.get('TMPDIR', '/tmp')) / f'awg31-cache-auth-{os.getpid()}.json'
    path.write_text(json.dumps(auth))
    monkeypatch.setenv('AWG31_AUTH', str(path))
    monkeypatch.setenv('AWG31_COOKIE_SECURE', '0')
    spec = importlib.util.spec_from_file_location('web_cache', ROOT / 'src' / 'web.py')
    web = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(web)
    asked = []

    def underlying(op, data=None):
        asked.append(op)
        if op == 'servers':
            return {'servers': [{'interface': 'awg0', 'subnet': '10.77.10.0/24', 'port': 45678, 'clients': 1, 'running': True}]}
        if op == 'list':
            return {'interface': 'awg0', 'subnet': '10.77.10.0/24', 'port': 45678, 'mtu': 1380, 'dns': '1.1.1.1',
                    'endpoint': 'vpn.example.test', 'mode': 'full', 'uplink': 'ens3', 'running': True, 'public_key': 'A' * 44,
                    'clients': [{'name': 'alpha', 'ip': '10.77.10.2', 'enabled': True, 'stats': {}}]}
        return {'ok': True}
    monkeypatch.setattr(web, '_ctl_call', underlying)
    from fastapi.testclient import TestClient
    client = TestClient(web.app)
    assert client.post('/login', data={'password': 'pw-for-cache-test'}).status_code == 200
    for page in ('/', '/servers/awg0/clients'):
        asked.clear()
        assert client.get(page).status_code == 200
        assert asked.count('servers') == 1, (page, asked)
    path.unlink()
    # Outside a request nothing is cached; inside one, a change forgets earlier reads and answers are copies.
    asked.clear()
    web.ctl('servers'); web.ctl('servers')
    assert asked == ['servers', 'servers']
    token = web._REQUEST_CACHE.set({})
    try:
        asked.clear()
        first = web.ctl('servers')
        first['servers'].clear()
        assert web.ctl('servers')['servers'], 'a caller changing its answer does not change the next one'
        web.ctl('add', {'name': 'x'})
        web.ctl('servers')
        assert asked == ['servers', 'add', 'servers']
    finally:
        web._REQUEST_CACHE.reset(token)
