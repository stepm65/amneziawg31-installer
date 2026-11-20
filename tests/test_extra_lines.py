"""Extra [Interface] lines for clients that run awg-quick (routers, containers, gateways)."""
from importlib.machinery import SourceFileLoader
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import types

import pytest
from fastapi.testclient import TestClient

from test_peer_routes_i import profile, make_client

ROOT = Path(__file__).parents[1]
ctl = SourceFileLoader('awg31_extra_test', str(ROOT / 'src/awg31ctl')).load_module()
sys.path.insert(0, str(ROOT / 'src'))
import amnezialink  # noqa: E402


def template_texts():
    from test_web import create_app  # noqa: F401  (imports web with test settings)
    import web
    t = lambda key: web.tr('ru', key)
    return web, {key: web.extra_template_text(key, t) for key, _ in web.EXTRA_TEMPLATES}


def test_every_template_passes_validation_and_is_valid_shell(tmp_path, monkeypatch):
    from test_web import create_app
    create_app(tmp_path, monkeypatch)
    web, texts = template_texts()
    assert set(texts) == {'gateway', 'mss', 'nat'}
    for key, text in texts.items():
        assert ctl.validate_extra_lines(text) == text, key
        for line in text.split('\n')[1:]:
            command = line.partition('=')[2].strip()
            if line.startswith(('PostUp', 'PostDown')):
                # awg-quick replaces %i, then evals the hook with bash.
                check = subprocess.run(['bash', '-n', '-c', command.replace('%i', 'fi-awg')], capture_output=True, text=True)
                assert check.returncode == 0, (key, check.stderr)
    gateway = texts['gateway']
    assert 'Table = 200' in gateway and 'veth' not in gateway and 'MikroTik' not in gateway
    assert gateway.count('\n#') == 0 and gateway.startswith('# ')


FAKE_IP = r"""#!/bin/bash
state="$STATE"
case "$1 $2 $3" in
  "-o -4 route") printf "%s" "$ROUTE" ;;
  "-o link show") printf "%s\n" "1: lo: <LOOPBACK,UP> mtu 65536" "2: fi-awg: <POINTOPOINT> mtu 1380" "44: veth3@if44: <BROADCAST> mtu 1500" ;;
  "rule del priority")
    # Like iproute2: deleting a rule that does not exist fails.
    [ -s "$state/rule" ] || { echo "RTNETLINK answers: No such file or directory" >&2; exit 2; }
    : > "$state/rule" ;;
  "rule add priority") echo "$*" > "$state/rule" ;;
  *) echo "unexpected ip $*" >&2; exit 9 ;;
esac
"""
FAKE_IPTABLES = r"""#!/bin/bash
echo "$*" >> "$STATE/iptables"
case " $* " in *" -D "*) grep -qxF -- "${*/-D/-A}" "$STATE/iptables" || exit 1 ;; esac
"""


def awg_quick_hooks(text, kind):
    return [line.partition('=')[2].strip().replace('%i', 'fi-awg')
            for line in text.split('\n') if line.startswith(kind + ' ')]


def run_like_awg_quick(hooks, env):
    """awg-quick: set -e -o pipefail, then (eval "$hook") for each hook in turn."""
    script = 'set -e -o pipefail\nfor hook in "$@"; do (eval "$hook"); done\n'
    return subprocess.run(['bash', '-c', script, 'awg-quick', *hooks], env=env, capture_output=True, text=True)


@pytest.mark.parametrize('route, lan', [('default via 172.17.99.1 dev veth3\n', 'veth3'),
                                        ('default via 10.0.0.1 dev veth7\n', 'veth7'),
                                        ('', 'veth3')])
def test_templates_survive_awg_quick_up_and_down(tmp_path, monkeypatch, route, lan):
    """Regression: a failing «ip rule del» on the first start used to tear the tunnel down."""
    from test_web import create_app
    create_app(tmp_path, monkeypatch)
    _, texts = template_texts()
    fake = tmp_path / 'bin'
    fake.mkdir()
    for name, body in (('ip', FAKE_IP), ('iptables', FAKE_IPTABLES)):
        (fake / name).write_text(body)
        (fake / name).chmod(0o755)
    state = tmp_path / 'state'
    state.mkdir()
    env = {'PATH': f'{fake}:/usr/bin:/bin', 'STATE': str(state), 'ROUTE': route}
    gateway = texts['gateway']
    up = run_like_awg_quick(awg_quick_hooks(gateway, 'PostUp'), env)
    assert up.returncode == 0, up.stderr
    assert (state / 'rule').read_text().split() == ['rule', 'add', 'priority', '300', 'iif', lan, 'lookup', '200']
    again = run_like_awg_quick(awg_quick_hooks(gateway, 'PostUp'), env)          # restart without a down
    assert again.returncode == 0, again.stderr
    down = run_like_awg_quick(awg_quick_hooks(gateway, 'PostDown'), env)
    assert down.returncode == 0, down.stderr
    assert (state / 'rule').read_text() == ''
    (state / 'iptables').unlink()
    for key in ('gateway', 'mss', 'nat'):                                         # down without an up
        down = run_like_awg_quick(awg_quick_hooks(texts[key], 'PostDown'), env)
        assert down.returncode == 0, (key, down.stderr)


@pytest.mark.parametrize('text, message', [
    ('[Peer]', 'разделы'),
    ('AllowedIPs = 0.0.0.0/0', 'панель'),
    ('DNS = 9.9.9.9', 'панель'),
    ('Jc = 5', 'панель'),
    ('H1 = 7', 'панель'),
    ('I1 = <r 10>', 'панель'),
    ('SaveConfig = true', 'панель'),
    ('Foo = bar', 'допустимы'),
    ('PostUp', 'Ключ = значение'),
    ('PostUp =', 'пустое'),
    ('PostUp = echo a # b', '#'),
    ('Table = 200\nTable = 201', 'один раз'),
    ('Table = 2 00', 'Table'),
    ('PostUp = echo \x1b[31m', 'управляющие'),
])
def test_unsafe_or_panel_managed_lines_are_refused(text, message):
    with pytest.raises(ValueError, match=message):
        ctl.validate_extra_lines(text)


def test_limits_and_normalisation():
    assert ctl.validate_extra_lines('  postup = echo up  \r\n\r\n# note\ntable=off') == 'PostUp = echo up\n# note\nTable = off'
    assert ctl.validate_extra_lines('') == ''
    with pytest.raises(ValueError, match='40'):
        ctl.validate_extra_lines('\n'.join(f'PostUp = echo {n}' for n in range(41)))
    with pytest.raises(ValueError, match='4096'):
        ctl.validate_extra_lines('PostUp = ' + 'x' * 4100)


def test_lines_go_into_the_conf_but_not_into_the_vpn_link():
    cfg = profile()
    peer = {**make_client('router', '10.77.10.2'), 'extra_lines': 'PostUp = echo up\nTable = 200'}
    conf = ctl.client_config(cfg, peer)
    head, peer_part = conf.split('[Peer]')
    assert 'PostUp = echo up\nTable = 200' in head and 'PostUp' not in peer_part
    assert 'DisableCookies = on\n\nPostUp = echo up' in head          # set apart by a blank line
    assert '\n\n\n' not in ctl.client_config(cfg, {**peer, 'extra_lines': ''})
    assert head.index('DisableCookies = on') < head.index('PostUp')
    plain = ctl.client_config(cfg, peer, extra=False)
    assert 'PostUp' not in plain and 'Table' not in plain
    assert ctl.config_fingerprint(conf) != ctl.config_fingerprint(ctl.client_config(cfg, {**peer, 'extra_lines': ''}))
    uri = amnezialink.build_vpn_uri(plain, name='router', server_ip='10.77.10.1', subnet='10.77.10.0/24',
                                    client_public_key='Y' * 44)
    assert uri.startswith('vpn://')


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, 'DB', tmp_path / 'state.sqlite3')
    monkeypatch.setattr(ctl, 'CONF', tmp_path / 'awg0.conf')
    monkeypatch.setattr(ctl, 'IFACE', 'awg0')
    monkeypatch.setenv('AWG31_PEER_BACKUPS', str(tmp_path / 'backups'))
    con = ctl.get_conn(True)
    ctl.put_settings(con, profile())
    for n, name in enumerate(('alpha', 'beta', 'gamma'), 2):
        con.execute('INSERT INTO clients (name,ip,private_key,public_key,psk,enabled,created_at) VALUES (?,?,?,?,?,?,?)',
                    (name, f'10.77.10.{n}', 'x' * 44, f'{name:y<44}', 'z' * 44, 1, f'2026-11-1{n}'))
    con.commit()
    monkeypatch.setattr(ctl, 'run', lambda *a, **k: '')
    monkeypatch.setattr(ctl.subprocess, 'run', lambda *a, **k: types.SimpleNamespace(returncode=1, stdout='', stderr=''))

    def call(fn, payload):
        monkeypatch.setattr(sys, 'stdin', StringIO(json.dumps(payload)))
        return fn(con)
    yield con, call, tmp_path
    con.close()


def extra_of(con, name):
    return con.execute('SELECT extra_lines FROM clients WHERE name=?', (name,)).fetchone()[0]


def test_client_network_keeps_or_sets_the_lines(db):
    con, call, tmp_path = db
    assert call(ctl.client_network_update, {'name': 'alpha', 'extra_lines': 'postup = echo up'})['reimport_client']
    assert extra_of(con, 'alpha') == 'PostUp = echo up'
    assert any((tmp_path / 'backups').iterdir())
    call(ctl.client_network_update, {'name': 'alpha', 'routed_subnets': ''})      # an older form: lines stay
    assert extra_of(con, 'alpha') == 'PostUp = echo up'
    with pytest.raises(ValueError):
        call(ctl.client_network_update, {'name': 'alpha', 'extra_lines': '[Peer]'})
    assert extra_of(con, 'alpha') == 'PostUp = echo up'
    export = call(lambda c: ctl.clients_action(c, 'download'), {'name': 'alpha'})
    assert 'PostUp = echo up' in export['config'] and 'PostUp' not in export['link_config']
    assert export['extra_lines'] == 'PostUp = echo up'
    listed = {c['name']: c for c in ctl.get_status(con, True)['clients']}
    assert listed['alpha']['extra_lines'] is True and listed['beta']['extra_lines'] is False


def test_bulk_replace_append_and_clear(db):
    con, call, _ = db
    call(ctl.client_network_update, {'name': 'alpha', 'extra_lines': 'PostUp = echo mine'})
    result = call(ctl.client_extra_update, {'names': ['alpha', 'beta'], 'mode': 'append', 'extra_lines': 'PostUp = echo shared'})
    assert result['updated'] == ['alpha', 'beta']
    assert extra_of(con, 'alpha') == 'PostUp = echo mine\nPostUp = echo shared'
    assert extra_of(con, 'beta') == 'PostUp = echo shared'
    again = call(ctl.client_extra_update, {'names': ['alpha', 'beta'], 'mode': 'append', 'extra_lines': 'PostUp = echo shared'})
    assert again['updated'] == [] and not again['reimport_client']
    with pytest.raises(ValueError, match='один раз'):
        call(ctl.client_extra_update, {'names': ['alpha'], 'mode': 'append', 'extra_lines': 'Table = 1\nTable = 2'})
    call(ctl.client_network_update, {'name': 'alpha', 'extra_lines': 'Table = 200'})
    with pytest.raises(ValueError, match='alpha: .*один раз'):
        call(ctl.client_extra_update, {'names': ['alpha'], 'mode': 'append', 'extra_lines': 'Table = off'})
    call(ctl.client_extra_update, {'names': ['alpha', 'beta', 'gamma'], 'mode': 'replace', 'extra_lines': 'PostUp = echo all'})
    assert {extra_of(con, n) for n in ('alpha', 'beta', 'gamma')} == {'PostUp = echo all'}
    call(ctl.client_extra_update, {'names': ['beta'], 'mode': 'replace', 'extra_lines': ''})
    assert extra_of(con, 'beta') == ''
    for bad in ({'names': ['ghost'], 'extra_lines': ''}, {'names': [], 'extra_lines': ''},
                {'names': ['../x'], 'extra_lines': ''}, {'names': ['alpha'], 'mode': 'merge', 'extra_lines': ''}):
        with pytest.raises(ValueError):
            call(ctl.client_extra_update, bad)


def test_operation_is_allowed_for_the_panel_only():
    mgr = (ROOT / 'src/awg31mgr').read_text()
    assert "'client-extra'" in mgr.split('OPS = {')[1].split('}')[0]
    panel = subprocess.run(['bash', '-c', f'. {ROOT}/scripts/sudoers.sh; printf "%s\\n" "${{AWG31_SUDO_COMMANDS[@]}}"'],
                           capture_output=True, text=True, check=True).stdout.split()
    bot = subprocess.run(['bash', '-c', f'. {ROOT}/scripts/sudoers.sh; printf "%s\\n" "${{AWG31_BOT_SUDO_COMMANDS[@]}}"'],
                         capture_output=True, text=True, check=True).stdout.split()
    assert 'client-extra' in panel and 'client-extra' not in bot


def test_panel_detail_bulk_and_link(tmp_path, monkeypatch):
    from test_web import create_app
    module = create_app(tmp_path, monkeypatch)
    calls = []
    conf = '[Interface]\nPrivateKey = secret\nAddress = 10.77.10.2/32\n'

    def fake_ctl(op, data=None):
        calls.append((op, data))
        if op == 'servers':
            return {'servers': [{'interface': 'awg0', 'subnet': '10.77.10.0/24', 'port': 45678, 'running': True, 'clients': 2}]}
        if op == 'list':
            return {'interface': 'awg0', 'subnet': '10.77.10.0/24', 'server_ip': '10.77.10.1', 'port': 45678,
                    'mtu': 1380, 'endpoint': '10.10.20.29', 'dns': '1.1.1.1', 'mode': 'full', 'uplink': 'ens33',
                    'public_key': 'A' * 44, 'running': True,
                    'clients': [{'name': 'router', 'ip': '10.77.10.2', 'enabled': 1, 'stats': {}, 'routed_subnets': '', 'extra_lines': True},
                                {'name': 'phone', 'ip': '10.77.10.3', 'enabled': 1, 'stats': {}, 'routed_subnets': '', 'extra_lines': False}]}
        if op == 'download':
            return {'config': conf + 'PostUp = echo up\n', 'link_config': conf, 'extra_lines': 'PostUp = echo up != x',
                    'ip': '10.77.10.2', 'routed_subnets': '', 'i_enabled': False, 'server_ip': '10.77.10.1',
                    'subnet': '10.77.10.0/24', 'client_public_key': 'Y' * 44, **{f'i{n}': '' for n in range(1, 6)}}
        if op == 'client-extra':
            return {'ok': True, 'updated': data['names'], 'reimport_client': True}
        return {'ok': True}
    module.ctl = fake_ctl
    seen = {}
    real = module.build_vpn_uri
    module.build_vpn_uri = lambda text, **kw: seen.setdefault('conf', text) and real(text, **kw)
    client = TestClient(module.app)
    client.post('/login', data={'password': 'testpassword1234'})
    listing = client.get('/servers/awg0/clients').text
    assert listing.count('class="extra-dot"') == 1 and 'class="client-icon has-extra"' in listing
    assert 'id="bulk-extra-button"' in listing and 'id="bulk-extra-modal"' in listing
    assert 'data-extra-target="bulk-extra-lines"' in listing and 'th class="actions-head"' in listing
    detail = client.get('/client/router').text
    assert 'name="extra_lines"' in detail and 'PostUp = echo up != x' in detail
    for key in ('Шлюз для локальной сети', 'Только clamp MSS', 'Только NAT', 'Вставить шаблон'):
        assert key in detail
    assert 'PostUp' not in seen['conf']
    csrf = listing.split('name="csrf" value="')[1].split('"')[0]
    saved = client.post('/client/router/network', data={'csrf': csrf, 'routed_subnets': '', 'extra_lines': 'PostUp = echo x'},
                        follow_redirects=False)
    assert saved.status_code == 303
    assert any(op == 'client-network' and d.get('extra_lines') == 'PostUp = echo x' for op, d in calls)
    bulk = client.post('/servers/awg0/clients/bulk-extra',
                       data={'csrf': csrf, 'names': ['router', 'phone'], 'mode': 'append', 'extra_lines': 'Table = 200'},
                       follow_redirects=False)
    assert bulk.status_code == 303
    assert ('client-extra', {'names': ['router', 'phone'], 'mode': 'append', 'extra_lines': 'Table = 200', 'interface': 'awg0'}) in calls
    for data, code in (({'csrf': 'bad', 'names': 'router'}, 403), ({'csrf': csrf}, 422),
                       ({'csrf': csrf, 'names': '../x'}, 422), ({'csrf': csrf, 'names': 'router', 'mode': 'merge'}, 422)):
        assert client.post('/servers/awg0/clients/bulk-extra', data=data).status_code == code
    css = client.get('/assets/md3.css').text
    rule = css.split('.extra-text {')[1].split('}')[0]
    assert 'font-variant-ligatures:none' in rule and '"liga" 0' in rule
    assert '.actions-cell {white-space:nowrap;text-align:right' in css
    js = client.get('/assets/panel.js').text
    assert 'data-bulk-name' in js and 'extraTarget' in js


def test_overlapping_templates_do_not_double_the_commands(tmp_path, monkeypatch):
    """Gateway + «MSS only» + «NAT only» in one field: each command once, no orphan comments."""
    from test_web import create_app
    create_app(tmp_path, monkeypatch)
    _, texts = template_texts()
    merged = ctl.validate_extra_lines('\n'.join((texts['gateway'], texts['mss'], texts['nat'], '# my own note')))
    assert merged == texts['gateway'] + '\n# my own note'
    commands = [line for line in merged.split('\n') if not line.startswith('#')]
    assert len(commands) == len(set(commands))
    assert ctl.validate_extra_lines('postup = echo a\nPostUp =   echo a\nPostUp = echo b') == 'PostUp = echo a\nPostUp = echo b'
    assert ctl.validate_extra_lines('Table = 200\nTable = 200') == 'Table = 200'
