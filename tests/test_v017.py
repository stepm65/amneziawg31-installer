"""0.17: subscriptions for routers, server rotation, masking profiles, the packet check, MSS clamping and sysctl."""
import base64
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from test_peer_routes_i import profile
from test_telegram_bot import FakeController, bot_module, press, sudo_list, FakeApi, ADMIN, TOKEN
from test_v015 import ctl, db, row  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ controller: subscription
def test_subscription_token_is_hashed_shown_once_and_revocable(db):
    con, call, _ = db
    first = call(ctl.subscription_token, {'name': 'alpha'})
    assert ctl.SUB_RE.fullmatch(first['token']) and len(first['token']) >= 43
    stored = row(con, 'alpha')
    assert first['token'] not in json.dumps(stored) and stored['sub_hash'] == ctl.sub_digest(first['token'])
    got = call(ctl.subscription_fetch, {'token': first['token'], 'addr': '203.0.113.45'})
    assert got['found'] and got['enabled'] and got['name'] == 'alpha' and '[Interface]' in got['config']
    assert got['etag'] == ctl.config_fingerprint(got['config'])[:32]
    after = row(con, 'alpha')
    assert after['sub_fetches'] == 1 and after['sub_last_fetch'] and after['sub_last_addr'] != '203.0.113.45'   # masked
    assert after['exported_hash'] == ctl.config_fingerprint(got['config'])        # the router has the current one
    shown = {c['name']: c for c in ctl.get_status(con, True)['clients']}
    assert shown['alpha']['subscription'] is True and shown['alpha']['config_stale'] is False and not shown['delta']['subscription']
    detail = call(lambda c: ctl.clients_action(c, 'download'), {'name': 'alpha'})
    assert detail['subscription']['active'] and detail['subscription']['fetches'] == 1 and 'sub_hash' not in json.dumps(detail)
    # A new link replaces the old one at once.
    second = call(ctl.subscription_token, {'name': 'alpha'})
    assert call(ctl.subscription_fetch, {'token': first['token']}) == {'found': False}
    assert call(ctl.subscription_fetch, {'token': second['token']})['found']
    # A switched-off client gets no configuration.
    con.execute('UPDATE clients SET enabled=0 WHERE name=?', ('alpha',)); con.commit()
    assert call(ctl.subscription_fetch, {'token': second['token']}) == {'found': True, 'enabled': False, 'name': 'alpha'}
    call(ctl.subscription_token, {'name': 'alpha', 'action': 'revoke'})
    assert call(ctl.subscription_fetch, {'token': second['token']}) == {'found': False}
    for bad in ({'name': 'ghost'}, {'name': '../x'}):
        with pytest.raises(ValueError):
            call(ctl.subscription_token, bad)
    with pytest.raises(ValueError):
        call(ctl.subscription_fetch, {'token': 'short'})


# ------------------------------------------------------------------ controller: rotation
@pytest.fixture
def rotating(db, monkeypatch):
    con, call, applied = db
    monkeypatch.setattr(ctl, 'settings_backup', lambda c, label: None)
    monkeypatch.setattr(ctl, 'used_udp_ports', lambda: {45678})
    opened = []
    monkeypatch.setattr(ctl, 'host_firewall_port', lambda new, old: opened.append((new, old)) or 'ufw')
    return con, call, applied, opened


def test_rotation_changes_only_what_was_asked(rotating):
    con, call, applied, opened = rotating
    before = ctl.get_settings(con)
    ctl.put_settings(con, {'RandomTrailers': 'off', 'Jmin': 20, 'Jmax': 70})
    clients = {r['name']: dict(r) for r in con.execute('SELECT * FROM clients')}
    result = call(ctl.rotate_op, {'parts': ['port', 'obfuscation']})
    after = ctl.get_settings(con)
    assert result['ok'] and result['old_port'] == before['port'] and 20000 <= result['port'] < 60000
    assert after['port'] == result['port'] and opened == [(result['port'], before['port'])] and applied
    assert [after[f'H{n}'] for n in range(1, 5)] != [before[f'H{n}'] for n in range(1, 5)]
    assert after['header_key'] != before['header_key'] and after['private_key'] == before['private_key']
    assert (after['RandomTrailers'], int(after['Jmin']), int(after['Jmax'])) == ('off', 20, 70)    # the admin's choices stay
    assert after['rotated_at']
    assert {r['name']: dict(r) for r in con.execute('SELECT * FROM clients')} == clients             # clients untouched
    key = call(ctl.rotate_op, {'parts': ['key']})
    assert key['port'] == result['port'] and ctl.get_settings(con)['private_key'].startswith('new-private')
    for bad in ({'parts': []}, {'parts': ['everything']}, {'parts': 'port'}):
        with pytest.raises(ValueError):
            call(ctl.rotate_op, bad)


def test_rotation_schedule(rotating):
    con, call, _, _ = rotating
    assert call(ctl.rotate_schedule, {'days': 7, 'parts': ['port']}) == {'ok': True, 'days': 7, 'parts': ['port']}
    cfg = ctl.get_settings(con)
    now = datetime.now(timezone.utc)
    assert not ctl.rotation_due(cfg, now) and ctl.rotation_due(cfg, now + timedelta(days=7, minutes=1))
    status = ctl.get_status(con)['rotation']
    assert status['days'] == 7 and status['parts'] == ['port']
    assert not ctl.rotation_due({**cfg, 'rotate_days': 0}, now + timedelta(days=99))
    for bad in ({'days': 2}, {'days': 'x'}, {'days': 7, 'parts': ['nothing']}):
        with pytest.raises(ValueError):
            call(ctl.rotate_schedule, bad)


# ------------------------------------------------------------------ controller: masking profiles
def test_mask_profile_writes_i1_and_moves_the_port(rotating):
    con, call, applied, opened = rotating
    stun = '<b 0x000100002112a442><r 12>'
    result = call(ctl.mask_apply, {'profile': 'stun', 'i1': {'alpha': stun, 'beta': stun}, 'port': 3478})
    assert result['updated'] == ['alpha', 'beta'] and result['port'] == 3478 and opened and applied
    assert (row(con, 'alpha')['i1'], row(con, 'alpha')['i_enabled']) == (stun, 1) and row(con, 'gamma')['i1'] == ''
    assert ctl.get_settings(con)['mask_profile'] == 'stun' and ctl.get_status(con)['mask_profile'] == 'stun'
    for bad in ({'profile': 'tor'}, {'profile': 'stun', 'i1': {'ghost': stun}},
                {'profile': 'stun', 'i1': {'alpha': '<script>'}}, {'profile': 'dns', 'port': 70000}):
        with pytest.raises(ValueError):
            call(ctl.mask_apply, bad)


def test_mask_profile_refuses_a_busy_port(rotating, monkeypatch):
    con, call, _, _ = rotating
    monkeypatch.setattr(ctl, 'used_udp_ports', lambda: {53})
    with pytest.raises(ValueError):
        call(ctl.mask_apply, {'profile': 'dns', 'port': 53})
    assert ctl.get_settings(con).get('mask_profile', 'none') == 'none'


# ------------------------------------------------------------------ controller: packet check
def udp4(src, dst, sport, dport, payload):
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28 + len(payload), 0, 0, 64, 17, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def test_packet_probe_counts_incoming_and_answers(db, monkeypatch):
    con, call, _ = db
    port = ctl.get_settings(con)['port']
    packets = [(udp4('198.51.100.7', '192.0.2.1', 40000, port, b'x' * 180), ('eth0', 0x0800, 0, 1, b'')),
               (udp4('198.51.100.7', '192.0.2.1', 40000, port, b'x' * 30), ('eth0', 0x0800, 0, 1, b'')),
               (udp4('192.0.2.1', '198.51.100.7', port, 40000, b'y' * 92), ('eth0', 0x0800, 4, 1, b'')),
               (udp4('198.51.100.9', '192.0.2.1', 5353, 53, b'z' * 40), ('eth0', 0x0800, 0, 1, b''))]

    class FakeSocket:
        def __init__(self, *args): assert args[0] == socket.AF_PACKET
        def settimeout(self, value): pass
        def recvfrom(self, size):
            if packets: return packets.pop(0)
            raise socket.timeout
        def close(self): pass
    clock = iter(range(1000))
    monkeypatch.setattr(socket, 'socket', FakeSocket)
    monkeypatch.setattr(ctl._time, 'monotonic', lambda: next(clock))
    result = call(ctl.packet_probe, {'seconds': 5})
    assert (result['incoming'], result['outgoing'], result['port'], result['seconds']) == (2, 1, port, 5)
    assert dict(result['sizes']) == {180: 1, 30: 1} and len(result['sources']) == 1
    assert '198.51.100.7' not in json.dumps(result['sources'])                # partial masking by default
    assert result['expected_init'] == 148 + int(ctl.get_settings(con)['S1'])


# ------------------------------------------------------------------ wiring
def test_new_operations_are_wired_and_allowed_to_the_right_users():
    mgr = (ROOT / 'src/awg31mgr').read_text()
    controller = (ROOT / 'src/awg31ctl').read_text()
    panel, bot = sudo_list('AWG31_SUDO_COMMANDS'), sudo_list('AWG31_BOT_SUDO_COMMANDS')
    ops = ('sub-token', 'sub-fetch', 'rotate', 'rotate-schedule', 'mask-apply', 'probe')
    for op in ops:
        assert f"'{op}'" in mgr and f"'{op}'" in controller, op
    assert set(ops) <= panel and {'probe', 'rotate'} <= bot
    assert not {'sub-token', 'sub-fetch', 'mask-apply', 'rotate-schedule'} & bot
    admin = (ROOT / 'src/awg31admin.py').read_text()
    for event in ('server_rotated', 'server_rotate_failed', 'mask_profile_applied', 'subscription_created',
                  'subscription_revoked', 'packet_probe'):
        assert f"'{event}'" in admin, event
    assert "'server_rotated'" in mgr and 'rotation_due' in controller


def test_mss_clamp_switch_adds_mangle_rules(db):
    con, _, _ = db
    cfg = ctl.get_settings(con)
    net = ctl.parse_network(cfg['subnet'])
    rule = '-t mangle -I FORWARD 1 -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu'
    assert ctl.SWITCHES['mss_clamp'] == 'off'                     # an existing server keeps what it had
    off = '\n'.join(ctl.firewall_lines({**cfg, 'mss_clamp': 'off'}, net, []))
    on = '\n'.join(ctl.firewall_lines({**cfg, 'mss_clamp': 'on'}, net, []))
    assert rule not in off and rule.replace('-I FORWARD 1', '-D FORWARD') in off     # a stale rule is cleaned up
    assert rule in on and rule.replace('-o awg0', '-i awg0') in on
    assert "'mss_clamp': 'on'" in (ROOT / 'src/awg31ctl').read_text()             # new servers start with it on


def test_sysctl_hardening_is_written_and_removed():
    support = (ROOT / 'scripts/os-support.sh').read_text()
    for line in ('net.ipv4.conf.all.rp_filter = 2', 'net.ipv4.conf.all.accept_redirects = 0',
                 'net.ipv4.conf.all.send_redirects = 0', 'net.ipv4.tcp_syncookies = 1'):
        assert line in support, line
    assert 'awg31_network_sysctl' in (ROOT / 'scripts/setup-wizard.sh').read_text()
    assert 'awg31_network_sysctl' in (ROOT / 'scripts/upgrade-core.sh').read_text()
    assert '96-awg31-network.conf' in (ROOT / 'scripts/uninstall.sh').read_text()


# ------------------------------------------------------------------ Nginx
def nginx(*commands, env=None):
    return subprocess.run(['bash', '-c', f'source "$1"; proxy_log() {{ echo "$*"; }}; {"; ".join(commands)}', '_',
                           str(ROOT / 'scripts/setup-nginx.sh')], capture_output=True, text=True, check=True,
                          env={**os.environ, **(env or {})}).stdout


def test_nginx_site_has_the_subscription_location_and_old_sites_get_it(tmp_path):
    site = nginx('proxy_render_config vpn.example.net 443 8080 /c.pem /k.pem "203.0.113.7"')
    assert 'zone=awg31_sub:10m rate=30r/m' in site
    block = site.index('location /sub/ {')
    assert block < site.index('    location / {')
    sub = site[block:site.index('}', block)]
    assert 'allow all;' in sub and 'limit_req zone=awg31_sub' in sub and 'X-Real-IP $remote_addr' in sub
    assert 'access_log off' in sub
    # An older site: the location is added once, the rest stays as it was.
    old = re.sub(r'    location /sub/ \{.*?\n    \}\n\n', '', site, flags=re.S).replace(
        'limit_req_zone $binary_remote_addr zone=awg31_sub:10m rate=30r/m;\n', '')
    assert 'location /sub/' not in old
    path = tmp_path / 'awg31-panel.conf'
    path.write_text(old)
    out = nginx('proxy_add_subscription', env={'AWG31_NGINX_SITE': str(path)})
    patched = path.read_text()
    assert 'added the /sub/ location' in out and patched == site
    nginx('proxy_add_subscription', env={'AWG31_NGINX_SITE': str(path)})
    assert path.read_text() == site and not list(tmp_path.glob('*.awg31-before-sub'))
    assert '--add-subscription' in (ROOT / 'scripts/setup-nginx.sh').read_text()
    assert '--add-subscription' in (ROOT / 'scripts/upgrade-core.sh').read_text()


# ------------------------------------------------------------------ web: public subscription route
def sub_ui(ui, tmp_path, cert=''):
    app, client, calls = ui
    site = tmp_path / 'awg31-panel.conf'
    site.write_text(nginx(f'proxy_render_config vpn.example.test 8443 8080 {cert or "/c.pem"} /k.pem ""'))
    app.NGINX_SITE = site
    original = app.ctl
    state = {'enabled': True, 'config': '[Interface]\nPrivateKey = ROUTER\n'}

    def fake(op, data=None):
        data = data or {}
        if op == 'sub-fetch':
            calls.append((op, dict(data)))
            if data['token'] != 'T' * 43: return {'found': False}
            if not state['enabled']: return {'found': True, 'enabled': False, 'name': 'alpha'}
            return {'found': True, 'enabled': True, 'name': 'alpha', 'config': state['config'],
                    'etag': hashlib.sha256(state['config'].encode()).hexdigest()[:32]}
        if op == 'sub-token':
            calls.append((op, dict(data)))
            return {'ok': True, 'name': data['name'], **({} if data.get('action') else {'token': 'S' * 43})}
        if op == 'download':
            result = {**original(op, data), 'name': 'alpha', 'telegram_id': '', 'invite_expires': '', 'server_ip': '10.77.10.1',
                      'subnet': '10.77.10.0/24', 'client_public_key': 'B' * 44}
            result['subscription'] = {'active': True, 'created': '2026-11-20T10:00:00+00:00',
                                      'last_fetch': '2026-11-21T08:30:00+00:00', 'last_addr': '203.0.113.x', 'fetches': 4}
            return result
        return original(op, data)
    app.ctl = fake
    app._sub_hits.clear(); app._sub_failures.clear()
    return app, client, calls, state


def test_subscription_route_serves_the_config_with_etag(ui, tmp_path):
    app, client, calls, state = sub_ui(ui, tmp_path)
    router = TestClient(app.app)                                  # no session: the token is the key
    reply = router.get('/sub/awg0/' + 'T' * 43)
    assert reply.status_code == 200 and reply.text == state['config']
    assert reply.headers['etag'].startswith('"') and reply.headers['cache-control'] == 'no-store'
    assert reply.headers['content-type'].startswith('text/plain')
    assert calls[-1] == ('sub-fetch', {'interface': 'awg0', 'token': 'T' * 43, 'addr': 'testclient'})
    same = router.get('/sub/awg0/' + 'T' * 43, headers={'If-None-Match': reply.headers['etag']})
    assert same.status_code == 304 and same.content == b''
    state['config'] += 'Jc = 7\n'
    assert router.get('/sub/awg0/' + 'T' * 43, headers={'If-None-Match': reply.headers['etag']}).status_code == 200
    state['enabled'] = False
    assert router.get('/sub/awg0/' + 'T' * 43).status_code == 403
    assert router.get('/sub/awg0/' + 'U' * 43).status_code == 404
    assert router.get('/sub/awg9x/' + 'T' * 43).status_code == 404
    assert router.get('/sub/awg0/short').status_code == 404


def test_subscription_route_limits_guessing(ui, tmp_path):
    app, client, calls, state = sub_ui(ui, tmp_path)
    router = TestClient(app.app)
    codes = [router.get('/sub/awg0/' + f'{n:043d}').status_code for n in range(12)]
    assert codes[:10] == [404] * 10 and codes[10:] == [429, 429]
    assert router.get('/sub/awg0/' + 'T' * 43).status_code == 429             # the address waits, even with a good token
    app._sub_hits.clear(); app._sub_failures.clear()
    codes = [router.get('/sub/awg0/' + 'T' * 43).status_code for _ in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429


def test_client_address_trusts_x_real_ip_only_from_nginx(ui):
    app, _, _ = ui
    request = lambda host, real: types.SimpleNamespace(client=types.SimpleNamespace(host=host), headers={'x-real-ip': real})
    assert app.client_address(request('127.0.0.1', '198.51.100.7')) == '198.51.100.7'
    assert app.client_address(request('203.0.113.9', '198.51.100.7')) == '203.0.113.9'
    assert app.client_address(request('127.0.0.1', '1.2.3.4; rm -rf')) == '127.0.0.1'


def test_public_site_and_certificate_pin(ui, tmp_path):
    app, _, _ = ui
    cert, key = tmp_path / 'c.pem', tmp_path / 'k.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '30', '-subj', '/CN=vpn.example.test'],
                   capture_output=True, check=True)
    site = tmp_path / 'awg31-panel.conf'
    site.write_text(nginx(f'proxy_render_config vpn.example.test 8443 8080 {cert} {key} ""'))
    app.NGINX_SITE = site
    found = app.public_site()
    assert found == {'base': 'https://vpn.example.test:8443', 'cert': str(cert), 'sub_location': True}
    der = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'der'], capture_output=True, check=True).stdout
    assert app.certificate_pin(str(cert)) == 'sha256//' + base64.b64encode(hashlib.sha256(der).digest()).decode()
    app.NGINX_SITE = tmp_path / 'missing.conf'
    assert app.public_site() == {} and app.certificate_pin('') == ''


def test_client_page_offers_the_subscription_and_creation_shows_the_script(ui, tmp_path):
    app, client, calls, _ = sub_ui(ui, tmp_path)
    page = client.get('/servers/awg0/clients/alpha')
    assert page.status_code == 200 and 'action="/servers/awg0/clients/alpha/subscription/revoke"' in page.text
    assert '203.0.113.x' in page.text and 'href="/sub/' not in page.text
    made = client.post('/servers/awg0/clients/alpha/subscription', data={'csrf': token(page)})
    assert made.status_code == 200 and ('sub-token', {'interface': 'awg0', 'name': 'alpha'}) in calls
    url = 'https://vpn.example.test:8443/sub/awg0/' + 'S' * 43
    assert f'value="{url}"' in made.text and 'data-download-from="sub-script"' in made.text
    assert f"URL=&#x27;{url}&#x27;" in made.text and "PIN=&#x27;&#x27;" in made.text       # /c.pem cannot be read: no pin
    gone = client.post('/servers/awg0/clients/alpha/subscription/revoke', data={'csrf': token(page)}, follow_redirects=False)
    assert gone.status_code == 303 and ('sub-token', {'interface': 'awg0', 'name': 'alpha', 'action': 'revoke'}) in calls
    app.NGINX_SITE = tmp_path / 'missing.conf'
    page = client.get('/servers/awg0/clients/alpha')
    assert 'sudo awg31 nginx' in page.text and 'clients/alpha/subscription"' not in page.text


def fake_tools(bin_dir):
    bin_dir.mkdir()
    (bin_dir / 'curl').write_text('''#!/bin/sh
out=''; head=''; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; -D) head="$2"; shift;; -H) echo "$2" >> "$FAKE/curl-headers";; esac; shift; done
echo call >> "$FAKE/curl-calls"
code="$(cat "$FAKE/code")"
if [ "$code" = 200 ]; then cat "$FAKE/body" > "$out"; printf 'HTTP/1.1 200 OK\\r\\nETag: "abc123"\\r\\n\\r\\n' > "$head"; else : > "$out"; : > "$head"; fi
printf '%s' "$code"
''')
    (bin_dir / 'awg-quick').write_text('#!/bin/sh\necho "awg-quick $*" >> "$FAKE/actions"\n')
    (bin_dir / 'awg').write_text('#!/bin/sh\necho "x $(date +%s)"\n')
    (bin_dir / 'ip').write_text('#!/bin/sh\nexit 0\n')
    (bin_dir / 'logger').write_text('#!/bin/sh\nexit 0\n')
    for item in bin_dir.iterdir(): item.chmod(0o755)


def test_router_script_updates_the_conf_and_uses_the_etag(ui, tmp_path):
    app, _, _ = ui
    script = tmp_path / 'awg-sub.sh'
    script.write_text(app.watchdog_script('https://vpn.example.test/sub/awg0/' + 'S' * 43, '', 'ru'))
    assert subprocess.run(['sh', '-n', str(script)]).returncode == 0
    fake_tools(tmp_path / 'bin')
    (tmp_path / 'code').write_text('200')
    (tmp_path / 'body').write_text('[Interface]\nPrivateKey = NEW\n')
    conf = tmp_path / 'awg0.conf'
    conf.write_text('[Interface]\nPrivateKey = OLD\n')
    env = {'PATH': f'{tmp_path / "bin"}:/usr/bin:/bin', 'FAKE': str(tmp_path), 'AWG_CONF': str(conf), 'AWG_IFACE': 'awg0'}
    run = lambda: subprocess.run(['sh', str(script)], env=env, capture_output=True, text=True, timeout=30)
    first = run()
    assert first.returncode == 0, first.stderr
    assert conf.read_text() == '[Interface]\nPrivateKey = NEW\n' and (tmp_path / 'awg0.conf.bak').read_text().endswith('OLD\n')
    assert (tmp_path / 'awg0.conf.etag').read_text().strip() == '"abc123"' and oct(conf.stat().st_mode)[-3:] == '600'
    assert (tmp_path / 'actions').read_text().splitlines() == ['awg-quick down awg0', 'awg-quick up awg0']
    # Nothing changed: 304, the same file, the ETag is sent, no restart.
    (tmp_path / 'code').write_text('304')
    (tmp_path / 'actions').write_text('')
    run()
    assert conf.read_text().endswith('NEW\n') and (tmp_path / 'actions').read_text() == ''
    assert 'If-None-Match: "abc123"' in (tmp_path / 'curl-headers').read_text().splitlines()[-1]
    # A page that is not a configuration never replaces it.
    (tmp_path / 'code').write_text('200')
    (tmp_path / 'body').write_text('<html>captive portal</html>')
    run()
    assert conf.read_text().endswith('NEW\n')
    assert "PIN='sha256//x'" in app.watchdog_script('https://h/sub/awg0/x', 'sha256//x', 'en')
    assert '--pinnedpubkey' in app.watchdog_script('https://h/sub/awg0/x', 'sha256//x', 'en')


# ------------------------------------------------------------------ web: rotation, masking, probe, MSS
def test_settings_page_has_rotation_masking_and_mss(ui):
    app, client, calls = ui
    page = client.get('/servers/awg0/settings')
    for needle in ('action="/servers/awg0/mask"', 'action="/servers/awg0/rotate"', 'action="/servers/awg0/rotate-schedule"',
                   'name="mss_clamp"', 'value="dtls"', 'value="quic"', 'id="rotation"'):
        assert needle in page.text, needle
    client.post('/servers/awg0/settings', data={'csrf': token(page), 'endpoint': 'vpn.example.test', 'port': '45678',
                                                'mtu': '1380', 'dns': '1.1.1.1', 'mss_clamp': 'on'})
    assert [d for op, d in calls if op == 'settings'][-1]['mss_clamp'] == 'on'
    reply = client.post('/servers/awg0/rotate', data={'csrf': token(page), 'port': '1', 'key': '1'}, follow_redirects=False)
    assert reply.status_code == 303 and ('rotate', {'interface': 'awg0', 'parts': ['port', 'key']}) in calls
    assert client.post('/servers/awg0/rotate', data={'csrf': token(page)}).status_code == 422
    client.post('/servers/awg0/rotate-schedule', data={'csrf': token(page), 'days': '7', 'port': '1'})
    assert ('rotate-schedule', {'interface': 'awg0', 'days': 7, 'parts': ['port']}) in calls
    client.post('/servers/awg0/mask', data={'csrf': token(page), 'profile': 'stun', 'clients': '1', 'use_port': '1'})
    sent = [d for op, d in calls if op == 'mask-apply'][-1]
    assert sent['profile'] == 'stun' and sent['port'] == 3478 and sent['i1'] == {'alpha': '<b 0x000100002112a442><r 12>'}
    client.post('/servers/awg0/mask', data={'csrf': token(page), 'profile': 'dtls'})
    assert [d for op, d in calls if op == 'mask-apply'][-1] == {'interface': 'awg0', 'profile': 'dtls', 'i1': {}, 'port': 0}
    assert client.post('/servers/awg0/mask', data={'csrf': token(page), 'profile': 'tor'}).status_code == 422
    assert ('server_rotated' in (ROOT / 'src/web.py').read_text())


def test_new_client_form_follows_the_masking_profile(ui):
    app, client, calls = ui
    original = app.ctl

    def masked(op, data=None):
        result = original(op, data)
        if op == 'list': result['mask_profile'] = 'stun'
        return result
    app.ctl = masked
    page = client.get('/servers/awg0/clients')
    assert '&lt;b 0x000100002112a442&gt;&lt;r 12&gt;</textarea>' in page.text
    assert 'name="i_enabled" value="1" checked data-cps-enabled' in page.text


def test_dtls_preset_is_a_well_formed_client_hello(ui):
    app, _, _ = ui
    value = app.cps_value('dtls')
    assert ctl.validate_i_fields({'i_enabled': '1', 'i1': value})['i1'] == value
    raw = re.sub(r'<r 32>', '<b 0x' + '00' * 32 + '>', value)
    data = bytes.fromhex(''.join(re.findall(r'<b 0x([0-9a-f]+)>', raw)))
    assert data[:3] == b'\x16\xfe\xff' and int.from_bytes(data[11:13], 'big') == len(data) - 13
    hello = data[13:]
    assert hello[0] == 1 and int.from_bytes(hello[1:4], 'big') == len(hello) - 12 == int.from_bytes(hello[9:12], 'big')
    body = hello[12:]
    assert body[:2] == b'\xfe\xfd'
    rest = body[34:]
    assert rest[0] == 0 and rest[1] == 0                               # no session id, no cookie: the first flight
    suites = int.from_bytes(rest[2:4], 'big')
    rest = rest[4 + suites:]
    assert rest[:2] == b'\x01\x00'
    extensions, rest = rest[4:], rest[2:4]
    assert int.from_bytes(rest, 'big') == len(extensions)
    seen = []
    while extensions:
        kind, size = int.from_bytes(extensions[:2], 'big'), int.from_bytes(extensions[2:4], 'big')
        seen.append(kind); extensions = extensions[4 + size:]
    assert seen == [0x17, 0xff01, 0x0a, 0x0b, 0x0d, 0x0e]               # ... use_srtp: a WebRTC call
    assert 'dtls' in app.CPS_PRESETS and app.cps_value('dtls') != '' and client_preset_listed(app)


def client_preset_listed(app):
    return app.tr('ru', 'cps_preset_dtls') != 'cps_preset_dtls' and app.tr('en', 'cps_preset_dtls') != 'cps_preset_dtls'


def test_probe_page_explains_the_result(ui):
    app, client, calls = ui
    original = app.ctl
    answer = {'incoming': 0, 'outgoing': 0}

    def probing(op, data=None):
        if op == 'probe':
            calls.append((op, dict(data)))
            return {'ok': True, 'interface': 'awg0', 'port': 45678, 'seconds': 15, 'sources': [['198.51.100.x:40000', 3]],
                    'sizes': [[180, 3]], 'expected_init': 170, 'junk': [10, 50], **answer}
        return original(op, data)
    app.ctl = probing
    overview = client.get('/servers/awg0/overview')
    assert 'action="/servers/awg0/probe"' in overview.text and 'data-busy-text' in overview.text
    page = client.post('/servers/awg0/probe', data={'csrf': token(overview)})
    assert ('probe', {'interface': 'awg0', 'seconds': 15}) in calls
    assert 'Трафик не доходит до сервера' in page.text
    answer.update(incoming=3)
    assert 'сервер не отвечает' in client.post('/servers/awg0/probe', data={'csrf': token(overview)}).text
    answer.update(outgoing=2)
    page = client.post('/servers/awg0/probe', data={'csrf': token(overview)})
    assert 'сервер отвечает' in page.text and '198.51.100.x:40000' in page.text and '180 B × 3' in page.text


def test_new_pages_keep_the_strict_csp(ui, tmp_path):
    app, client, _, _ = sub_ui(ui, tmp_path)
    page = client.get('/servers/awg0/settings')
    made = client.post('/servers/awg0/clients/alpha/subscription', data={'csrf': token(page)})
    for html in (page.text, made.text):
        assert '<script>' not in html and ' onclick=' not in html and ' style="' not in html
    js = (ROOT / 'src/panel.js').read_text()
    assert 'data-download-from' in js or 'downloadFrom' in js and 'busyText' in js


# ------------------------------------------------------------------ bot
class RotateController(FakeController):
    def __call__(self, command, data=None):
        if command == 'probe':
            self.log.append((command, data))
            return {'ok': True, 'port': 51820, 'incoming': 4, 'outgoing': 0, 'sources': [['198.51.100.x:4000', 4]]}
        if command == 'rotate':
            self.log.append((command, data))
            return {'ok': True, 'port': 34567, 'old_port': 51820}
        return super().__call__(command, data)


@pytest.fixture
def rbot(tmp_path):
    api, controller = FakeApi(), RotateController()
    config = {'token': TOKEN, 'admins': {ADMIN}, 'lang': 'en', 'api_base': 'https://api.telegram.org'}
    bot = bot_module.Bot(config, api=api, controller=controller, state_path=tmp_path / 'state.json', clock=lambda: 1_780_000_000.0)
    return bot, api, controller


def test_bot_checks_packets_and_rotates_after_confirmation(rbot):
    bot, api, controller = rbot
    bot.handle_update(press('s:awg0'))
    assert {'pr:awg0', 'ro:awg0'} <= set(api.buttons())
    bot.handle_update(press('pr:awg0'))
    assert ('probe', {'interface': 'awg0', 'seconds': 15}) in controller.log
    assert 'From clients: <b>4</b>' in api.texts()[-1] and 'does not answer' in api.texts()[-1]
    bot.handle_update(press('ro:awg0'))
    assert 'ry:awg0:go' in api.buttons() and 'rotate' not in controller.commands()
    bot.handle_update(press('ry:awg0:go'))
    assert ('rotate', {'interface': 'awg0', 'parts': ['port', 'obfuscation']}) in controller.log
    assert '34567' in api.texts()[-1]
    assert any(e['event'] == 'server_rotated' and '51820 → 34567' in e['target'] for e in controller.audit)
    bot.config['viewers'] = {ADMIN + 1}
    before = controller.commands().count('rotate')
    bot.handle_update(press('ry:awg0:go', user=ADMIN + 1))
    assert controller.commands().count('rotate') == before


def test_bot_reports_a_scheduled_rotation(rbot):
    bot, api, controller = rbot
    bot.check_audit()
    start = len(api.calls)
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'server_rotated',
                             'target': 'awg0: port, obfuscation, port 51820 → 34567 (schedule)'})
    bot.check_audit()
    sent = [p['text'] for m, p in api.calls[start:] if m == 'sendMessage']
    assert sent and 'Server parameters changed' in sent[-1] and '34567' in sent[-1]
    assert bot_module.EVENTS['rotation'] == 'server'
