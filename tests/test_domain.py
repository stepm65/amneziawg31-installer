"""0.19.8: an optional server domain that client configurations use instead of the IP."""
from pathlib import Path

import pytest

from test_peer_routes_i import make_client, profile
from test_v015 import ctl, db  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]


def test_domain_is_validated():
    assert ctl.valid_domain('  VPN.Example.COM. ') == 'vpn.example.com'
    assert ctl.valid_domain('') == '' and ctl.valid_domain(None) == ''
    assert ctl.valid_domain('a-b.c-d.example') == 'a-b.c-d.example'
    for bad in ('203.0.113.10', '2001:db8::1', 'localhost', 'vpn.example.com:443', 'https://vpn.example.com',
                '-vpn.example.com', 'vpn-.example.com', 'vpn..example.com', 'vpn.example.123', 'vpn_x.example.com',
                'a' * 64 + '.example.com', 'vpn example.com'):
        with pytest.raises(ValueError):
            ctl.valid_domain(bad)


def test_config_uses_the_domain_only_when_switched_on():
    peer = make_client('phone', '10.77.10.2')
    cfg = profile()
    assert 'Endpoint = 10.10.20.29:45678' in ctl.client_config(cfg, peer)
    cfg['endpoint_domain'] = 'vpn.example.com'
    assert 'Endpoint = 10.10.20.29:45678' in ctl.client_config(cfg, peer)            # a stored domain alone changes nothing
    cfg['use_domain'] = 'on'
    text = ctl.client_config(cfg, peer)
    assert 'Endpoint = vpn.example.com:45678' in text and '10.10.20.29' not in text
    assert ctl.client_host({**cfg, 'endpoint_domain': ''}) == '10.10.20.29'        # switched on but empty: the IP


@pytest.fixture
def settings(db, monkeypatch, tmp_path):
    monkeypatch.setattr(ctl, 'SETTINGS_BACKUPS', tmp_path / 'settings-backups')
    resolved = {'vpn.example.com': ['10.10.20.29'], 'old.example.com': ['198.51.100.9']}
    monkeypatch.setattr(ctl, 'domain_addresses', lambda name, timeout=3.0: resolved.get(name))
    return db


def test_switching_to_the_domain_changes_every_config_and_checks_dns(settings):
    con, call, applied = settings
    keep = {'endpoint': '10.10.20.29', 'port': 45678, 'mtu': 1380, 'dns': '1.1.1.1'}
    result = call(ctl.settings_update, {**keep, 'endpoint_domain': 'VPN.example.com'})
    assert result['configs_changed'] == 0 and result['domain_warning'] == ''          # stored, not used yet
    status = ctl.get_status(con)
    assert status['endpoint_domain'] == 'vpn.example.com' and status['use_domain'] == 'off'
    assert status['client_host'] == '10.10.20.29'
    result = call(ctl.settings_update, {**keep, 'use_domain': 'on'})
    assert result['configs_changed'] == 5 and result['reimport_clients'] and result['domain_warning'] == ''
    assert ctl.get_status(con)['client_host'] == 'vpn.example.com'
    row = dict(con.execute("SELECT * FROM clients WHERE name='alpha'").fetchone())
    assert 'Endpoint = vpn.example.com:45678' in ctl.client_config(ctl.get_settings(con), row)
    assert call(ctl.settings_update, {**keep, 'endpoint_domain': 'old.example.com'})['domain_warning'] == 'mismatch'
    assert call(ctl.settings_update, {**keep, 'endpoint_domain': 'gone.example.com'})['domain_warning'] == 'unresolved'
    assert call(ctl.settings_update, {**keep, 'use_domain': 'off'})['domain_warning'] == ''   # off: no lookup needed
    assert ctl.get_status(con)['client_host'] == '10.10.20.29'


def test_the_switch_needs_a_domain(settings):
    con, call, applied = settings
    with pytest.raises(ValueError, match='укажите домен'):
        call(ctl.settings_update, {'use_domain': 'on'})
    with pytest.raises(ValueError):
        call(ctl.settings_update, {'use_domain': 'yes', 'endpoint_domain': 'vpn.example.com'})
    with pytest.raises(ValueError):
        call(ctl.settings_update, {'endpoint_domain': '203.0.113.10'})


def test_a_server_from_an_older_release_keeps_its_ip(settings):
    con, call, applied = settings
    cfg = ctl.get_settings(con)
    assert cfg['use_domain'] == 'off' and ctl.client_host(cfg) == '10.10.20.29'
    assert ctl.domain_check(cfg) == ''


def test_lookup_never_hangs(monkeypatch):
    import socket
    import time
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: time.sleep(1) or [])
    started = time.monotonic()
    assert ctl.domain_addresses('slow.example.com', timeout=0.2) is None
    assert time.monotonic() - started < 0.9


def test_profile_and_manager_carry_the_domain():
    mgr = (ROOT / 'src/awg31mgr').read_text()
    assert "'endpoint_domain', 'use_domain'" in mgr


# ------------------------------------------------------------------ panel
def domain_ui(ui, warning=''):
    app, client, calls = ui
    original = app.ctl

    def fake(op, data=None):
        if op == 'settings':
            calls.append((op, dict(data or {})))
            return {'ok': True, 'configs_changed': 2, 'domain_warning': warning}
        result = original(op, data)
        if op in ('status', 'list') and isinstance(result, dict):
            result.update({'endpoint_domain': 'vpn.example.org', 'use_domain': 'on', 'client_host': 'vpn.example.org'})
        return result
    app.ctl = fake
    return app, client, calls


def test_settings_page_has_the_domain_field_and_switch(ui):
    app, client, calls = domain_ui(ui, 'mismatch')
    page = client.get('/servers/awg0/settings')
    assert 'name="endpoint_domain" value="vpn.example.org"' in page.text
    assert '<select id="use-domain" name="use_domain"><option value="off">IP-адрес (поле Endpoint)</option>' \
           '<option value="on" selected>Домен</option>' in page.text
    done = client.post('/servers/awg0/settings', data={'csrf': token(page), 'endpoint': '203.0.113.10', 'port': '45678',
                                                       'mtu': '1380', 'dns': '1.1.1.1', 'endpoint_domain': 'vpn.example.org',
                                                       'use_domain': 'on'}, follow_redirects=False)
    assert done.headers['location'] == '/servers/awg0/settings?saved=1&domain=mismatch'
    sent = [d for op, d in calls if op == 'settings'][-1]
    assert sent['endpoint_domain'] == 'vpn.example.org' and sent['use_domain'] == 'on'
    warned = client.get(done.headers['location'])
    assert 'Домен vpn.example.org указывает не на' in warned.text
    overview = client.get('/servers/awg0/overview')
    assert '<dt>В конфигурациях</dt><dd>vpn.example.org</dd>' in overview.text


def test_no_warning_without_a_problem(ui):
    app, client, calls = domain_ui(ui, '')
    page = client.get('/servers/awg0/settings')
    done = client.post('/servers/awg0/settings', data={'csrf': token(page), 'endpoint': '203.0.113.10', 'port': '45678',
                                                       'mtu': '1380', 'dns': '1.1.1.1'}, follow_redirects=False)
    assert done.headers['location'] == '/servers/awg0/settings?saved=1'
    english = client.get('/servers/awg0/settings?saved=1&domain=bogus')
    assert 'does not point' not in english.text and 'указывает не на' not in english.text
