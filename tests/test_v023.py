"""0.23: deleting rollback snapshots, a traffic chart per client, one-time configuration links."""
import json
from pathlib import Path

import pytest

from test_v016 import fake_root, updater, update_ui, install_version  # noqa: F401  (pytest fixtures)
from test_password_guards import admin  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)
from test_telegram_bot import sudo_list

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ snapshots
def test_the_snapshot_tool_deletes_one_snapshot(fake_root):
    root, snap = fake_root
    first = snap.create('upgrade', '0.16.0').name
    second = snap.create('upgrade', '0.17.0').name
    assert snap.delete(first) == first
    assert [x['name'] for x in snap.snapshots()] == [second]
    for bad in (first, '../../etc', 'awg31-upgrade.' + 'x' * 3):
        with pytest.raises(SystemExit):
            snap.delete(bad)


def test_admin_refuses_while_an_update_runs(updater):
    module, tmp, calls, active = updater
    assert module.snapshot_delete({'name': 'awg31-upgrade.20261120T100000Z-abcd'}) == {'ok': True, 'name': 'awg31-upgrade.20261120T100000Z-abcd'}
    assert calls[-1][2:] == ['delete', 'awg31-upgrade.20261120T100000Z-abcd']
    with pytest.raises(ValueError, match='No such'):
        module.snapshot_delete({'name': 'awg31-upgrade.Missing01'})
    with pytest.raises(ValueError):
        module.snapshot_delete({'name': '../x'})
    active['on'] = True
    with pytest.raises(ValueError, match='running'):
        module.snapshot_delete({'name': 'awg31-upgrade.20261120T100000Z-abcd'})


def test_update_tab_has_a_delete_button_per_snapshot(ui):
    status = {'state': {}, 'running': False, 'log': '', 'version': '0.16.0', 'available': True,
              'snapshots': [{'name': 'awg31-upgrade.20261120T100000Z-abcd', 'version': '0.15.0', 'to': '0.16.0', 'reason': 'upgrade',
                             'created': '2026-11-20T10:00:00+00:00', 'usable': True},
                            {'name': 'awg31-upgrade.Legacy01', 'usable': False, 'created': '2026-10-01T00:00:00+00:00'}]}
    app, client, calls = update_ui(ui, status)
    original = app.ctl

    def fake(op, data=None):
        if op == 'snapshot-delete':
            calls.append((op, dict(data)))
            return {'ok': True}
        return original(op, data)
    app.ctl = fake
    page = client.get('/maintenance?tab=update')
    assert page.text.count('class="icon-btn snapshot-delete"') == 2 and 'form="snapdel-0"' in page.text and 'form="snapdel-1"' in page.text
    assert 'id="snapdel-1"' in page.text and 'Неполная копия от старой версии' in page.text
    assert 'Удалить снимок v0.15.0?' in page.text
    done = client.post('/maintenance/update/snapshot-delete', data={'csrf': token(page), 'name': 'awg31-upgrade.Legacy01'},
                       follow_redirects=False)
    assert done.headers['location'] == '/maintenance?tab=update&snapshot=deleted'
    assert ('snapshot-delete', {'name': 'awg31-upgrade.Legacy01'}) in calls
    assert 'Снимок удалён' in client.get(done.headers['location']).text
    assert client.post('/maintenance/update/snapshot-delete', data={'csrf': token(page), 'name': '../etc'}).status_code == 422


def test_snapshot_delete_wiring():
    assert 'snapshot-delete' in sudo_list('AWG31_SUDO_COMMANDS') and 'snapshot-delete' not in sudo_list('AWG31_BOT_SUDO_COMMANDS')
    menu = (ROOT / 'scripts/awg31-menu').read_text()
    assert 'awg31 rollback delete SNAPSHOT' in menu and 'python3 "$tool" delete "$2"' in menu


# ------------------------------------------------------------------ traffic of one client
from test_v015 import ctl, db, row  # noqa: E402,F401  (pytest fixture)


def test_hourly_traffic_is_kept_and_bucketed(db, monkeypatch):
    con, call, _ = db
    from datetime import datetime, timezone
    keys = {r['name']: r['public_key'] for r in ctl.peer_rows(con)}
    stats = {}
    monkeypatch.setattr(ctl, 'live_stats', lambda: stats)
    base = datetime(2026, 11, 28, 10, 0, 5, tzinfo=timezone.utc)
    received = {'alpha': 500, 'delta': 600}
    for minute, add in ((0, 1000), (30, 2000), (65, 4000)):
        for name in received:
            received[name] += add
        stats.clear()
        stats.update({keys[n]: {'received': received[n], 'sent': received[n] // 2, 'handshake': 1} for n in received})
        from datetime import timedelta
        ctl.sample_usage(con, now=base + timedelta(minutes=minute))
    hours = [dict(r) for r in con.execute("SELECT hour, rx, tx FROM client_traffic WHERE client='alpha' ORDER BY hour")]
    assert [h['rx'] for h in hours] == [3000, 4000] and hours[1]['hour'] - hours[0]['hour'] == 3600
    now = int((base + timedelta(minutes=70)).timestamp())
    day = call(ctl.client_history, {'name': 'alpha', 'window': '24h', 'now': now})
    assert len(day['points']) == 24 and day['bucket'] == 3600 and day['total_rx'] == 7000
    assert day['points'][-1]['rx'] == 4000 and day['points'][-2]['rx'] == 3000
    week = call(ctl.client_history, {'name': 'alpha', 'window': '7d', 'now': now})
    assert len(week['points']) == 28 and week['total_rx'] == 7000
    month = call(ctl.client_history, {'name': 'alpha', 'window': '30d', 'now': now})
    assert len(month['points']) == 30 and month['points'][-1]['rx'] == 7000
    for bad in ({'name': 'nobody'}, {'name': 'alpha', 'window': '1y'}):
        with pytest.raises(ValueError):
            call(ctl.client_history, bad)
    call(lambda c: ctl.clients_action(c, 'delete'), {'name': 'alpha'})
    assert not con.execute("SELECT 1 FROM client_traffic WHERE client='alpha'").fetchone()


def test_client_page_shows_the_chart(ui):
    app, client, calls = ui
    original = app.ctl
    G = 1024 ** 3

    def fake(op, data=None):
        if op == 'client-history':
            calls.append((op, dict(data)))
            points = [{'t': 1_780_000_000 + n * 3600, 'rx': n * 1024 ** 2, 'tx': (n % 3) * G} for n in range(24)]
            return {'points': points, 'bucket': 3600, 'total_rx': sum(p['rx'] for p in points), 'total_tx': sum(p['tx'] for p in points)}
        return original(op, data)
    app.ctl = fake
    page = client.get('/servers/awg0/clients/alpha?traffic=7d')
    assert ('client-history', {'name': 'alpha', 'window': '7d', 'interface': 'awg0'}) in calls
    html = page.text
    assert 'id="client-traffic"' in html and '<svg class="client-traffic-chart"' in html
    assert html.count('class="ct-rx"') == 23 and 'Скачивание (к клиенту): <strong>24.0 GiB</strong>' in html
    assert '<title>' in html and '↓ 2.0 GiB · ↑ 2.0 MiB' in html and 'aria-current=page>7 дней' in html
    assert 'style=' not in html.split('id="client-traffic"')[1].split('</section>')[0]          # CSP: no inline styles
    client.get('/servers/awg0/clients/alpha?traffic=forever')
    assert [d for op, d in calls if op == 'client-history'][-1] == {'name': 'alpha', 'window': '24h', 'interface': 'awg0'}
    assert 'client-history' in sudo_list('AWG31_SUDO_COMMANDS')


# ------------------------------------------------------------------ one-time links
def test_once_link_is_hashed_used_up_and_revocable(db):
    con, call, _ = db
    made = call(ctl.once_link, {'name': 'alpha', 'hours': 24, 'uses': 3})
    token = made['token']
    stored = row(con, 'alpha')
    assert ctl.SUB_RE.fullmatch(token) and token not in json.dumps(stored) and stored['once_hash'] == ctl.once_digest(token)
    assert stored['once_uses'] == 3 and made['uses'] == 3
    detail = call(lambda c: ctl.clients_action(c, 'download'), {'name': 'alpha'})
    assert detail['once'] == {'expires': made['expires'], 'uses': 3} and 'once_hash' not in json.dumps(detail)
    peek = call(ctl.once_fetch, {'token': token, 'peek': True})
    assert peek == {'found': True, 'enabled': True, 'name': 'alpha', 'uses': 3, 'expires': made['expires']}
    assert row(con, 'alpha')['once_uses'] == 3                                     # a preview uses nothing up
    for left in (2, 1, 0):
        got = call(ctl.once_fetch, {'token': token})
        assert got['found'] and got['uses_left'] == left and '[Interface]' in got['config'] and got['client_public_key']
    assert call(ctl.once_fetch, {'token': token}) == {'found': False}
    assert row(con, 'alpha')['once_hash'] == '' and row(con, 'alpha')['exported_hash']
    # A switched-off client: nothing is used up.
    token = call(ctl.once_link, {'name': 'alpha', 'hours': 1, 'uses': 1})['token']
    con.execute('UPDATE clients SET enabled=0 WHERE name=?', ('alpha',)); con.commit()
    assert call(ctl.once_fetch, {'token': token}) == {'found': True, 'enabled': False, 'name': 'alpha'}
    assert row(con, 'alpha')['once_uses'] == 1
    # An expired link is cleared.
    con.execute("UPDATE clients SET enabled=1, once_expires='2020-01-01T00:00:00+00:00' WHERE name=?", ('alpha',)); con.commit()
    assert call(ctl.once_fetch, {'token': token}) == {'found': False, 'expired': True} and row(con, 'alpha')['once_hash'] == ''
    # A new link replaces the old one; revoke clears it.
    first = call(ctl.once_link, {'name': 'alpha'})['token']
    second = call(ctl.once_link, {'name': 'alpha'})['token']
    assert call(ctl.once_fetch, {'token': first, 'peek': True}) == {'found': False}
    call(ctl.once_link, {'name': 'alpha', 'action': 'revoke'})
    assert call(ctl.once_fetch, {'token': second, 'peek': True}) == {'found': False}
    for bad in ({'name': 'ghost'}, {'name': 'alpha', 'hours': 5}, {'name': 'alpha', 'uses': 2}, {'name': 'alpha', 'hours': 'x'}):
        with pytest.raises(ValueError):
            call(ctl.once_link, bad)
    assert call(ctl.once_fetch, {'token': 'short'}) == {'found': False}
    assert {'once_hash', 'once_expires', 'once_uses'} <= set(ctl.MOVE_KEEP)


def once_ui(ui, tmp_path):
    from test_v017 import nginx
    app, client, calls = ui
    site = tmp_path / 'awg31-panel.conf'
    site.write_text(nginx('proxy_render_config vpn.example.test 8443 8080 /c.pem /k.pem ""'))
    app.NGINX_SITE = site
    original = app.ctl
    state = {'uses': 2, 'enabled': True, 'active': None}

    def fake(op, data=None):
        data = data or {}
        if op == 'once-link':
            calls.append((op, dict(data)))
            if data.get('action') == 'revoke':
                state['active'] = None
                return {'ok': True}
            state['active'] = {'expires': '2026-11-29T10:00:00+00:00', 'uses': data['uses']}
            return {'ok': True, 'name': data['name'], 'token': 'O' * 43, 'expires': '2026-11-29T10:00:00+00:00', 'uses': data['uses']}
        if op == 'once-fetch':
            calls.append((op, dict(data)))
            if data['token'] != 'O' * 43 or data['interface'] != 'awg0' or state['uses'] <= 0: return {'found': False}
            if not state['enabled']: return {'found': True, 'enabled': False, 'name': 'alpha'}
            if data.get('peek'): return {'found': True, 'enabled': True, 'name': 'alpha', 'uses': state['uses'], 'expires': 'x'}
            state['uses'] -= 1
            return {'found': True, 'enabled': True, 'name': 'alpha', 'uses_left': state['uses'],
                    'config': '[Interface]\nPrivateKey = ONCEKEY\nAddress = 10.77.10.2/32\n\n[Peer]\nPublicKey = ' + 'S' * 44 + '\nPresharedKey = ' + 'P' * 44 + '\nEndpoint = 203.0.113.1:443\nAllowedIPs = 0.0.0.0/0\n',
                    'server_ip': '10.77.10.1', 'subnet': '10.77.10.0/24', 'client_public_key': 'B' * 44}
        if op == 'download':
            result = original(op, data)
            if state['active']: result = {**result, 'once': state['active']}
            return result
        return original(op, data)
    app.ctl = fake
    app._sub_hits.clear(); app._sub_failures.clear()
    return app, client, calls, state


def test_client_page_creates_and_revokes_a_one_time_link(ui, tmp_path):
    app, client, calls, state = once_ui(ui, tmp_path)
    page = client.get('/servers/awg0/clients/alpha')
    assert 'Одноразовая ссылка' in page.text and 'action="/servers/awg0/clients/alpha/once"' in page.text and '<option value="24" selected>' in page.text
    made = client.post('/servers/awg0/clients/alpha/once', data={'csrf': token(page), 'hours': '72', 'uses': '3'})
    assert made.status_code == 200 and ('once-link', {'interface': 'awg0', 'name': 'alpha', 'hours': 72, 'uses': 3}) in calls
    assert 'value="https://vpn.example.test:8443/sub/once/awg0/' + 'O' * 43 + '"' in made.text and '2026-11-29 10:00' in made.text
    page = client.get('/servers/awg0/clients/alpha')
    assert 'осталось открытий: 3' in page.text and 'data-confirm="Создать новую ссылку?' in page.text
    gone = client.post('/client/alpha/once/revoke', data={'csrf': token(page)}, follow_redirects=False)
    assert gone.status_code == 303 and [d for op, d in calls if op == 'once-link'][-1].get('action') == 'revoke'
    for bad in ({'hours': '5', 'uses': '1'}, {'hours': '24', 'uses': '2'}, {'hours': 'x', 'uses': '1'}):
        assert client.post('/servers/awg0/clients/alpha/once', data={'csrf': token(page), **bad}).status_code == 422
    assert client.post('/servers/awg0/clients/alpha/once', data={'hours': '24', 'uses': '1'}).status_code in (401, 403)
    app.NGINX_SITE = tmp_path / 'missing.conf'
    page = client.get('/servers/awg0/clients/alpha')
    assert 'Ссылки работают через HTTPS-адрес панели' in page.text and 'action="/servers/awg0/clients/alpha/once"' not in page.text
    assert {'once-link', 'once-fetch'} <= set(sudo_list('AWG31_SUDO_COMMANDS')) and 'once-fetch' not in sudo_list('AWG31_BOT_SUDO_COMMANDS')
    assert {'once_link_created', 'once_link_used', 'once_link_revoked'} <= set(__import__('awg31admin').VALID_AUDIT)


def test_public_one_time_page_shows_a_button_then_the_config(ui, tmp_path):
    from fastapi.testclient import TestClient
    app, client, calls, state = once_ui(ui, tmp_path)
    person = TestClient(app.app)                                  # no session
    url = '/sub/once/awg0/' + 'O' * 43
    first = person.get(url, headers={'Accept-Language': 'ru-RU,ru;q=0.9'})
    assert first.status_code == 200 and 'Показать конфигурацию' in first.text and '<form method="post"' in first.text
    assert 'ONCEKEY' not in first.text and state['uses'] == 2                       # a link preview uses nothing up
    csp = first.headers['content-security-policy']
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'<style nonce="{nonce}">' in first.text and "script-src" not in csp and first.headers['cache-control'] == 'no-store'
    assert 'noindex' in first.headers['x-robots-tag']
    taken = person.post(url, headers={'Accept-Language': 'ru'})
    assert taken.status_code == 200 and 'ONCEKEY' in taken.text and 'src="data:image/png;base64,' in taken.text
    assert 'download="alpha.conf"' in taken.text and 'vpn://' in taken.text and 'ещё 1 раз' in taken.text and state['uses'] == 1
    last = person.post(url, headers={'Accept-Language': 'en-US'})
    assert 'will not open again' in last.text and state['uses'] == 0
    assert person.get(url).status_code == 404 and person.post(url).status_code == 404
    state['uses'] = 1; state['enabled'] = False
    assert person.get(url).status_code == 403 and state['uses'] == 1
    assert person.get('/sub/once/awg0/short').status_code == 404 and person.get('/sub/once/bad!/' + 'O' * 43).status_code == 404
    app._sub_hits.clear(); app._sub_failures.clear()
    codes = [person.get('/sub/once/awg0/' + f'{n:043d}').status_code for n in range(12)]
    assert codes[:10] == [404] * 10 and codes[10:] == [404, 404]
    state['enabled'] = True
    assert 'ONCEKEY' not in person.post(url).text                                   # the guessing address waits
