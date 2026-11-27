"""0.19: client groups and list filters, the blocking signal, configurations after a settings change."""
import csv
import io
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from test_telegram_bot import sudo_list
from test_v015 import ctl, db, row  # noqa: F401  (pytest fixture)
from test_v018 import OwnersController, obot, to  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ groups
def test_group_is_validated_stored_and_changed_in_bulk(db):
    con, call, _ = db
    assert ctl.valid_group('  Офис   Москва ') == 'Офис Москва' and ctl.valid_group(None) == ''
    for bad in ('x' * 33, 'a<b', 'bell\x07', "it's"):
        with pytest.raises(ValueError):
            ctl.valid_group(bad)
    call(ctl.client_policy_update, {'name': 'alpha', 'group': 'office'})
    assert row(con, 'alpha')['group_name'] == 'office'
    call(ctl.client_policy_update, {'name': 'alpha', 'comment': 'kept'})               # a form without the field keeps it
    assert row(con, 'alpha')['group_name'] == 'office'
    result = call(ctl.client_batch, {'names': ['alpha', 'beta', 'gamma'], 'action': 'group', 'group': 'family'})
    assert result['changed'] == ['alpha', 'beta', 'gamma'] and row(con, 'gamma')['group_name'] == 'family'
    assert call(ctl.client_batch, {'names': ['alpha'], 'action': 'group', 'group': 'family'})['skipped'] == {'alpha': 'already'}
    call(ctl.client_batch, {'names': ['beta'], 'action': 'group', 'group': ''})
    groups = {c['name']: c['group_name'] for c in ctl.get_status(con, True)['clients']}
    assert groups == {'alpha': 'family', 'beta': '', 'gamma': 'family', 'delta': '', 'omega': ''}
    assert call(lambda c: ctl.clients_action(c, 'download'), {'name': 'alpha'})['group_name'] == 'family'
    assert 'group_name' in ctl.MOVE_KEEP


def test_new_client_gets_its_group(db, monkeypatch):
    con, call, _ = db
    call(ctl.clients_add, {'name': 'newbie', 'group': 'guests'})
    assert row(con, 'newbie')['group_name'] == 'guests'


# ------------------------------------------------------------------ blocking signal
@pytest.fixture
def watch(db, monkeypatch):
    con, call, _ = db
    link = {'up': True}
    monkeypatch.setattr(ctl.subprocess, 'run', lambda *a, **k: types.SimpleNamespace(returncode=0 if link['up'] else 1, stdout='', stderr=''))
    rotated = []
    monkeypatch.setattr(ctl, 'rotate', lambda c, parts, reason='': rotated.append((parts, reason)) or {'ok': True, 'parts': parts})
    rows = ctl.peer_rows(con)
    keys = {r['name']: r['public_key'] for r in rows}
    t0 = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)

    def tick(minutes, online=()):
        now = t0 + timedelta(minutes=minutes)
        stats = {keys[n]: {'handshake': int(now.timestamp()) - 30, 'received': 1, 'sent': 1} for n in online}
        return ctl.silence_watch(con, stats, ctl.peer_rows(con), now)
    return con, call, tick, link, rotated


def test_all_clients_gone_at_once_is_reported_once_and_recovery_too(watch):
    con, call, tick, link, rotated = watch
    assert tick(0, ('alpha', 'delta')) is None                     # alpha and delta are enabled
    assert tick(10) is None and tick(29) is None
    event = tick(31)
    assert event == {'event': 'silent', 'count': 2, 'minutes': 30, 'since': int((datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)).timestamp())}
    assert tick(45) is None and not rotated                         # once, and no rotation unless asked
    assert ctl.get_status(con)['watch']['state'] == 'silent'
    assert tick(50, ('alpha',)) == {'event': 'back', 'active': 1}
    assert ctl.get_status(con)['watch']['state'] == 'ok'


def test_one_client_leaving_or_a_stopped_server_is_not_blocking(watch):
    con, call, tick, link, rotated = watch
    tick(0, ('alpha',))
    assert tick(120) is None                                        # one phone went to sleep
    tick(130, ('alpha', 'delta'))
    link['up'] = False
    assert tick(200) is None and ctl.get_status(con)['watch']['count'] == 0
    link['up'] = True
    assert tick(300) is None                                        # the count was reset when it stopped


def test_blocking_can_rotate_by_itself_and_can_be_switched_off(watch):
    con, call, tick, link, rotated = watch
    assert call(ctl.watch_set, {'minutes': 15, 'rotate': True}) == {'ok': True, 'minutes': 15, 'rotate': 'on'}
    tick(0, ('alpha', 'delta'))
    event = tick(16)
    assert event['event'] == 'silent' and event['rotated'] == {'ok': True, 'parts': ['port', 'obfuscation']}
    assert rotated == [(['port', 'obfuscation'], 'silence')]
    tick(20, ('alpha', 'delta'))
    call(ctl.watch_set, {'minutes': 0})
    assert tick(200) is None
    for bad in ({'minutes': 7}, {'minutes': 'x'}):
        with pytest.raises(ValueError):
            call(ctl.watch_set, bad)


def test_manager_and_wiring_for_the_signal():
    mgr = (ROOT / 'src/awg31mgr').read_text()
    assert "'server_silent'" in mgr and "'server_back'" in mgr and '(no handshakes)' in mgr and "'watch-set'" in mgr
    admin = (ROOT / 'src/awg31admin.py').read_text()
    assert "'server_silent', 'server_back'" in admin and "'blocking':'server'" in admin
    assert 'watch-set' in sudo_list('AWG31_SUDO_COMMANDS') and 'watch-set' not in sudo_list('AWG31_BOT_SUDO_COMMANDS')


# ------------------------------------------------------------------ panel
def grouped(ui):
    app, client, calls = ui
    original = app.ctl
    now = int(datetime.now(timezone.utc).timestamp())

    def fake(op, data=None):
        result = original(op, data)
        if op == 'list' and (data or {}).get('interface', 'awg0') == 'awg0':
            result['clients'] = [
                {'name': 'alpha', 'ip': '10.77.10.2', 'enabled': True, 'group_name': 'office', 'comment': 'Main PC',
                 'stats': {'handshake': now - 20, 'received': 1, 'sent': 1}, 'subscription': True},
                {'name': 'bravo', 'ip': '10.77.10.3', 'enabled': False, 'disabled_reason': 'expired', 'group_name': '',
                 'stats': {}, 'config_stale': True},
            ]
            result['watch'] = {'minutes': 30, 'rotate': 'off', 'state': 'silent', 'seen': now - 3600, 'count': 2}
        if op == 'settings':
            calls.append((op, dict(data or {})))
            return {'ok': True, 'configs_changed': 3}
        return result
    app.ctl = fake
    return app, client, calls


def test_list_has_group_chips_filters_and_bulk_group(ui):
    app, client, calls = grouped(ui)
    page = client.get('/servers/awg0/clients')
    assert '<span class="group-chip">office</span>' in page.text
    assert 'id="client-group-filter"' in page.text and '<option value="office">office</option>' in page.text
    assert 'id="client-state-filter"' in page.text and '<option value="expiring">' in page.text
    # Online / offline / switched off are the chips above the table; the list keeps only what they lack.
    assert '<option value="online">' not in page.text and '<option value="expired">' not in page.text
    assert 'data-group="office" data-flags="online sub"' in page.text
    assert 'data-flags="never stale expired"' in page.text and 'data-text="office main pc"' in page.text
    assert 'data-modal-open="bulk-group-modal"' in page.text and 'name="action" value="group"' in page.text
    client.post('/servers/awg0/clients/bulk-action', data={'csrf': token(page), 'action': 'group', 'names': ['alpha'], 'group': '  Home   LAN '})
    assert ('client-batch', {'names': ['alpha'], 'action': 'group', 'group': 'Home LAN', 'interface': 'awg0'}) in calls
    done = client.get('/servers/awg0/clients?bulk=group&changed=1')
    assert 'Группа задана клиентам: 1' in done.text
    js = (ROOT / 'src/panel.js').read_text()
    assert "byId('client-group-filter')" in js and "dataset.flags" in js and 'hidden-by-filter' in js


def test_group_field_in_forms_and_csv(ui):
    app, client, calls = grouped(ui)
    detail = client.get('/servers/awg0/clients/alpha')
    assert 'id="policy-group"' in detail.text and 'list="policy-groups"' in detail.text
    assert 'id="new-group"' in client.get('/servers/awg0/clients').text
    client.post('/servers/awg0/clients/alpha/policy', data={'csrf': token(detail), 'group': 'office', 'quota_gib': '0'})
    assert [d for op, d in calls if op == 'client-policy'][-1]['group'] == 'office'
    exported = client.get('/servers/awg0/export/clients.csv')
    table = list(csv.reader(io.StringIO(exported.text.lstrip('﻿'))))
    assert table[0][-1] == 'group' and table[1][-1] == 'office'


def test_blocking_signal_in_settings_and_overview(ui):
    app, client, calls = grouped(ui)
    settings = client.get('/servers/awg0/settings')
    assert 'action="/servers/awg0/watch"' in settings.text and 'клиенты пропали все сразу' in settings.text
    client.post('/servers/awg0/watch', data={'csrf': token(settings), 'minutes': '60', 'rotate': '1'})
    assert ('watch-set', {'interface': 'awg0', 'minutes': 60, 'rotate': True}) in calls
    overview = client.get('/servers/awg0/overview')
    assert 'возможно, порт или протокол заблокирован' in overview.text and 'href="/servers/awg0/settings#rotation"' in overview.text
    client.post('/servers/awg0/settings', data={'csrf': token(settings), 'endpoint': 'new.example.test', 'port': '45678',
                                                'mtu': '1380', 'dns': '1.1.1.1'})
    assert ('audit', {'event': 'server_settings_changed', 'target': 'awg0: 3 client configurations changed'}) in calls \
        or any(op == 'audit' and d.get('target') == 'awg0: 3 client configurations changed' for op, d in calls)
    assert 'blocking' in [e for _, _, events in app.TG_EVENT_GROUPS for e in events]


# ------------------------------------------------------------------ bot
def test_bot_reports_blocking_and_delivers_after_a_settings_change(obot):
    bot, api, controller = obot
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'server_silent', 'target': 'awg0: 3 clients gone, 30 min without handshakes'})
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'server_back', 'target': 'awg0: 2 clients connected again'})
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'server_settings_changed', 'target': 'awg0'})
    bot.check_audit()
    admin = to(api, 111222333)
    assert any('vanished at once' in t and '3 clients gone' in t for t in admin) and any('connect again' in t for t in admin)
    assert api.files == []                                          # settings without client changes: nothing to send
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'server_settings_changed', 'target': 'awg0: 4 client configurations changed'})
    bot.check_audit()
    assert [f[1:3] for f in api.files] == [(700000001, 'alice.conf'), (700000001, 'alice-qr.png')]
