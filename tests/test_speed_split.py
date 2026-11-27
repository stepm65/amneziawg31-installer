"""0.19.6: download and upload speed limits apart."""
import csv
import io
import sqlite3

import pytest

from test_peer_routes_i import profile
from test_telegram_bot import FakeController, bot_module, FakeApi, ADMIN, TOKEN
from test_v015 import ctl, db, row  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)


def peer(ip, down=0, up=0, routes=''):
    return {'ip': ip, 'enabled': 1, 'speed_limit_mbit': down, 'speed_up_mbit': up, 'routed_subnets': routes}


def test_each_direction_gets_its_own_rule(monkeypatch):
    monkeypatch.setattr(ctl, 'IFACE', 'awg0')
    cfg = profile()
    rules = '\n'.join(ctl.shaping_commands(cfg, [peer('10.77.10.2', down=50), peer('10.77.10.3', up=10),
                                                 peer('10.77.10.4', down=40, up=8, routes='192.168.50.0/24'),
                                                 peer('10.77.10.5')]))
    assert 'classid 1:2 htb rate 50mbit ceil 50mbit' in rules and 'match ip src 10.77.10.2/32' not in rules
    assert 'match ip src 10.77.10.3/32 police rate 10mbit' in rules and 'classid 1:3 ' not in rules
    assert 'classid 1:4 htb rate 40mbit' in rules and 'match ip src 10.77.10.4/32 police rate 8mbit' in rules
    assert 'match ip dst 192.168.50.0/24 flowid 1:4' in rules and 'match ip src 192.168.50.0/24 police rate 8mbit' in rules
    assert '10.77.10.5' not in rules
    assert ctl.shaping_commands(cfg, [peer('10.77.10.5')]) == []


def test_old_single_limit_becomes_both_directions(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, 'DB', tmp_path / 'state.sqlite3')
    old = sqlite3.connect(ctl.DB)
    old.execute('''CREATE TABLE clients (name TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL, private_key TEXT NOT NULL,
                   public_key TEXT UNIQUE NOT NULL, psk TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                   created_at TEXT NOT NULL, speed_limit_mbit INTEGER NOT NULL DEFAULT 0)''')
    old.execute("INSERT INTO clients VALUES ('slow','10.77.10.2','P','K','S',1,'2026-11-01',30)")
    old.execute("INSERT INTO clients VALUES ('free','10.77.10.3','P2','K2','S2',1,'2026-11-01',0)")
    old.commit(); old.close()
    con = ctl.get_conn()
    values = {r['name']: (r['speed_limit_mbit'], r['speed_up_mbit']) for r in con.execute('SELECT * FROM clients')}
    assert values == {'slow': (30, 30), 'free': (0, 0)}
    con.execute("UPDATE clients SET speed_up_mbit=5 WHERE name='slow'"); con.commit(); con.close()
    con = ctl.get_conn()                     # the copy happens once, when the column is added
    assert con.execute("SELECT speed_up_mbit FROM clients WHERE name='slow'").fetchone()[0] == 5
    con.close()


def test_policy_takes_both_numbers_or_one_for_both(db):
    con, call, _ = db
    call(ctl.client_policy_update, {'name': 'alpha', 'speed_limit_mbit': 50, 'speed_up_mbit': 10})
    assert (row(con, 'alpha')['speed_limit_mbit'], row(con, 'alpha')['speed_up_mbit']) == (50, 10)
    call(ctl.client_policy_update, {'name': 'alpha', 'comment': 'kept'})
    assert (row(con, 'alpha')['speed_limit_mbit'], row(con, 'alpha')['speed_up_mbit']) == (50, 10)
    call(ctl.client_policy_update, {'name': 'alpha', 'speed_limit_mbit': 20})       # the bot: one number, both ways
    assert (row(con, 'alpha')['speed_limit_mbit'], row(con, 'alpha')['speed_up_mbit']) == (20, 20)
    call(ctl.clients_add, {'name': 'guest', 'speed_limit_mbit': 30, 'speed_up_mbit': 0})
    assert (row(con, 'guest')['speed_limit_mbit'], row(con, 'guest')['speed_up_mbit']) == (30, 0)
    for bad in ({'speed_up_mbit': -1}, {'speed_up_mbit': 10001}, {'speed_up_mbit': 'fast'}):
        with pytest.raises(ValueError):
            call(ctl.client_policy_update, {'name': 'alpha', **bad})
    detail = call(lambda c: ctl.clients_action(c, 'download'), {'name': 'guest'})
    assert detail['speed_up_mbit'] == 0 and detail['speed_limit_mbit'] == 30
    assert 'speed_up_mbit' in ctl.MOVE_KEEP


def test_panel_has_two_fields_and_csv_two_columns(ui):
    app, client, calls = ui
    page = client.get('/servers/awg0/clients/alpha')
    assert 'name="speed_limit_mbit"' in page.text and 'name="speed_up_mbit"' in page.text
    assert 'Скачивание, Мбит/с (к клиенту)' in page.text and 'Загрузка, Мбит/с (от клиента)' in page.text
    client.post('/servers/awg0/clients/alpha/policy', data={'csrf': token(page), 'quota_gib': '0',
                                                            'speed_limit_mbit': '50', 'speed_up_mbit': '10'})
    sent = [d for op, d in calls if op == 'client-policy'][-1]
    assert (sent['speed_limit_mbit'], sent['speed_up_mbit']) == (50, 10)
    assert client.post('/servers/awg0/clients/alpha/policy', data={'csrf': token(page), 'quota_gib': '0',
                                                                   'speed_up_mbit': '-3'}).status_code == 422
    header = next(csv.reader(io.StringIO(client.get('/servers/awg0/export/clients.csv').text.lstrip('﻿'))))
    assert 'speed_down_mbit' in header and 'speed_up_mbit' in header and 'speed_limit_mbit' not in header


def test_bot_shows_both_directions(tmp_path):
    controller = FakeController()
    bot = bot_module.Bot({'token': TOKEN, 'admins': {ADMIN}, 'lang': 'en', 'api_base': 'https://api.telegram.org'},
                         api=FakeApi(), controller=controller, state_path=tmp_path / 'state.json', clock=lambda: 1_780_000_000.0)
    assert bot.speed_text({'speed_limit_mbit': 20, 'speed_up_mbit': 20}) == '\nSpeed: up to 20 Mbit/s'
    assert bot.speed_text({'speed_limit_mbit': 50, 'speed_up_mbit': 10}) == '\nSpeed: ↓ 50 · ↑ 10 (Mbit/s)'
    assert bot.speed_text({'speed_limit_mbit': 0, 'speed_up_mbit': 10}) == '\nSpeed: ↓ unlimited · ↑ 10 (Mbit/s)'
    assert bot.speed_text({}) == ''


def test_history_reports_its_interval_and_the_page_has_a_scale(db, ui):
    con, call, _ = db
    import time
    now = int(time.time())
    con.executemany('INSERT INTO traffic_samples(measured_at,rx_delta,tx_delta) VALUES(?,?,?)',
                    [(now - 600, 60_000, 120_000), (now - 60, 6_000, 12_000)])
    con.commit()
    result = ctl.traffic_history(con, {'window': '24h'})
    assert result['bucket'] == 480 and sum(p['rx'] for p in result['points']) == 66_000
    app, client, _ = ui
    page = client.get('/servers/awg0/monitoring')
    for needle in ('data-tick="max"', 'data-tick="mid"', 'id="history-from"', 'id="history-to"', 'id="history-tip"',
                   'data-unit-m="Мбит/с"', 'От клиентов — загрузка (RX)', 'К клиентам — скачивание (TX)', 'data-ago="{n} с назад"'):
        assert needle in page.text, needle
    js = (ROOT_JS := __import__('pathlib').Path(__file__).resolve().parents[1] / 'src/panel.js').read_text()
    assert 'niceMax' in js and 'data.bucket' in js and "awgChart.rate" in js
