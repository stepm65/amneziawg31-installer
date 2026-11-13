"""Dashboard regression: independent AWG charts + host resource metrics."""
import importlib.machinery
import json
import sqlite3
import time
from pathlib import Path
import pytest
from test_workflows import ui, token

ROOT=Path(__file__).resolve().parents[1]


def test_overview_has_3xui_host_blocks_and_instance_charts(ui):
    _,client,_=ui
    html=client.get('/').text
    assert html.count('class="instance-dashboard"')==2
    assert html.count('class="host-kpi"')==4
    assert 'class="fleet-list-panel"' not in html
    assert 'class="fleet-row"' not in html
    assert 'class="system-line"' not in html
    for key in ('cpu','ram','swap','disk'):
        assert f'id="host-{key}"' in html
        assert f'data-kpi-line="{key}"' in html
    for key in ('wan','awg0','awg1'):
        assert f'data-plot="{key}"' in html
        assert f'data-line="rx"' in html
        assert f'data-line="tx"' in html
    for key in ('awg0','awg1'):
        assert f'data-awg-instance="{key}"' in html
        assert f'id="{key}-connected"' in html
        assert f'id="{key}-rx-rate"' in html
        assert f'id="{key}-tx-rate"' in html
        assert f'id="{key}-rx-total"' in html
        assert f'id="{key}-tx-total"' in html
        assert f'id="{key}-uptime"' in html
        assert f'action="/server/{key}/restart"' in html
        assert f'action="/server/{key}/stop"' in html
        assert f'href="/servers/{key}/clients"' in html
        assert f'href="/servers/{key}/settings"' in html
    assert html.count('data-period="5m"')==3
    assert html.count('data-period="15m"')==3
    assert html.count('data-period="1h"')==3
    assert 'id="host-sockets-total"' in html
    assert 'id="wan-rx-rate"' in html and 'id="wan-tx-rate"' in html
    assert 'id="host-panel-ram"' in html


def test_status_and_history_are_separated_per_interface(ui):
    app,client,calls=ui
    old=app.ctl
    def fake(op,data=None):
        if op=='list':
            iface=data['interface']
            received,sent=(512,2048) if iface=='awg0' else (4096,12288)
            return {'running':True,'clients':[{'name':'sensitive-peer',
                'private_key':'SUPER_SECRET', 'enabled':True,
                'used_bytes':300,
                'stats':{'received':received,'sent':sent,'handshake':10**11}}]}
        if op=='history':
            iface=data['interface']; assert data['window'] in ('5m','15m','1h')
            return {'points':[{'ts':int(time.time())-60,'rx':1200 if iface=='awg0' else 9000,
                               'tx':300 if iface=='awg0' else 4500}]}
        return old(op,data)
    app.ctl=fake
    res=client.get('/api/overview/telemetry');assert res.status_code==200
    result=res.json()
    assert result['rx']==4608 and result['tx']==14336
    assert [x['interface'] for x in result['instances']]==['awg0','awg1']
    assert result['instances'][0]['rx']==512
    assert result['instances'][1]['rx']==4096
    assert result['instances'][0]['recorded_bytes']==300
    assert 'SUPER_SECRET' not in res.text and 'sensitive-peer' not in res.text
    short=client.get('/api/overview/series?window=5m');assert short.status_code==200
    series=short.json()['series']
    assert [x['interface'] for x in series]==['awg0','awg1']
    assert series[0]['points'][0]['rx']==1200
    assert series[1]['points'][0]['rx']==9000
    assert 'SUPER_SECRET' not in short.text
    assert client.get('/api/overview/series?window=2h').status_code==422
    assert ('history',{'interface':'awg0','window':'5m'}) not in calls  # mocked


def test_dashboard_endpoints_are_private(ui):
    app,client,_=ui
    client.cookies.clear()
    for route in ('/api/overview/telemetry','/api/overview/series?window=15m'):
        assert client.get(route).status_code==401


def test_restart_and_stop_require_csrf_and_explicit_interface(ui):
    _,client,calls=ui
    assert client.post('/server/awg1/restart',data={'csrf':'invalid'}).status_code==403
    csrf=token(client.get('/'))
    assert client.post('/server/awg1/restart',data={'csrf':csrf},follow_redirects=False).status_code==303
    assert ('server-restart',{'interface':'awg1'}) in calls
    assert ('server-restart',{'interface':'awg0'}) not in calls
    assert client.post('/server/awg9/restart',data={'csrf':csrf},follow_redirects=False).status_code == 404
    assert client.post('/server/../restart',data={'csrf':csrf},follow_redirects=False).status_code!=303


def test_history_short_windows_and_invalid_ranges():
    ctl=importlib.machinery.SourceFileLoader('awg31ctl_test_v092',str(ROOT/'src/awg31ctl')).load_module()
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE traffic_samples(measured_at INT, rx_delta INT, tx_delta INT)')
        db.execute('INSERT INTO traffic_samples VALUES(?,?,?)',(int(time.time())-60,6000,3000))
        for window in ('5m','15m','1h','24h'):
            result=ctl.traffic_history(db,{'window':window})
            assert result['points'] and result['points'][0]['rx']==6000
        with pytest.raises(ValueError):ctl.traffic_history(db,{'window':'oops'})


def test_js_and_css_keep_real_data_and_responsive_layout(ui):
    _,client,_=ui
    js=client.get('/assets/panel.js').text
    css=client.get('/assets/md3.css').text
    assert 'data-plot' in js
    assert '/api/overview/series' in js and '/api/overview/telemetry' in js
    assert 'windowLength' in js
    assert 'Math.random(' not in js.split('// Infrastructure dashboard:')[-1]
    assert '.instance-dash-grid' in css and '.host-kpi-grid' in css
    assert 'grid-template-columns:repeat(2,minmax(0,1fr))' in css
    assert '@media(max-width:680px)' in css


def test_host_history_written_to_its_own_database(tmp_path,monkeypatch):
    from importlib.util import spec_from_file_location,module_from_spec
    spec=spec_from_file_location('admin_dashboard_v092',ROOT/'src/awg31admin.py')
    admin=module_from_spec(spec);spec.loader.exec_module(admin)
    monkeypatch.setenv('AWG31_ROOT',str(tmp_path))
    database=tmp_path/'state.sqlite3'
    with sqlite3.connect(database) as con:
        con.execute('CREATE TABLE config (key TEXT, value TEXT)')
    now=int(time.time())
    common={'cpu_total':10000,'cpu_idle':5000,'mem_total':10000,'mem_available':6000,
            'swap_total':2000,'swap_free':1800,'disk_total':40000,'disk_free':28000,
            'uplink':'ens33','wan_rx':1000000,'wan_tx':2000000,'tcp':20,'udp':10}
    samples=[{'measured_at':now-60,**common},{'measured_at':now,**{
        **common,'cpu_total':20000,'cpu_idle':7000,'mem_available':5000,
        'wan_rx':1060000,'wan_tx':2120000,'tcp':22,'udp':11}}]
    monkeypatch.setattr(admin,'_host_snapshot',lambda:samples.pop(0))
    assert admin.sample_host_metrics()['ok']
    assert admin.sample_host_metrics()['ok']
    history=admin.host_metrics_history({'window':'5m'})
    assert history['window']=='5m'
    assert len(history['points'])==2
    last=history['points'][-1]
    assert last['rx']==1000.0 and last['tx']==2000.0
    assert last['cpu']==80.0
    assert last['ram']==50.0 and last['swap']==10.0 and last['disk']==30.0
    assert last['sockets']==33
    with pytest.raises(ValueError):admin.host_metrics_history({'window':'1d;rm -rf /'})
    # Host counters no longer live in the awg0 database (awg0 can be deleted).
    with sqlite3.connect(tmp_path/'host.sqlite3') as con:
        assert con.execute('SELECT count(*) FROM host_samples').fetchone()[0]==2
    with sqlite3.connect(database) as con:
        assert not con.execute("SELECT 1 FROM sqlite_master WHERE name='host_samples'").fetchone()
        assert con.execute('SELECT count(*) FROM config').fetchone()[0]==0
    assert (tmp_path/'host.sqlite3').stat().st_mode & 0o777 == 0o600


def test_host_telemetry_is_separate_from_awg_counters(ui):
    mod,client,_=ui
    original=mod.ctl
    def mock(op,data=None):
        if op=='host-history':
            return {'points':[{'ts':int(time.time()),'rx':1000.0,'tx':2000.0,
                  'cpu':42.0,'ram':66.0,'swap':10.0,'disk':40.0,'sockets':13}]}
        return original(op,data)
    mod.ctl=mock
    result=client.get('/api/overview/series?window=15m')
    assert result.status_code==200
    assert len(result.json()['host'])==1
    assert result.json()['host'][0]['rx']==1000.0
    assert 'host-history' in (ROOT/'src/awg31mgr').read_text()
    assert 'host-history' in (ROOT/'scripts/sudoers.sh').read_text()
