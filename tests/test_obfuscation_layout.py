"""Regression tests for optional AWG 3.1 timing ranges, long CPS and fleet telemetry."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import json
from test_workflows import ui
import pytest

ROOT = Path(__file__).resolve().parents[1]
ctl = SourceFileLoader('awgctl_v091', str(ROOT/'src/awg31ctl')).load_module()


def test_large_cps_is_optional_client_only():
    long_signature = '<b 0x' + ('abcd' * 900) + '>'  # 1800 bytes; old cap was 768.
    opts = ctl.validate_i_fields({'i_enabled':'1', 'i1':long_signature})
    assert opts['i1'] == long_signature
    assert opts['i_enabled'] == 1
    assert ctl.validate_i_fields({'i_enabled':'0', 'i1':long_signature})['i_enabled'] == 0
    for raw in ['<b 0x' + ('aa' * 8200) + '>', '<r 1001>', '<b 0xabc>']:
        with pytest.raises(ValueError):
            ctl.validate_i_fields({'i_enabled':'1','i1':raw})


def test_timing_ranges_are_opt_in(ui):
    _, client, calls = ui
    default=client.get('/servers/awg1/api/obfuscation/generate')
    assert default.status_code == 200
    assert 'KeepaliveTimeout' not in default.json()
    optional=client.get('/servers/awg1/api/obfuscation/generate?timing_ranges=true')
    assert optional.status_code == 200
    result=optional.json()
    assert result['KeepaliveTimeout']=='9-11'
    assert result['RekeyAfterTime']=='112-118'
    assert result['RejectAfterTime']=='176-184'
    assert set(('RekeyTimeout','MaxHandshakeAttempts')) <= result.keys()
    settings=client.get('/servers/awg1/settings').text
    assert 'id="generate-timings"' in settings
    js=client.get('/assets/panel.js').text
    assert 'timing_ranges=' in js and 'generate-timings' in js


def test_only_one_sidebar_and_maintenance_tabs(ui):
    _,client,calls=ui
    for tab in ('diagnostics','backups','restore','profiles','security','audit','system'):
        text=client.get('/maintenance?tab='+tab).text
        assert text.count('class="sidebar"')==1
        assert 'class="maint-tabs"' in text
        assert 'class="maint-nav"' not in text
        assert 'class="maint-nav-heading"' not in text
        assert text.count('class="maint-nav-link is-active"')==1
        assert text.count('class="maint-panel"')==1
    css=client.get('/assets/md3.css').text
    assert '.maint-workspace {display:flex!important;flex-direction:column!important' in css


def test_authenticated_fleet_telemetry_aggregates_only_safe_values(ui,monkeypatch):
    mod,client,calls=ui
    assert client.get('/api/overview/telemetry').status_code==200
    result=client.get('/api/overview/telemetry').json()
    assert result['rx']==0 and result['tx']==0 and result['connected']==0
    assert isinstance(result['uptime'],int) or result['uptime'] is None
    assert 'private_key' not in json.dumps(result)
    # Real metrics must be available on the overview, but never hardcoded.
    overview=client.get('/').text
    assert 'id="wan-rx-rate"' in overview
    assert 'id="wan-tx-rate"' in overview
    assert 'id="host-cpu"' in overview
    assert 'id="host-ram"' in overview
    assert 'id="host-uptime"' in overview
    assert 'id="host-sockets-total"' in overview
    script=client.get('/assets/panel.js').text
    assert '/api/overview/telemetry' in script


def test_long_config_hides_oversized_qr_but_keeps_export(ui,monkeypatch):
    mod,client,calls=ui
    huge = '<b 0x'+'abcd'*900+'>'
    conf='[Interface]\nPrivateKey = EXAMPLE\nI1 = '+huge+'\n[Peer]\nPublicKey = TEST\n'
    old=mod.ctl
    def fake(op,data=None):
        if op=='download':
            return {'config':conf,'ip':'10.77.20.2','routed_subnets':'','i_enabled':True,
                    'i1':huge,'client_public_key':'TEST'}
        return old(op,data)
    mod.ctl=fake
    page=client.get('/servers/awg1/clients/beta')
    assert page.status_code==200
    assert 'class="qr-too-large"' in page.text
    assert 'id="detail-i1"' in page.text
    assert 'href="/servers/awg1/clients/beta/download"' in page.text
    assert 'maxlength="16384"' in page.text


def test_fleet_telemetry_never_exposes_client_keys_and_is_per_interface(ui):
    mod,client,calls=ui
    previous=mod.ctl
    def fake(op, data=None):
        if op=='list':
            idx=0 if data.get('interface')=='awg0' else 1
            return {'clients':[{'enabled':True,'name':'secret-name',
                'private_key':'SECRET_MUST_NOT_LEAK',
                'stats':{'received':100+idx*50,'sent':200+idx*70,'handshake':10**11}}]}
        return previous(op,data)
    mod.ctl=fake
    response=client.get('/api/overview/telemetry')
    assert response.status_code==200
    data=response.json()
    assert data['rx']==250 and data['tx']==470 and data['connected']==2
    assert 'SECRET_MUST_NOT_LEAK' not in response.text
    assert 'secret-name' not in response.text
    assert ('list',{'interface':'awg0'}) not in calls  # mocked away, not a single-server shortcut
