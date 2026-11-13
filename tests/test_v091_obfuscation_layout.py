"""UI v0.9.1: optional timing generation, single sidebar and live fleet metrics."""
from test_v080_workflows import ui
from importlib.machinery import SourceFileLoader
from pathlib import Path
import pytest

root=Path(__file__).resolve().parents[1]
ctl=SourceFileLoader('awgctl091',str(root/'src/awg31ctl')).load_module()

def test_large_cps_signature():
    signature='<b 0x'+('abcd'*900)+'>'
    params=ctl.validate_i_fields({'i_enabled':'1','i1':signature})
    assert params['i1']==signature
    assert ctl.validate_i_fields({'i_enabled':'0','i1':signature})['i_enabled']==0
    with pytest.raises(ValueError):ctl.validate_i_fields({'i_enabled':'1','i1':'<r 1001>'})

def test_optional_timing_generation(ui):
    _,c,_=ui
    base=c.get('/servers/awg1/api/obfuscation/generate')
    assert 'KeepaliveTimeout' not in base.json()
    custom=c.get('/servers/awg1/api/obfuscation/generate?timing_ranges=true')
    assert custom.json()['KeepaliveTimeout']=='9-11'
    assert custom.json()['RekeyAfterTime']=='112-118'
    assert 'id="generate-timings"' in c.get('/servers/awg1/settings').text

def test_one_sidebar_in_maintenance(ui):
    _,c,_=ui
    for tab in ('diagnostics','backups','restore','profiles','security','audit','system'):
        text=c.get('/maintenance?tab='+tab).text
        assert 'class="maint-tabs"' in text
        assert 'class="maint-nav"' not in text
        assert text.count('class="sidebar"')==1
        assert 'class="maint-nav-heading"' not in text
    assert 'display:flex!important;flex-direction:column!important' in c.get('/assets/md3.css').text

def test_fleet_telemetry_authenticated(ui):
    _,c,_=ui
    r=c.get('/api/overview/telemetry')
    assert r.status_code==200
    assert r.headers['cache-control']=='no-store'
    assert r.json()['rx']==0 and r.json()['tx']==0
    assert 'private_key' not in r.text
    for key in ('fleet-rx-rate','fleet-tx-rate','fleet-cpu','fleet-memory','fleet-uptime'):
        assert 'id="'+key+'"' in c.get('/').text
