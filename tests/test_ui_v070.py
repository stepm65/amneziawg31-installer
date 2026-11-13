"""Web-only UI regression tests. No AWG kernel, VPN config, sudo or filesystem writes."""
import hashlib
import json
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec
from fastapi.testclient import TestClient
import pytest

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def ui(tmp_path, monkeypatch):
    salt=b'5'*16
    auth={'salt':salt.hex(),'password_hash':hashlib.scrypt(b'testpassword1234',salt=salt,n=2**14,r=8,p=1,dklen=32).hex(),
          'session_key':'F'*48}
    f=tmp_path/'auth.json';f.write_text(json.dumps(auth))
    monkeypatch.setenv('AWG31_AUTH',str(f));monkeypatch.setenv('AWG31_COOKIE_SECURE','0')
    spec=spec_from_file_location('web_ui_07',ROOT/'src'/'web.py')
    module=module_from_spec(spec);spec.loader.exec_module(module)
    calls=[]
    def ctl(op,data=None):
        calls.append((op,data))
        if op=='diagnostics':
            return {'kernel':{'ok':True,'output':'7.0.0-43-generic'},
                    'device':{'ok':True,'output':'3: awg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 state UNKNOWN'},
                    'forwarding':{'ok':True,'output':'1'},
                    'dkms':{'ok':False,'output':'missing headers'},
                    'panel':{'ok':True,'output':'active'}}
        if op=='backup-list':return {'backups':[{'name':'awg31-20261113T012228Z-b68af64ecb.tar.gz','size':2660}]}
        if op=='audit-list':return {'entries':[{'timestamp':'2026-11-13T01:00Z','event':'backup_created','target':'awg0'}]}
        if op=='servers':return {'servers':[{'interface':'awg0','subnet':'10.77.10.0/24','port':45678,'clients':0,'running':True}]}
        if op=='list':return {'interface':'awg0','subnet':'10.77.10.0/24','server_ip':'10.77.10.1',
                             'port':45678,'mtu':1380,'endpoint':'vpn.example.test','dns':'1.1.1.1','mode':'full','uplink':'ens3',
                             'public_key':'P'*44,'running':True,'clients':[]}
        if op=='history':return {'points':[],'window':'24h'}
        return {'ok':True}
    module.ctl=ctl
    client=TestClient(module.app)
    client.post('/login',data={'password':'testpassword1234'})
    return module,client,calls


def test_app_sidebar_sections_are_grouped_no_top_kernel(ui):
    _,client,_=ui
    html=client.get('/').text
    assert '<span class="top-kernel">' not in html
    assert 'РАБОЧЕЕ ПРОСТРАНСТВО' in html and 'КОНФИГУРАЦИЯ' in html and 'СИСТЕМА' in html
    assert 'Серверы и интерфейсы</span></a>' not in html
    assert 'Обслуживание и безопасность</span></a>' not in html
    assert 'data-nav-key="overview"' in html
    assert 'data-nav-key="clients"' in html
    assert 'data-nav-key="maintenance"' in html
    assert 'aria-controls="app-sidebar"' in html
    assert 'id="sidebar-collapse"' in html
    assert '/assets/panel.js?v=0.7.0' in html
    assert '/assets/md3.css?v=0.7.0' in html
    js=client.get('/assets/panel.js').text
    assert 'mobile-nav-toggle' in js and 'sidebar-collapse' in js
    assert 'nav-open' in js and 'nav-collapsed' in js
    css=client.get('/assets/md3.css').text
    assert '.maint-workspace' in css and '.health-grid' in css and '.nav-scrim' in css
    assert 'grid-template-columns:252px minmax(0,1fr)' in css


def test_diagnostics_cards_health_and_no_duplicate_title(ui):
    _,client,calls=ui
    html=client.get('/maintenance').text
    assert html.count('<h1>Обслуживание и безопасность</h1>')==1
    assert '<h2>Обслуживание и безопасность</h2>' not in html
    assert 'Диагностика, резервные копии и управление доступом' in html
    assert html.count('class="health-card ') == 5
    assert '4<span> / 5</span>' in html
    assert '7.0.0-43-generic' in html
    assert 'awg0 · UP' in html
    assert 'Требует внимания' in html
    assert 'missing headers' in html
    assert '&lt;POINTOPOINT' in html
    assert '<POINTOPOINT' not in html
    assert ('diagnostics', {'interface':'awg0'}) in calls
    assert not any(op in ('backup-list','audit-list') for op,_ in calls)


def test_maintenance_independent_subpages_and_404(ui):
    _,client,calls=ui
    assert client.get('/maintenance?tab=unknown').status_code==404
    for tab in ('diagnostics','backups','restore','profiles','security','audit','system'):
        r=client.get('/maintenance?tab='+tab)
        assert r.status_code==200,tab
        assert 'class="maint-nav"' in r.text
        assert r.text.count('class="maint-nav-link is-active"')==1
        assert 'href="/maintenance?tab='+tab+'"' in r.text
    b=client.get('/maintenance?tab=backups')
    assert 'Создать полную резервную копию' in b.text
    assert 'action="/maintenance/backup"' in b.text
    assert 'action="/maintenance/restore"' not in b.text
    r=client.get('/maintenance?tab=restore')
    assert 'action="/maintenance/restore"' in r.text
    assert 'ВОССТАНОВИТЬ' in r.text
    s=client.get('/maintenance?tab=security')
    assert 'action="/maintenance/password"' in s.text
    assert 'action="/maintenance/backup"' not in s.text
    a=client.get('/maintenance?tab=audit')
    assert 'backup_created' in a.text
    assert 'action="/maintenance/password"' not in a.text
    p=client.get('/maintenance?tab=profiles')
    assert 'action="/maintenance/profile"' in p.text
    assert 'name="profile"' in p.text
    sys=client.get('/maintenance?tab=system')
    assert 'sudo awg31 doctor' in sys.text
    assert 'sudo awg31 restart-panel' in sys.text
    assert 'sudo awg31 restore ' not in sys.text


def test_maintenance_backup_csrf_and_post_redirect(ui):
    _,client,calls=ui
    html=client.get('/maintenance?tab=backups').text
    token=html.split('name="csrf" value="')[1].split('"')[0]
    assert client.post('/maintenance/backup',data={'csrf':'wrong'}).status_code==403
    result=client.post('/maintenance/backup',data={'csrf':token},follow_redirects=False)
    assert result.status_code==303
    assert result.headers['location']=='/maintenance?tab=backups'
    assert ('backup-create',{}) in calls


def test_locale_and_auth_boundaries(ui):
    _,client,_=ui
    r=client.get('/lang/en?next=%2Fmaintenance');assert r.status_code==200 or r.status_code==303
    html=client.get('/maintenance?tab=security').text
    assert 'Security' in html and 'Maintenance sections' in html
    assert 'Change administrator password' in html
    client.get('/logout')
    assert client.get('/maintenance?tab=diagnostics').status_code==401
    assert client.get('/maintenance?tab=backups').status_code==401
