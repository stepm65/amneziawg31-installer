import base64
from importlib.machinery import SourceFileLoader
from pathlib import Path
import json
import sqlite3
import pytest
from fastapi.testclient import TestClient

DIR=Path(__file__).parents[1]
ctl=SourceFileLoader('awg31_multictl',str(DIR/'src/awg31ctl')).load_module()
mgr=SourceFileLoader('awg31_multimgr',str(DIR/'src/awg31mgr')).load_module()


def params(**changes):
    d={'subnet':'10.77.10.0/24','server_ip':'10.77.10.1','port':45678,'mtu':1380,
       'dns':'1.1.1.1','endpoint':'vpn.example.com','mode':'full','uplink':'ens3',
       'header_key':base64.b64encode(b'A'*32).decode(), 'Jc':4,'Jmin':10,'Jmax':50,
       'S1':12,'S2':12,'S3':12,'S4':12,'H1':'1','H2':'2','H3':'3','H4':'4',
       'RandomTrailers':'on','DisableCookies':'on','ContentPaddingAddition':'0-16'}
    d.update(changes)
    return d


def test_obfuscation_custom_fields_and_generated_profiles():
    cfg=params()
    obf=ctl.validate_obfuscation({'S1':34,'S2':55,'H1':'101-200','H2':'301-400',
                                  'H3':'501','H4':'900', 'RandomTrailers':'off',
                                  'ContentPaddingAddition':'8-20'},cfg)
    rendered=ctl.awg_lines({**cfg,**obf})
    assert 'S1 = 34' in rendered and 'H1 = 101-200' in rendered
    assert 'RandomTrailers' not in rendered
    assert 'ContentPaddingAddition = 8-20' in rendered
    for _ in range(25):
        generated=ctl.fresh_obfuscation()
        assert ctl.validate_obfuscation({}, {**cfg,**generated})
        assert len(base64.b64decode(generated['header_key']))==32


def test_obfuscation_rejects_broken_inputs():
    with pytest.raises(ValueError,match='overlaps'):
        ctl.validate_obfuscation({'H1':'100-200','H2':'150-220'},params())
    with pytest.raises(ValueError,match='HeaderProtectionKey'):
        ctl.validate_obfuscation({'HeaderProtectionKey':'abcd'},params())
    with pytest.raises(ValueError,match='S1'):
        ctl.validate_obfuscation({'S1':5},params())
    with pytest.raises(ValueError):
        ctl.validate_obfuscation({'H1':'9; rm -rf /'},params())


def create_db(path,subnet,port,clients=0):
    path.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute('create table config (key text primary key,value text)')
        db.execute('create table clients (name text)')
        db.executemany('insert into config values (?,?)',
            [('subnet',subnet),('port',str(port)),('mtu','1280'),('mode','full')])
        for i in range(clients): db.execute('insert into clients values (?)',(f'peer{i}',))


def test_isolated_server_databases_and_inventory(tmp_path,monkeypatch):
    monkeypatch.setattr(mgr,'BASE',tmp_path/'db')
    monkeypatch.setattr(mgr,'CONFIG_DIR',tmp_path/'cfg')
    mgr.CONFIG_DIR.mkdir()
    create_db(mgr.db_path('awg0'),'10.77.10.0/24',45678,1)
    create_db(mgr.db_path('awg1'),'10.77.20.0/24',51821,3)
    mgr.conf_path('awg0').write_text('first')
    mgr.conf_path('awg1').write_text('second')
    assert mgr.db_path('awg0')!=mgr.db_path('awg1')
    assert mgr.interfaces()==['awg0','awg1']
    assert mgr.conf_path('awg0').read_text()=='first'
    assert mgr.conf_path('awg1').read_text()=='second'
    monkeypatch.setattr(mgr.subprocess,'run',lambda *args,**kw: type('P',(),{'returncode':0})())
    assert mgr.info('awg1')['clients']==3


def test_web_server_switch_and_generator(tmp_path,monkeypatch):
    # Reuse the existing test app fixture shape.
    from test_web import create_app
    module=create_app(tmp_path,monkeypatch)
    state={'interface':'awg0','subnet':'10.77.10.0/24','port':45678,
           'mtu':1380,'dns':'1.1.1.1','endpoint':'10.10.20.29',
           'mode':'full','uplink':'ens33','running':True,'clients':[]}
    module.ctl=lambda op,data=None: ({'servers':[
        {'interface':'awg0','subnet':'10.77.10.0/24','port':45678,'running':True,'clients':0},
        {'interface':'awg1','subnet':'10.77.20.0/24','port':51821,'running':False,'clients':0}]}
        if op=='servers' else ({**state,'interface':(data or {}).get('interface','awg0')} if op=='list'
        else {'ok':True}))
    c=TestClient(module.app)
    assert c.get('/api/obfuscation/generate').status_code==401
    c.post('/login',data={'password':'testpassword1234'})
    page=c.get('/').text
    assert 'Создать сервер' in page and 'HeaderProtectionKey' in page
    assert 'Сгенерировать параметры' in page
    result=c.get('/api/obfuscation/generate')
    assert result.status_code==200 and len(base64.b64decode(result.json()['HeaderProtectionKey']))==32
    assert c.get('/server/awg1',follow_redirects=False).status_code==303
    assert 'awg1' in c.cookies.get('awg31_server')
    assert c.get('/server/../../etc/passwd').status_code in (404,307)


def test_refuse_port_and_subnet_collision(tmp_path,monkeypatch):
    monkeypatch.setattr(mgr,'BASE',tmp_path/'state')
    monkeypatch.setattr(mgr,'CONFIG_DIR',tmp_path/'conf')
    mgr.CONFIG_DIR.mkdir()
    create_db(mgr.db_path('awg0'),'10.77.10.0/24',45678)
    mgr.conf_path('awg0').write_text('private')
    monkeypatch.setattr(mgr,'CTL',str(DIR/'src/awg31ctl'))
    class Proc:
        def __init__(self,args):
            self.returncode=1 if args[:3]==['ip','link','show'] else 0
            self.stdout='[]' if args[:3]==['ip','-j','-4'] else ''
    monkeypatch.setattr(mgr.subprocess,'run',lambda args,**kwargs: Proc(args))
    p={'subnet':'10.77.20.0/24','port':51821,'mtu':1280,'endpoint':'vpn.example.net',
       'dns':'1.1.1.1','mode':'full','uplink':'ens3'}
    assert mgr.check_new('awg1',p)['port']==51821
    with pytest.raises(ValueError,match='overlaps'):
        mgr.check_new('awg1',{**p,'subnet':'10.77.10.0/24'})
    with pytest.raises(ValueError,match='already used'):
        mgr.check_new('awg1',{**p,'port':45678})
    with pytest.raises(ValueError):
        mgr.check_new('awg0',p)


def test_server_creation_form_is_authenticated_and_csrf_protected(tmp_path, monkeypatch):
    from test_web import create_app
    module=create_app(tmp_path,monkeypatch)
    c=TestClient(module.app)
    payload={'interface':'awg1','subnet':'10.77.20.0/24','port':'51821',
             'mtu':'1280','endpoint':'vpn.example.net','dns':'1.1.1.1',
             'mode':'full','uplink':'ens3','csrf':'bad'}
    assert c.post('/server/create',data=payload).status_code==401
    c.post('/login',data={'password':'testpassword1234'})
    assert c.post('/server/create',data=payload).status_code==403
    token=c.get('/').text.split('name="csrf" value="')[1].split('"')[0]
    payload['csrf']=token
    result=c.post('/server/create',data=payload,follow_redirects=False)
    assert result.status_code==303
    assert 'awg31_server=awg1' in result.headers['set-cookie']
