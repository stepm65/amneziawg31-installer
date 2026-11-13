"""Regression tests for optional I1-I5 and site-to-site AllowedIPs.
No test changes real routing, kernel interfaces or firewall.
"""
import base64
from importlib.machinery import SourceFileLoader
from io import StringIO
import json
from pathlib import Path
import sqlite3
import sys
import types

import pytest
from fastapi.testclient import TestClient

PATH = Path(__file__).parents[1]
ctl = SourceFileLoader('awg31_routes_test', str(PATH/'src/awg31ctl')).load_module()


def profile():
    return dict(subnet='10.77.10.0/24', server_ip='10.77.10.1', port=45678,
                mtu=1380, endpoint='10.10.20.29', dns='1.1.1.1', mode='full',
                uplink='ens33', private_key='A'*44, public_key='B'*44,
                header_key=base64.b64encode(b'h'*32).decode(),
                Jc=4, Jmin=10, Jmax=50, S1=12, S2=12, S3=12, S4=12,
                H1='1', H2='2', H3='3', H4='4', RandomTrailers='on', DisableCookies='on')


def make_client(name, ip, routes='', enabled=1):
    return dict(name=name, ip=ip, private_key='X'*44, public_key='Y'*44,
                psk='Z'*44, enabled=enabled, routed_subnets=routes, i_enabled=0,
                i1='', i2='', i3='', i4='', i5='')


def test_i_parameters_optional_client_only_and_qr_generates():
    cfg=profile()
    peer=make_client('router','10.77.10.2')
    default_client=ctl.client_config(cfg, peer)
    assert '\nI1 =' not in default_client
    assert '\nI5 =' not in default_client
    cps=ctl.validate_i_fields({'i_enabled':'1','i1':'<r 48><t>', 'i2':'<b 0xaabbcc>'})
    assert cps['i_enabled']==1
    client=ctl.client_config(cfg,{**peer,**cps})
    assert 'I1 = <r 48><t>' in client
    assert 'I2 = <b 0xaabbcc>' in client
    assert 'I1 =' not in ctl.server_config(cfg,[{**peer,**cps}])
    assert '\nI1 =' not in ctl.client_config(cfg,{**peer,**cps,'i_enabled':0})
    import qrcode
    assert qrcode.make(client).size[0] > 0


@pytest.mark.parametrize('value',[
    '<r 0>', '<r 600>', '<b 0xa>', '<foo 4>', 'bad',
    '<r 48>\nAllowedIPs = 0.0.0.0/0', '<b 0xZZ>',
])
def test_malformed_or_oversized_i_rejected(value):
    with pytest.raises(ValueError): ctl.validate_i_fields({'i_enabled':'1','i1':value})


def test_i_enabled_requires_i1():
    with pytest.raises(ValueError, match='I1'):
        ctl.validate_i_fields({'i_enabled':'1'})
    assert ctl.validate_i_fields({'i_enabled':'0','i1':''})['i_enabled']==0


def test_db_migration_keeps_legacy_peers(tmp_path,monkeypatch):
    monkeypatch.setattr(ctl,'DB',tmp_path/'state.sqlite3')
    db=sqlite3.connect(ctl.DB)
    db.execute('''CREATE TABLE clients (name TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL,
                private_key TEXT NOT NULL, public_key TEXT UNIQUE NOT NULL,
                psk TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL)''')
    db.execute('INSERT INTO clients VALUES (?,?,?,?,?,?,?)',
               ('existing','10.77.10.2','PRIVATE','PUBLIC','PSK',1,'2026-11-12'))
    db.commit();db.close()
    con=ctl.get_conn()
    row=con.execute('SELECT * FROM clients WHERE name="existing"').fetchone()
    assert row['private_key']=='PRIVATE'
    assert row['routed_subnets']==''
    assert row['i_enabled']==0
    assert row['i1']==''
    assert len(row.keys())==22
    con.close()


def test_routes_reject_duplicates_and_reserved_or_overlap(tmp_path,monkeypatch):
    monkeypatch.setattr(ctl,'DB',tmp_path/'state.sqlite3')
    con=ctl.get_conn(True)
    con.execute('INSERT INTO clients (name,ip,private_key,public_key,psk,enabled,created_at,routed_subnets) VALUES (?,?,?,?,?,?,?,?)',
                ('other','10.77.10.3','x','y','z',1,'now','192.168.40.0/24'))
    con.commit()
    def fake_os(argv,**kw):
        return types.SimpleNamespace(returncode=0,stdout='[]',stderr='')
    monkeypatch.setattr(ctl.subprocess,'run',fake_os)
    assert ctl.parse_routes('192.168.50.0/24, 192.168.60.12',profile(),con) == '192.168.50.0/24, 192.168.60.12/32'
    for x in ('10.77.10.0/24','0.0.0.0/0','127.0.0.1','224.0.0.0/24',
              '192.168.40.0/24','192.168.50.0/24,192.168.50.5',
              '192.168.55.0/24\nPostUp = curl evil'):
        with pytest.raises(ValueError): ctl.parse_routes(x,profile(),con)
    con.close()


def test_route_renders_server_peer_only_and_firewall_scoped():
    cfg=profile()
    peer=make_client('site','10.77.10.2','192.168.50.0/24, 192.168.60.12/32')
    server=ctl.server_config(cfg,[peer])
    assert 'AllowedIPs = 10.77.10.2/32, 192.168.50.0/24, 192.168.60.12/32' in server
    assert 'PostUp = iptables -w -C FORWARD -i awg0 -o awg0 -d 192.168.50.0/24 -j ACCEPT' in server
    assert 'PostDown = iptables -w -D FORWARD -i awg0 -o awg0 -s 192.168.50.0/24 -j ACCEPT' in server
    client=ctl.client_config(cfg, peer)
    assert 'AllowedIPs = 0.0.0.0/0' in client
    assert 'AllowedIPs = 192.168.50.0/24' not in client


def test_modify_peer_route_without_restart(tmp_path,monkeypatch):
    monkeypatch.setattr(ctl,'DB',tmp_path/'state.sqlite3')
    monkeypatch.setattr(ctl,'CONF',tmp_path/'awg0.conf')
    monkeypatch.setattr(ctl,'IFACE','awg0')
    monkeypatch.setenv('AWG31_PEER_BACKUPS',str(tmp_path/'backups'))
    con=ctl.get_conn(True)
    ctl.put_settings(con,profile())
    con.execute('INSERT INTO clients (name,ip,private_key,public_key,psk,enabled,created_at) VALUES (?,?,?,?,?,?,?)',
                ('router','10.77.10.2','x','y','z',1,'now'))
    con.commit()
    ctl.atomic_write(ctl.CONF,ctl.server_config(profile(),ctl.peer_rows(con)))
    routes=set(); commands=[]
    def fake_os(argv,**kw):
        if argv[:3] == ['ip','link','show']:
            return types.SimpleNamespace(returncode=0, stdout='',stderr='')
        if argv[:4] == ['ip','-j','-4','route']:
            if 'table' in argv: return types.SimpleNamespace(returncode=0,stdout='[]',stderr='')
            r=argv[-1]
            return types.SimpleNamespace(returncode=0,stdout=json.dumps([{'dst':r,'dev':'awg0'}] if r in routes else []),stderr='')
        if argv[:4] == ['iptables','-w','-C','FORWARD']:
            return types.SimpleNamespace(returncode=1,stdout='',stderr='')
        raise AssertionError(f'Unexpected call: {argv}')
    monkeypatch.setattr(ctl.subprocess,'run',fake_os)
    def fake_run(*argv,stdin=None):
        commands.append(argv)
        if argv[:2] == ('awg-quick','strip'): return '[Interface]\nPrivateKey = TEST\n'
        if argv[:4] == ('ip','-4','route','add'): routes.add(argv[4]); return ''
        if argv[:4] == ('ip','-4','route','del'): routes.remove(argv[4]); return ''
        return ''
    monkeypatch.setattr(ctl,'run',fake_run)
    def req(payload):
        monkeypatch.setattr(sys,'stdin',StringIO(json.dumps(payload)))
        return ctl.client_network_update(con)
    assert req({'name':'router','routed_subnets':'192.168.50.0/24','i_enabled':'1','i1':'<r 48>'})['ok']
    assert routes=={'192.168.50.0/24'}
    assert any(x[:2]==('awg','syncconf') for x in commands)
    assert not any(x[0]=='systemctl' for x in commands)
    assert 'I1 = <r 48>' in ctl.client_config(profile(),dict(con.execute('select * from clients').fetchone()))
    assert '192.168.50.0/24' in ctl.CONF.read_text()
    assert req({'name':'router','routed_subnets':'','i_enabled':'0','i1':'<r 48>'})['ok']
    assert not routes
    assert '192.168.50.0/24' not in ctl.CONF.read_text()
    assert any((tmp_path/'backups').iterdir())
    con.close()


def test_web_client_routes_and_i_settings_with_csrf(tmp_path,monkeypatch):
    from test_web import create_app
    module = create_app(tmp_path,monkeypatch)
    calls=[]
    def fake_ctl(op,data=None):
        calls.append((op,data))
        if op=='servers': return {'servers':[{'interface':'awg0','subnet':'10.77.10.0/24','port':45678,'running':True,'clients':1}]}
        if op=='list': return {'interface':'awg0','subnet':'10.77.10.0/24','server_ip':'10.77.10.1','port':45678,
                              'mtu':1380,'endpoint':'10.10.20.29','dns':'1.1.1.1','mode':'full','uplink':'ens33',
                              'public_key':'A'*44,'running':True,
                              'clients':[{'name':'router','ip':'10.77.10.2','enabled':1,'stats':{},'routed_subnets':''}]}
        if op=='download': return {'config':'[Interface]\nPrivateKey = secret\n','ip':'10.77.10.2',
                                    'routed_subnets':'192.168.50.0/24','i_enabled':False,'i1':'','i2':'','i3':'','i4':'','i5':''}
        if op=='add': return {'name':data['name']}
        return {'ok':True}
    module.ctl=fake_ctl
    client=TestClient(module.app)
    client.post('/login',data={'password':'testpassword1234'})
    main=client.get('/')
    assert 'routed_subnets' in main.text
    assert 'I1–I5' in main.text
    detail=client.get('/client/router')
    assert '192.168.50.0/24' in detail.text
    assert 'client/router/network' in detail.text
    invalid=client.post('/client/router/network',data={'csrf':'invalid','routed_subnets':'192.168.60.0/24'})
    assert invalid.status_code==403
    csrf=main.text.split('name="csrf" value="')[1].split('"')[0]
    result=client.post('/client/router/network',data={'csrf':csrf,'routed_subnets':'192.168.60.0/24',
                        'i_enabled':'1','i1':'<r 48>'},follow_redirects=False)
    assert result.status_code==303
    assert ('client-network',{'name':'router','routed_subnets':'192.168.60.0/24',
                             'i_enabled':'1','i1':'<r 48>','i2':'','i3':'','i4':'','i5':'','interface':'awg0'}) in calls
