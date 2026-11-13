from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_file_location, module_from_spec
from datetime import datetime, timezone, timedelta
from pathlib import Path
import hashlib
import io
import json
import os
import sqlite3
import tarfile

import pytest
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parents[1]
ctl=SourceFileLoader('ctl06',str(ROOT/'src/awg31ctl')).load_module()
admin=SourceFileLoader('admin06',str(ROOT/'src/awg31admin.py')).load_module()


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl,'DB',tmp_path/'state.sqlite3')
    monkeypatch.setattr(ctl,'CONF',tmp_path/'awg0.conf')
    monkeypatch.setattr(ctl,'IFACE','awg0')
    con=ctl.get_conn(create=True)
    cfg={'subnet':'10.77.10.0/24','server_ip':'10.77.10.1','port':51820,'mtu':1380,
         'endpoint':'test.example','dns':'1.1.1.1','mode':'full','uplink':'ens33',
         'private_key':'A'*44,'public_key':'B'*44,'header_key':'C'*44,
         'Jc':4,'Jmin':10,'Jmax':50,'S1':12,'S2':12,'S3':12,'S4':12}
    ctl.put_settings(con,cfg)
    con.execute('''INSERT INTO clients (name,ip,private_key,public_key,psk,enabled,created_at)
                   VALUES (?,?,?,?,?,?,?)''',('test','10.77.10.2','private','PUBLIC','PSK',1,'2026-11-11'))
    con.commit()
    return con


def test_policy_and_expiration_default(tmp_path,monkeypatch):
    con=setup_db(tmp_path,monkeypatch)
    expiry=(datetime.now(timezone.utc)-timedelta(days=1)).date().isoformat()
    policy=ctl.validate_policy({'expires_at':expiry,'traffic_limit_bytes':'1000','comment':'NAS #1'})
    assert policy['comment']=='NAS #1'
    assert policy['expires_at'].endswith('+00:00')
    assert policy['traffic_limit_bytes']==1000
    with pytest.raises(ValueError): ctl.validate_policy({'traffic_limit_bytes':'-1'})
    with pytest.raises(ValueError): ctl.validate_policy({'expires_at':'yesterday'})
    con.execute('UPDATE clients SET expires_at=? WHERE name="test"',(policy['expires_at'],))
    con.commit()
    monkeypatch.setattr(ctl,'live_stats',lambda:{})
    monkeypatch.setattr(ctl,'apply',lambda cfg,con:None)
    outcome=ctl.sample_usage(con)
    assert outcome['disabled']==['test']
    assert con.execute('SELECT enabled,disabled_reason FROM clients').fetchone()[:]==(0,'expired')
    assert len(ctl.traffic_history(con,{'window':'24h'})['points'])==1
    with pytest.raises(ValueError): ctl.traffic_history(con,{'window':'3y'})
    con.close()


def test_traffic_quota_reset_counter_and_no_double_count(tmp_path,monkeypatch):
    con=setup_db(tmp_path,monkeypatch)
    con.execute('UPDATE clients SET traffic_limit_bytes=200 WHERE name="test"');con.commit()
    counter={'received':100,'sent':50,'handshake':0}
    monkeypatch.setattr(ctl,'live_stats',lambda:{'PUBLIC':dict(counter)})
    monkeypatch.setattr(ctl,'apply',lambda cfg,con:None)
    assert ctl.sample_usage(con)['disabled']==[]
    assert con.execute('SELECT used_bytes FROM clients').fetchone()[0]==150
    assert ctl.sample_usage(con)['disabled']==[]
    assert con.execute('SELECT used_bytes FROM clients').fetchone()[0]==150
    counter.update(received=200,sent=100)
    assert ctl.sample_usage(con)['disabled']==['test']
    assert con.execute('SELECT enabled,used_bytes FROM clients').fetchone()[:]==(0,300)
    con.close()


def test_migration_from_old_database_retains_keys(tmp_path,monkeypatch):
    db=tmp_path/'state.sqlite3'
    with sqlite3.connect(db) as con:
        con.execute('''CREATE TABLE clients (name TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL,
                      private_key TEXT NOT NULL, public_key TEXT UNIQUE NOT NULL,
                      psk TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                      created_at TEXT NOT NULL)''')
        con.execute('INSERT INTO clients VALUES (?,?,?,?,?,?,?)',
                    ('legacy','10.77.10.2','private','public','psk',1,'yesterday'))
    monkeypatch.setattr(ctl,'DB',db)
    with ctl.get_conn() as con:
        row=con.execute('SELECT * FROM clients').fetchone()
        assert row['private_key']=='private'
        assert row['traffic_limit_bytes']==0
        assert row['expires_at']==''
        assert con.execute('SELECT count(*) FROM traffic_samples').fetchone()[0]==0


def test_auth_password_change_revokes_old_session(tmp_path,monkeypatch):
    salt=b'1'*16
    auth={'salt':salt.hex(),'password_hash':hashlib.scrypt(b'old-passphrase123',salt=salt,n=2**14,r=8,p=1,dklen=32).hex(),
          'session_key':'T'*48}
    f=tmp_path/'auth.json';f.write_text(json.dumps(auth));os.chmod(f,0o640)
    monkeypatch.setenv('AWG31_AUTH',str(f))
    monkeypatch.setenv('AWG31_AUDIT',str(tmp_path/'audit.jsonl'))
    assert admin.password_change({'old_password':'old-passphrase123','new_password':'new-passphrase456'})['ok']
    newer=json.loads(f.read_text())
    assert newer['session_key']==auth['session_key']
    assert newer['auth_version']
    assert newer['password_hash']!=auth['password_hash']
    with pytest.raises(ValueError): admin.password_change({'old_password':'old-passphrase123','new_password':'other-passphrase123'})
    assert admin.audit_recent()['entries'][0]['event']=='password_changed'


def test_safe_backup_contains_only_scoped_files_and_manifest(tmp_path,monkeypatch):
    monkeypatch.setenv('AWG31_ROOT',str(tmp_path/'db'))
    monkeypatch.setenv('AWG31_BACKUP_DIR',str(tmp_path/'backups'))
    monkeypatch.setenv('AWG31_AUDIT',str(tmp_path/'audit.jsonl'))
    auth=tmp_path/'auth.json';auth.write_text('{"secret":"TEST"}')
    monkeypatch.setenv('AWG31_AUTH',str(auth))
    db=tmp_path/'db'/'state.sqlite3';db.parent.mkdir()
    with sqlite3.connect(db) as con:
        con.execute('CREATE TABLE config (key TEXT,value TEXT)')
        con.execute('INSERT INTO config VALUES (?,?)',('subnet','10.77.10.0/24'))
    cfg=tmp_path/'awg0.conf';cfg.write_text('PrivateKey = TESTSECRET\n')
    class FakeManager:
        @staticmethod
        def interfaces():return ['awg0']
        @staticmethod
        def db_path(i):return db
        @staticmethod
        def conf_path(i):return cfg
    output=admin.create_backup(FakeManager)
    assert output['ok']
    exported=admin.export_backup({'name':output['name']})
    import base64
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(exported['content'])),mode='r:gz') as tf:
        assert sorted(tf.getnames())==['auth/auth.json','configs/awg0.conf','databases/awg0.sqlite3','manifest.json']
        assert b'TESTSECRET' in tf.extractfile('configs/awg0.conf').read()
        mf=json.load(tf.extractfile('manifest.json'))
        assert mf['format']=='awg31-backup-v1'
    with pytest.raises(ValueError):admin.export_backup({'name':'../../etc/shadow'})
    assert (tmp_path/'backups'/output['name']).stat().st_mode&0o777==0o600


def test_web_policy_history_maintenance_security(tmp_path,monkeypatch):
    salt=b'1'*16
    auth={'salt':salt.hex(),'password_hash':hashlib.scrypt(b'testpassword1234',salt=salt,n=2**14,r=8,p=1,dklen=32).hex(),
          'session_key':'B'*48}
    path=tmp_path/'auth.json';path.write_text(json.dumps(auth))
    monkeypatch.setenv('AWG31_AUTH',str(path));monkeypatch.setenv('AWG31_COOKIE_SECURE','0')
    spec=spec_from_file_location('web_06',ROOT/'src/web.py')
    module=module_from_spec(spec);spec.loader.exec_module(module)
    calls=[]
    def fake(op,data=None):
        calls.append((op,data))
        if op=='list':return {'interface':'awg0','subnet':'10.77.10.0/24', 'server_ip':'10.77.10.1',
          'port':45678,'mtu':1380,'endpoint':'example.org','dns':'1.1.1.1','mode':'full',
          'uplink':'ens3','public_key':'pub','running':True, 'clients':[]}
        if op=='diagnostics':return {'kernel':{'ok':True,'output':'7.0'}}
        if op=='backup-list':return {'backups':[]}
        if op=='audit-list':return {'entries':[]}
        if op=='history':return {'points':[],'window':'24h'}
        if op=='servers':return {'servers':[{'interface':'awg0','subnet':'10.77.10.0/24','port':45678,'clients':0,'running':True}]}
        return {'ok':True}
    module.ctl=fake
    client=TestClient(module.app)
    assert client.get('/api/history').status_code==401
    assert client.get('/maintenance').status_code==401
    client.post('/login',data={'password':'testpassword1234'})
    assert client.get('/maintenance').status_code==200
    assert 'Резервные копии' in client.get('/maintenance').text
    assert client.get('/api/history').json()['points']==[]
    assert client.get('/api/history?window=bad').status_code==422
    csrf=client.get('/maintenance?tab=backups').text.split('name="csrf" value="')[1].split('"')[0]
    assert client.post('/maintenance/backup',data={'csrf':'bad'}).status_code==403
    assert client.post('/maintenance/backup',data={'csrf':csrf},follow_redirects=False).status_code==303
    assert ('backup-create',{}) in calls
    assert client.post('/maintenance/password',data={'csrf':csrf,'old':'old','new':'x'*12,'confirm':'other'}).status_code==200
