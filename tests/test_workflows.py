"""Multi-instance routing and scheduled-backup regression checks."""
import hashlib
import importlib.util
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

ROOT=Path(__file__).resolve().parents[1]


@pytest.fixture
def ui(tmp_path,monkeypatch):
    salt=b'8'*16
    password=b'correct-test-password'
    auth={'salt':salt.hex(), 'password_hash':hashlib.scrypt(password,salt=salt,n=2**14,r=8,p=1,dklen=32).hex(),
          'session_key':'Z'*48}
    f=tmp_path/'auth.json';f.write_text(json.dumps(auth))
    monkeypatch.setenv('AWG31_AUTH',str(f));monkeypatch.setenv('AWG31_COOKIE_SECURE','0')
    spec=importlib.util.spec_from_file_location('web080',ROOT/'src/web.py')
    app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
    calls=[]
    def fake(op,data=None):
        data=data or {}; calls.append((op,dict(data)))
        iface=data.get('interface','awg0')
        if op=='servers':return {'servers':[
            {'interface':'awg0','subnet':'10.77.10.0/24','port':45678,'clients':1,'running':True},
            {'interface':'awg1','subnet':'10.77.20.0/24','port':51821,'clients':1,'running':True}]}
        if op=='list':
            prefix='10.77.20' if iface=='awg1' else '10.77.10'
            return {'interface':iface,'subnet':prefix+'.0/24', 'port':51821 if iface=='awg1' else 45678,
                    'mtu':1380,'dns':'1.1.1.1','endpoint':'vpn.example.test','mode':'full','uplink':'ens3',
                    'running':True,'public_key':'A'*44,
                    'clients':[{'name':'beta' if iface=='awg1' else 'alpha','ip':prefix+'.2','enabled':True,'stats':{}}]}
        if op=='download':return {'config':'[Interface]\nPrivateKey = TEST_ONLY\n','ip':'10.77.20.2',
                                 'routed_subnets':'','i_enabled':False}
        if op=='add':return {'name':data['name']}
        if op=='diagnostics':return {'kernel':{'ok':True,'output':'7.0.0-43'},'loaded_module':{'ok':True,'output':'3.1.20260812'}}
        if op=='history':return {'points':[]}
        if op=='backup-list':return {'backups':[
            {'name':'awg31-20261112T030000Z-0123456789.tar.gz','size':1024},
            {'name':'awg31-20261113T030000Z-0123456789.tar.gz','size':2048}]}
        if op=='backup-policy':return {'policy':{'frequency':'daily','hour':3,'minute':0,'weekday':0,'retention_days':21,'max_copies':15}}
        if op=='backup-restore':return {'scheduled':'awg31-restore-123'}
        if op=='backup-check':return {'ok':True}
        return {'ok':True}
    app.ctl=fake
    c=TestClient(app.app)
    assert c.post('/login',data={'password':password.decode()}).status_code==200
    return app,c,calls


def token(page):return page.text.split('name="csrf" value="')[1].split('"')[0]


def test_fleet_home_and_server_pages_are_separate(ui):
    _,c,calls=ui
    root=c.get('/'); assert root.status_code==200
    assert 'Обзор инфраструктуры' in root.text
    assert root.text.count('class="instance-dashboard"')==2
    assert 'class="host-kpi-grid"' in root.text and 'class="instance-dash-grid"' in root.text
    assert 'action="/client"' not in root.text
    listing=c.get('/servers');assert 'Создать сервер' in listing.text
    assert 'new-instance' in listing.text
    awg0=c.get('/servers/awg0/clients');awg1=c.get('/servers/awg1/clients')
    assert 'alpha' in awg0.text and 'beta' not in awg0.text
    assert 'beta' in awg1.text and 'alpha' not in awg1.text
    assert 'action="/servers/awg1/clients"' in awg1.text
    assert 'href="/servers/awg1/clients/beta"' in awg1.text
    assert 'name="csrf"' in awg1.text
    settings=c.get('/servers/awg1/settings')
    assert 'action="/servers/awg1/settings"' in settings.text
    assert '10.77.20.0/24' in settings.text and '51821' in settings.text
    assert 'client-search' not in settings.text
    assert 'name="server-picker"' not in root.text
    assert 'id="server-picker"' not in root.text
    assert root.text.count('class="instance-nav-link')==2
    assert 'href="/servers/awg1/overview"' in root.text
    assert 'href="/#clients"' not in root.text
    assert c.get('/servers/awg2/clients').status_code==404
    assert c.get('/servers/awg1/invalid').status_code==404


def test_explicit_url_prevents_cookie_cross_server_writes(ui):
    _,c,calls=ui
    c.cookies.set('awg31_server','awg0')
    clientpage=c.get('/servers/awg1/clients')
    res=c.post('/servers/awg1/clients',data={'csrf':token(clientpage),'name':'router'},follow_redirects=False)
    assert res.status_code==303
    assert res.headers['location']=='/servers/awg1/clients/router'
    assert ('add',{'name':'router','comment':'','expires_at':'','traffic_limit_bytes':0,
                   'routed_subnets':'','i_enabled':'0','i1':'','i2':'','i3':'','i4':'','i5':'',
                   'interface':'awg1'}) in calls
    assert c.get('/servers/awg1/api/traffic').status_code==200
    assert ('list',{'interface':'awg1'}) in calls
    assert c.post('/servers/awg1/settings',data={'csrf':token(c.get('/servers/awg1/settings')),
                  'port':'51822','endpoint':'new.example'},follow_redirects=False).status_code==303
    assert any(op=='settings' and d['interface']=='awg1' and d['port']=='51822' for op,d in calls)
    assert not any(op=='settings' and d['interface']=='awg0' for op,d in calls)
    assert c.get('/servers/awg1/clients/beta').status_code==200
    assert 'src="/servers/awg1/clients/beta/qr?mode=conf"' in c.get('/servers/awg1/clients/beta').text
    assert c.post('/servers/awg1/clients/beta/delete',data={'csrf':token(clientpage)},follow_redirects=False).headers['location']=='/servers/awg1/clients'


def test_backup_selection_delete_schedule_and_csrf(ui):
    _,c,calls=ui
    page=c.get('/maintenance?tab=backups')
    assert 'action="/maintenance/backup/delete"' in page.text
    assert 'action="/maintenance/backup/policy"' in page.text
    assert 'name="retention_days"' in page.text and 'value="21"' in page.text
    assert 'value="daily" selected' in page.text
    restore=c.get('/maintenance?tab=restore')
    assert restore.text.count('name="name"')==2 # one dropdown for verify, one for restore
    assert 'name="confirmation"' in restore.text
    assert restore.text.count('<option value="awg31-')==4
    assert c.post('/maintenance/backup/delete',data={'csrf':'bad','name':'some'}).status_code==403
    good=token(page)
    archive='awg31-20261112T030000Z-0123456789.tar.gz'
    assert c.post('/maintenance/backup/delete',data={'csrf':good,'name':'../bad'}).status_code==400
    deletion=c.post('/maintenance/backup/delete',data={'csrf':good,'name':archive},follow_redirects=False)
    assert deletion.status_code==303 and ('backup-delete',{'name':archive}) in calls
    policy_data={'csrf':good,'frequency':'weekly','hour':'4','minute':'30','weekday':'2','retention_days':'90','max_copies':'8'}
    assert c.post('/maintenance/backup/policy',data=policy_data,follow_redirects=False).status_code==303
    assert ('backup-policy-set',{k:v for k,v in policy_data.items() if k!='csrf'}) in calls
    assert c.post('/maintenance/restore',data={'csrf':token(restore),'name':archive,'confirmation':'BAD'}).status_code==400
    restored=c.post('/maintenance/restore',data={'csrf':token(restore),'name':archive,'confirmation':'ВОССТАНОВИТЬ'},follow_redirects=False)
    assert restored.status_code==202
    assert ('backup-restore',{'name':archive}) in calls
    verified=c.post('/maintenance/backup/check',data={'csrf':token(restore),'name':archive})
    assert verified.status_code==200 and 'Целостность архива' in verified.text


def test_admin_policy_and_safe_pruning(tmp_path,monkeypatch):
    spec=importlib.util.spec_from_file_location('admin080',ROOT/'src/awg31admin.py')
    admin=importlib.util.module_from_spec(spec);spec.loader.exec_module(admin)
    monkeypatch.setenv('AWG31_BACKUP_DIR',str(tmp_path/'backups'))
    monkeypatch.setenv('AWG31_BACKUP_POLICY',str(tmp_path/'policy.json'))
    monkeypatch.setenv('AWG31_BACKUP_TIMER',str(tmp_path/'awg31-backup.timer'))
    monkeypatch.setenv('AWG31_AUDIT',str(tmp_path/'audit.jsonl'))
    before={'frequency':'weekly','hour':'3','minute':'15','weekday':'1','retention_days':'7','max_copies':'2'}
    assert admin.save_backup_policy(before,apply=False)['ok']
    assert admin.backup_policy()=={**before,'hour':3,'minute':15,'weekday':1,'retention_days':7,'max_copies':2}
    assert 'Tue *-*-* 03:15:00 UTC' in (tmp_path/'awg31-backup.timer').read_text()
    assert (tmp_path/'policy.json').stat().st_mode & 0o777 == 0o600
    for bad in [{**before,'frequency':'daily\n[Service]'}, {**before,'max_copies':'1000'}, {**before,'retention_days':'0'}, {**before,'hour':'$(rm -rf /)'}]:
        with pytest.raises(ValueError):admin.save_backup_policy(bad,apply=False)
    backup_dir=tmp_path/'backups';backup_dir.mkdir()
    for day in (1,3,5,10):
        timestamp=(datetime(2026,11,13,tzinfo=timezone.utc)-timedelta(days=day)).strftime('%Y%m%dT%H%M%SZ')
        (backup_dir/f'awg31-{timestamp}-0123456789.tar.gz').write_bytes(b'backup')
    (backup_dir/'keep-other-data.txt').write_text('do not remove')
    report=admin.prune_backups(now=datetime(2026,11,13,tzinfo=timezone.utc))
    assert len(report['removed'])==2
    assert len(admin.list_backups()['backups'])==2
    assert (backup_dir/'keep-other-data.txt').read_text()=='do not remove'
    assert admin.delete_backup({'name':admin.list_backups()['backups'][0]['name']})['ok']
    with pytest.raises(ValueError): admin.delete_backup({'name':'../../etc/shadow'})
    policy_off={**before,'frequency':'off'}
    assert admin.save_backup_policy(policy_off,apply=False)['ok']
    assert not (tmp_path/'awg31-backup.timer').exists()
    assert admin.backup_policy()['frequency']=='off'


def test_scheduled_backup_does_not_prune_on_failed_creation(tmp_path,monkeypatch):
    spec=importlib.util.spec_from_file_location('admin080fail',ROOT/'src/awg31admin.py')
    admin=importlib.util.module_from_spec(spec);spec.loader.exec_module(admin)
    monkeypatch.setenv('AWG31_BACKUP_DIR',str(tmp_path/'archives'))
    monkeypatch.setenv('AWG31_BACKUP_POLICY',str(tmp_path/'policy.json'))
    monkeypatch.setenv('AWG31_BACKUP_TIMER',str(tmp_path/'timer'))
    monkeypatch.setenv('AWG31_AUDIT',str(tmp_path/'audit'))
    policy={'frequency':'daily','hour':3,'minute':0,'weekday':0,'retention_days':1,'max_copies':1}
    admin.save_backup_policy(policy,apply=False)
    path=admin.backup_dir();path.mkdir(parents=True)
    old=path/'awg31-20250101T030000Z-0123456789.tar.gz';old.write_bytes(b'existing backup')
    def fail(*args,**kwargs): raise RuntimeError('SQLite database busy')
    monkeypatch.setattr(admin,'create_backup',fail)
    with pytest.raises(RuntimeError,match='SQLite'):
        admin.scheduled_backup(object())
    assert old.read_bytes()==b'existing backup'


def test_policy_rolls_back_if_systemd_fails(tmp_path,monkeypatch):
    import subprocess
    spec=importlib.util.spec_from_file_location('admin080rollback',ROOT/'src/awg31admin.py')
    admin=importlib.util.module_from_spec(spec);spec.loader.exec_module(admin)
    monkeypatch.setenv('AWG31_BACKUP_POLICY',str(tmp_path/'policy.json'))
    monkeypatch.setenv('AWG31_BACKUP_TIMER',str(tmp_path/'awg31-backup.timer'))
    monkeypatch.setenv('AWG31_AUDIT',str(tmp_path/'audit.jsonl'))
    previous={'frequency':'off','hour':3,'minute':0,'weekday':0,'retention_days':30,'max_copies':20}
    admin.save_backup_policy(previous,apply=False)
    calls=[]
    def systemctl(args,**kwargs):
        calls.append(args)
        if args==['systemctl','restart','awg31-backup.timer']:
            raise subprocess.CalledProcessError(1,args)
        return subprocess.CompletedProcess(args,0)
    monkeypatch.setattr(admin.subprocess,'run',systemctl)
    new={**previous,'frequency':'daily','retention_days':10}
    with pytest.raises(subprocess.CalledProcessError):admin.save_backup_policy(new,apply=True)
    assert admin.backup_policy()==previous
    assert not (tmp_path/'awg31-backup.timer').exists()
    assert ['systemctl','daemon-reload'] in calls
