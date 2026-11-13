"""Root-only administrative operations. Never accepts user-specified filesystem paths."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone

VALID_BACKUP = re.compile(r'^awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz$')
VALID_AUDIT = {'login_success', 'login_failed', 'password_changed', 'client_added',
               'client_modified', 'client_deleted', 'client_enabled', 'client_disabled',
               'server_created', 'server_started', 'server_stopped', 'server_deleted',
               'server_settings_changed', 'profile_imported', 'backup_created',
               'backup_downloaded'}


def base_dir():
    return Path(os.environ.get('AWG31_ROOT', '/var/lib/awg31-panel'))


def backup_dir():
    return Path(os.environ.get('AWG31_BACKUP_DIR', '/var/backups/awg31-panel/full'))


def auth_file():
    return Path(os.environ.get('AWG31_AUTH', '/etc/awg31-panel/auth.json'))


def audit_file():
    return Path(os.environ.get('AWG31_AUDIT', '/var/log/awg31-panel/audit.jsonl'))


def audit(data):
    event = str(data.get('event',''))
    if event not in VALID_AUDIT: raise ValueError('Unknown audit event')
    target = str(data.get('target',''))
    if len(target)>120 or any(ord(x)<32 for x in target): raise ValueError('Invalid audit target')
    path = audit_file(); path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    record={'timestamp':datetime.now(timezone.utc).isoformat(),'event':event,'target':target}
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        os.write(fd,(json.dumps(record,ensure_ascii=False)+'\n').encode())
        os.fsync(fd)
    finally: os.close(fd)
    return {'ok':True}


def audit_recent():
    path=audit_file()
    if not path.exists(): return {'entries':[]}
    if path.stat().st_size>10*1024*1024: raise RuntimeError('Audit log is too large; rotate it')
    items=[]
    for line in path.read_text(encoding='utf-8').splitlines()[-100:]:
        try: items.append(json.loads(line))
        except ValueError: continue
    return {'entries':items}


def password_change(data):
    old=str(data.get('old_password',''))
    new=str(data.get('new_password',''))
    if len(new)<12 or len(new)>256: raise ValueError('Password must be 12-256 characters')
    file=auth_file(); auth=json.loads(file.read_text())
    check=hashlib.scrypt(old.encode(), salt=bytes.fromhex(auth['salt']),
                        n=2**14,r=8,p=1,dklen=32)
    if not secrets.compare_digest(check.hex(),auth['password_hash']):
        raise ValueError('Incorrect old password')
    salt=secrets.token_bytes(16)
    auth['salt']=salt.hex()
    auth['password_hash']=hashlib.scrypt(new.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32).hex()
    # Keep middleware signing key, but expire all previously issued sessions.
    auth['auth_version']=secrets.token_hex(16)
    fd,path=tempfile.mkstemp(prefix='.awg31-auth-',dir=file.parent)
    try:
        with os.fdopen(fd,'w') as fp:
            json.dump(auth,fp);fp.flush();os.fsync(fp.fileno())
            os.fchmod(fp.fileno(),0o640)
        original=file.stat()
        os.chown(path,original.st_uid,original.st_gid)
        os.replace(path,file)
    finally:
        Path(path).unlink(missing_ok=True)
    audit({'event':'password_changed'})
    return {'ok':True}


def _collect(manager):
    """Map safe archive paths to source files (never follow links in archives)."""
    sources={}
    if auth_file().is_file(): sources['auth/auth.json']=auth_file()
    for iface in manager.interfaces():
        sources[f'configs/{iface}.conf']=manager.conf_path(iface)
    return sources


def _safe_add(tf, name, data):
    if len(data)>20*1024*1024: raise ValueError('Oversized backup content')
    info=tarfile.TarInfo(name)
    info.size=len(data);info.mode=0o600;info.uid=info.gid=0;info.mtime=0
    tf.addfile(info,io.BytesIO(data))


def create_backup(manager):
    directory=backup_dir();directory.mkdir(parents=True,mode=0o700,exist_ok=True)
    previous=list_backups()['backups']
    if len(previous)>=30 or sum(item['size'] for item in previous)>250*1024*1024:
        raise ValueError('Backup retention limit reached; move old archives to secure storage')
    os.chmod(directory,0o700)
    name='awg31-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(5)+'.tar.gz'
    archive=directory/name
    fd=os.open(archive,os.O_WRONLY|os.O_EXCL|os.O_CREAT,0o600)
    os.close(fd)
    try:
        manifest={'format':'awg31-backup-v1','created_at':datetime.now(timezone.utc).isoformat(),
                  'files':{},'interfaces':manager.interfaces()}
        with tarfile.open(archive,'w:gz',format=tarfile.PAX_FORMAT) as tf:
            for name_in_archive,path in _collect(manager).items():
                if not path.is_file() or path.is_symlink(): raise ValueError('Invalid backup source')
                data=path.read_bytes()
                _safe_add(tf,name_in_archive,data)
                manifest['files'][name_in_archive]=hashlib.sha256(data).hexdigest()
            for iface in manager.interfaces():
                source=manager.db_path(iface)
                with tempfile.TemporaryDirectory(prefix='awg31-db-') as td:
                    temp=Path(td)/'backup.sqlite3'
                    with sqlite3.connect(source) as s, sqlite3.connect(temp) as d:
                        s.backup(d)
                    key=f'databases/{iface}.sqlite3';content=temp.read_bytes()
                    _safe_add(tf,key,content)
                    manifest['files'][key]=hashlib.sha256(content).hexdigest()
            _safe_add(tf,'manifest.json',json.dumps(manifest,sort_keys=True).encode())
        if archive.stat().st_size>20*1024*1024: raise ValueError('Archive exceeds 20 MiB limit')
    except Exception:
        archive.unlink(missing_ok=True);raise
    audit({'event':'backup_created','target':name})
    return {'ok':True,'name':name,'size':archive.stat().st_size}


def list_backups():
    directory=backup_dir()
    if not directory.exists(): return {'backups':[]}
    found=[]
    for p in directory.iterdir():
        if VALID_BACKUP.fullmatch(p.name) and p.is_file() and not p.is_symlink():
            found.append({'name':p.name,'size':p.stat().st_size})
    return {'backups':sorted(found,key=lambda x:x['name'],reverse=True)[:30]}


def export_backup(data):
    name=str(data.get('name',''))
    if not VALID_BACKUP.fullmatch(name): raise ValueError('Invalid backup name')
    path=backup_dir()/name
    if not path.is_file() or path.is_symlink(): raise ValueError('Backup not found')
    size=path.stat().st_size
    if size>20*1024*1024: raise ValueError('Backup too large for web download')
    audit({'event':'backup_downloaded','target':name})
    return {'name':name,'content':base64.b64encode(path.read_bytes()).decode()}


def diagnose(manager,iface):
    def command(args):
        try:
            cp=subprocess.run(args,capture_output=True,text=True,timeout=10,check=False)
            return {'ok':cp.returncode==0,'output':(cp.stdout or cp.stderr).strip()[:800]}
        except (OSError,subprocess.TimeoutExpired) as exc:
            return {'ok':False,'output':str(exc)[:300]}
    kernel=command(['uname','-r'])
    running=kernel['output'] if kernel['ok'] else ''
    return {'interface':iface,'kernel':kernel,
            'installed_module':command(['modinfo','-k',running,'-F','version','amneziawg']) if running else {'ok':False},
            'loaded_module':command(['cat','/sys/module/amneziawg/version']) if Path('/sys/module/amneziawg/version').exists() else {'ok':False,'output':'not loaded'},
            'dkms':command(['dkms','status','-m','amneziawg']),
            'device':command(['ip','-4','addr','show','dev',iface]),
            'forwarding':command(['sysctl','-n','net.ipv4.ip_forward']),
            'service':command(['systemctl','is-active',f'awg-quick@{iface}.service']),
            'secure_boot':command(['mokutil','--sb-state']),
            'panel':command(['systemctl','is-active','awg31-panel.service'])}
