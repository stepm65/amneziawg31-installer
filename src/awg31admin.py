"""Root-only administrative operations. Never accepts user-specified filesystem paths."""
import base64
import fcntl
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
from datetime import datetime, timezone, timedelta

VALID_BACKUP = re.compile(r'^awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz$')
VALID_AUDIT = {'login_success', 'login_failed', 'password_changed', 'client_added',
               'client_modified', 'client_deleted', 'client_enabled', 'client_disabled',
               'server_created', 'server_started', 'server_stopped', 'server_deleted',
               'server_settings_changed', 'profile_imported', 'backup_created',
               'backup_downloaded', 'backup_deleted', 'backup_policy_changed', 'backup_pruned'}


def base_dir():
    return Path(os.environ.get('AWG31_ROOT', '/var/lib/awg31-panel'))


def backup_dir():
    return Path(os.environ.get('AWG31_BACKUP_DIR', '/var/backups/awg31-panel/full'))


def auth_file():
    return Path(os.environ.get('AWG31_AUTH', '/etc/awg31-panel/auth.json'))


BACKUP_POLICY_DEFAULT = {'frequency': 'off', 'hour': 3, 'minute': 0, 'weekday': 0, 'retention_days': 30, 'max_copies': 20}


def policy_path():
    return Path(os.environ.get('AWG31_BACKUP_POLICY', '/etc/awg31-panel/backup-policy.json'))


def timer_path():
    return Path(os.environ.get('AWG31_BACKUP_TIMER', '/etc/systemd/system/awg31-backup.timer'))


def _policy_values(data):
    allowed = set(BACKUP_POLICY_DEFAULT)
    if set(data) != allowed: raise ValueError('Invalid backup policy fields')
    frequency = str(data['frequency'])
    if frequency not in ('off', 'daily', 'weekly'): raise ValueError('Invalid backup frequency')
    nums = {}
    for name, low, high in [('hour', 0, 23), ('minute', 0, 59), ('weekday', 0, 6),
                             ('retention_days', 1, 365), ('max_copies', 1, 30)]:
        value = data[name]
        if isinstance(value, bool) or not str(value).isdecimal(): raise ValueError(f'Invalid {name}')
        nums[name] = int(value)
        if not low <= nums[name] <= high: raise ValueError(f'Invalid {name}')
    return {'frequency': frequency, **nums}


def backup_policy():
    file = policy_path()
    if not file.exists(): return dict(BACKUP_POLICY_DEFAULT)
    if file.is_symlink(): raise ValueError('Invalid backup policy file')
    return _policy_values(json.loads(file.read_text()))


def _atomic_private_file(path, data, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and path.is_symlink(): raise ValueError('Refusing symlink')
    fd, name = tempfile.mkstemp(prefix='.awg31-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as fp:
            fp.write(data);fp.flush();os.fsync(fp.fileno());os.fchmod(fp.fileno(), mode)
        os.replace(name, path)
    finally: Path(name).unlink(missing_ok=True)


def _timer_unit(policy):
    freq = policy['frequency']
    if freq == 'off': return None
    timepart = f"{policy['hour']:02}:{policy['minute']:02}:00 UTC"
    day = '' if freq == 'daily' else ('Mon','Tue','Wed','Thu','Fri','Sat','Sun')[policy['weekday']] + ' '
    return ('[Unit]\nDescription=Automatic AWG31 VPN backup (contains secrets)\n'
            '[Timer]\nOnCalendar=' + day + '*-*-* ' + timepart + '\nPersistent=true\n'
            'AccuracySec=1min\nUnit=awg31-backup.service\n'
            '[Install]\nWantedBy=timers.target\n')


def save_backup_policy(data, *, apply=True):
    policy = _policy_values(data)
    previous = backup_policy()
    policy_file = policy_path()
    timer_file = timer_path()
    old_policy = policy_file.read_text() if policy_file.exists() else None
    old_timer = timer_file.read_text() if timer_file.exists() else None
    unit = _timer_unit(policy)
    try:
        _atomic_private_file(policy_file, json.dumps(policy, sort_keys=True) + '\n')
        if unit is not None: _atomic_private_file(timer_file, unit, mode=0o644)
        else:
            # Stop/disable before removing the unit file: systemctl may reject
            # disable after daemon-reload has forgotten a deleted unit.
            if apply:
                subprocess.run(['systemctl','disable','--now','awg31-backup.timer'], check=False, timeout=30)
            if timer_file.exists(): timer_file.unlink()
        if apply:
            subprocess.run(['systemctl','daemon-reload'], check=True, timeout=30)
            if unit is not None:
                subprocess.run(['systemctl','enable','--now','awg31-backup.timer'], check=True, timeout=30)
            if unit is not None:
                subprocess.run(['systemctl','restart','awg31-backup.timer'], check=True, timeout=30)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        if old_policy is None: policy_file.unlink(missing_ok=True)
        else: _atomic_private_file(policy_file, old_policy)
        if old_timer is None: timer_file.unlink(missing_ok=True)
        else: _atomic_private_file(timer_file, old_timer, mode=0o644)
        if apply:
            subprocess.run(['systemctl','daemon-reload'],check=False,timeout=15)
            if old_timer is None: subprocess.run(['systemctl','disable','--now','awg31-backup.timer'],check=False,timeout=15)
            else: subprocess.run(['systemctl','enable','--now','awg31-backup.timer'],check=False,timeout=15)
        raise
    audit({'event':'backup_policy_changed','target':f"{policy['frequency']} / {policy['retention_days']}d / {policy['max_copies']}"})
    return {'ok': True, 'policy': policy, 'previous': previous}


def delete_backup(data):
    name = str(data.get('name', ''))
    if not VALID_BACKUP.fullmatch(name): raise ValueError('Invalid backup name')
    directory = backup_dir()
    archive = directory / name
    if not archive.is_file() or archive.is_symlink(): raise ValueError('Backup not found')
    archive.unlink()
    audit({'event':'backup_deleted', 'target': name})
    return {'ok': True, 'deleted': name}


def prune_backups(*, now=None):
    policy = backup_policy()
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=policy['retention_days'])
    directory = backup_dir()
    if not directory.exists(): return {'removed': []}
    archives = [p for p in directory.iterdir() if VALID_BACKUP.fullmatch(p.name) and p.is_file() and not p.is_symlink()]
    archives.sort(key=lambda p:p.name, reverse=True)
    remove = []
    for index, file in enumerate(archives):
        try: stamp = datetime.strptime(file.name[6:22], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
        except ValueError: continue
        if stamp < cutoff or index >= policy['max_copies']:
            file.unlink(); remove.append(file.name)
    if remove: audit({'event':'backup_pruned', 'target':f'{len(remove)} archive(s)'})
    return {'removed': remove}


def scheduled_backup(manager):
    lock_path = backup_dir().parent / '.backup-schedule.lock'
    lock_path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    with open(lock_path,'a+') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        if backup_policy()['frequency'] == 'off': return {'ok':True, 'skipped':True}
        # Never remove an existing backup until the replacement is complete.
        result = create_backup(manager, enforce_limit=False)
        prune_backups()
        return result


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


def create_backup(manager, *, enforce_limit=True):
    directory=backup_dir();directory.mkdir(parents=True,mode=0o700,exist_ok=True)
    previous=list_backups()['backups']
    if enforce_limit and (len(previous)>=30 or sum(item['size'] for item in previous)>250*1024*1024):
        raise ValueError('Backup limit reached; remove old archives or adjust retention')
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
            found.append({'name':p.name,'size':p.stat().st_size,'created_at':p.name[6:22]})
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
