"""Root-only administrative operations. Never accepts user-specified filesystem paths."""
import base64
import fcntl
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import pwd
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timezone, timedelta

VALID_BACKUP = re.compile(r'^awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz(?:\.gpg)?$')
VALID_AUDIT = {'login_success', 'login_failed', 'password_changed', 'client_added',
               'client_modified', 'client_deleted', 'client_enabled', 'client_disabled',
               'server_created', 'server_started', 'server_stopped', 'server_restarted', 'server_deleted', 'logout',
               'server_settings_changed', 'profile_imported', 'backup_created',
               'backup_downloaded', 'backup_deleted', 'backup_policy_changed', 'backup_pruned',
               'backup_failed', 'client_config_sent', 'totp_enabled', 'totp_disabled',
               'telegram_changed', 'backup_encryption_changed', 'backup_uploaded', 'backup_upload_failed',
               'backup_remote_changed', 'logging_changed', 'debug_changed', 'support_report',
               'client_rekeyed', 'client_invite_created', 'client_invite_used', 'totp_recovery_used',
               'totp_recovery_new', 'clients_exported', 'panel_update_started', 'panel_updated',
               'panel_update_failed', 'panel_rolled_back', 'server_rotated', 'server_rotate_failed',
               'mask_profile_applied', 'subscription_created', 'subscription_revoked', 'once_link_created', 'once_link_revoked', 'once_link_used', 'packet_probe',
               'client_moved', 'server_silent', 'server_back',
               'owner_created', 'owner_changed', 'owner_deleted', 'owner_blocked', 'owner_unblocked', 'clients_imported',
               'snapshot_deleted', 'account_created', 'account_changed', 'account_deleted', 'session_ended'}
ACCOUNT_RE=re.compile(r'^[a-z][a-z0-9_.-]{1,31}$')
ROLES=('admin','viewer')
MAX_ACCOUNTS=20


def _host_uplink():
    """Read lowest-metric IPv4 default route for WAN accounting."""
    try:
        candidates=[]
        for row in Path('/proc/net/route').read_text().splitlines()[1:]:
            cols=row.split()
            if len(cols)>=8 and cols[1]=='00000000' and int(cols[3],16)&1:
                iface=cols[0]
                if re.fullmatch(r'[a-zA-Z0-9_.:-]{1,32}',iface) and not iface.startswith(('awg','lo','wg','tun')):
                    candidates.append((int(cols[6]),iface))
        return min(candidates)[1] if candidates else None
    except (OSError,ValueError,IndexError):return None


def _host_snapshot():
    """Host snapshots contain counters only, no peer data or credentials."""
    state={'measured_at':int(datetime.now(timezone.utc).timestamp()),
           'cpu_total':None,'cpu_idle':None,'mem_total':None,'mem_available':None,
           'swap_total':None,'swap_free':None,'disk_total':None,'disk_free':None,
           'uplink':None,'wan_rx':None,'wan_tx':None,'tcp':None,'udp':None}
    try:
        cpu=[int(n) for n in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
        state['cpu_total']=sum(cpu);state['cpu_idle']=cpu[3]+cpu[4]
    except (OSError,ValueError,IndexError):pass
    try:
        memo={}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key,_,raw=line.partition(':')
            if key in ('MemTotal','MemAvailable','SwapTotal','SwapFree'):
                memo[key]=int(raw.strip().split()[0])*1024
        for dest,key in (('mem_total','MemTotal'),('mem_available','MemAvailable'),
                         ('swap_total','SwapTotal'),('swap_free','SwapFree')):
            state[dest]=memo.get(key)
    except (OSError,ValueError,IndexError):pass
    try:
        fs=os.statvfs('/');state['disk_total']=fs.f_blocks*fs.f_frsize;state['disk_free']=fs.f_bavail*fs.f_frsize
    except OSError:pass
    name=_host_uplink()
    if name:
        try:
            stats=Path('/sys/class/net')/name/'statistics'
            state['wan_rx']=int((stats/'rx_bytes').read_text());state['wan_tx']=int((stats/'tx_bytes').read_text())
            state['uplink']=name
        except (OSError,ValueError):pass
    for kind in ('tcp','tcp6','udp','udp6'):
        try:
            rows=(Path('/proc/net')/kind).read_text().splitlines()[1:]
            count=sum(int(row.split()[3]=='01') for row in rows if len(row.split())>=4) if kind.startswith('tcp') else len(rows)
            name='tcp' if kind.startswith('tcp') else 'udp'
            state[name]=(state[name] or 0)+count
        except OSError:pass
    return state


_HOST_COLUMNS=('measured_at','cpu_total','cpu_idle','mem_total','mem_available',
               'swap_total','swap_free','disk_total','disk_free','uplink','wan_rx','wan_tx','tcp','udp')


_HOST_SCHEMA="""CREATE TABLE IF NOT EXISTS host_samples (
           measured_at INTEGER PRIMARY KEY, cpu_total INTEGER, cpu_idle INTEGER,
           mem_total INTEGER, mem_available INTEGER, swap_total INTEGER, swap_free INTEGER,
           disk_total INTEGER, disk_free INTEGER, uplink TEXT, wan_rx INTEGER, wan_tx INTEGER,
           tcp INTEGER, udp INTEGER)"""


def host_db():
    """Host counters live in their own file: awg0 may be deleted or restored."""
    return base_dir()/'host.sqlite3'


def _open_host_db():
    path=host_db()
    fresh=not path.exists()
    path.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(path,timeout=20)
    if fresh: os.chmod(path,0o600)
    con.execute(_HOST_SCHEMA)
    if fresh:
        # One-time move of history that older installations kept inside the awg0 database.
        legacy=base_dir()/'state.sqlite3'
        try:
            if legacy.is_file():
                with sqlite3.connect(f'file:{legacy}?mode=ro',uri=True,timeout=5) as old:
                    if old.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_samples'").fetchone():
                        rows=old.execute('SELECT '+','.join(_HOST_COLUMNS)+' FROM host_samples').fetchall()
                        con.executemany('INSERT OR IGNORE INTO host_samples VALUES('+','.join('?' for _ in _HOST_COLUMNS)+')',rows)
        except sqlite3.Error:
            pass  # History is a convenience; never block sampling on it.
        con.commit()
    return con


def sample_host_metrics():
    """Invoked by the root sampler once a minute, with or without any AWG server."""
    snap=_host_snapshot()
    con=_open_host_db()
    try:
        con.execute('INSERT OR REPLACE INTO host_samples VALUES('+','.join('?' for _ in _HOST_COLUMNS)+')',
                    [snap[k] for k in _HOST_COLUMNS])
        con.execute('DELETE FROM host_samples WHERE measured_at < ?', (snap['measured_at']-32*86400,))
        con.commit()
    finally: con.close()
    return {'ok':True,'measured_at':snap['measured_at']}


def host_metrics_history(payload):
    duration={'5m':300,'15m':900,'1h':3600}.get(str(payload.get('window','15m')))
    if not duration:raise ValueError('Invalid host history window')
    if not host_db().exists() and not (base_dir()/'state.sqlite3').exists():return {'points':[]}
    con=_open_host_db()
    with con:
        con.row_factory=sqlite3.Row
        now=int(datetime.now(timezone.utc).timestamp())
        rows=[dict(row) for row in con.execute('SELECT * FROM host_samples WHERE measured_at >= ? ORDER BY measured_at',
                                               (now-duration-120,))]
    con.close()
    def pct(used,total):
        return round(min(100,max(0,100*used/total)),2) if total and used is not None else None
    points=[]
    previous=None
    for row in rows:
        t=row['measured_at']
        if t<now-duration:previous=row;continue
        cpu=wan_rx=wan_tx=None
        if previous:
            delta=t-previous['measured_at']
            total=(row['cpu_total']-previous['cpu_total'] if row['cpu_total'] is not None and previous['cpu_total'] is not None else 0)
            idle=(row['cpu_idle']-previous['cpu_idle'] if row['cpu_idle'] is not None and previous['cpu_idle'] is not None else 0)
            if total>0 and 0<=idle<=total:cpu=pct(total-idle,total)
            if delta>0 and row['uplink']==previous['uplink'] and row['uplink']:
                if all(v is not None for v in (row['wan_rx'],previous['wan_rx'],row['wan_tx'],previous['wan_tx'])):
                    dr=row['wan_rx']-previous['wan_rx'];dt=row['wan_tx']-previous['wan_tx']
                    if dr>=0 and dt>=0:wan_rx=round(dr/delta,2);wan_tx=round(dt/delta,2)
        points.append({'ts':t,'rx':wan_rx,'tx':wan_tx,'cpu':cpu,
                       'ram':pct(row['mem_total']-row['mem_available'],row['mem_total']) if row['mem_total'] and row['mem_available'] is not None else None,
                       'swap':pct(row['swap_total']-row['swap_free'],row['swap_total']) if row['swap_total'] and row['swap_free'] is not None else (0 if row['swap_total']==0 else None),
                       'disk':pct(row['disk_total']-row['disk_free'],row['disk_total']) if row['disk_total'] and row['disk_free'] is not None else None,
                       'sockets':(row['tcp']+row['udp']) if row['tcp'] is not None and row['udp'] is not None else None})
        previous=row
    return {'window':str(payload.get('window','15m')),'points':points}


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
    # Public addresses (sign-in attempts) are kept as the panel's masking setting says.
    target = mask_text(target)
    path = audit_file(); path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    record={'timestamp':datetime.now(timezone.utc).isoformat(),'event':event,'target':target}
    who=actor()
    if who: record['actor']=who
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        os.write(fd,(json.dumps(record,ensure_ascii=False)+'\n').encode())
        os.fsync(fd)
    finally: os.close(fd)
    return {'ok':True}


def audit_recent():
    """The last 100 entries, oldest first. The bot asks every minute: only the end of the file is read."""
    path=audit_file()
    if not path.is_file() or path.is_symlink(): return {'entries':[]}
    with open(path,'rb') as stream:
        stream.seek(max(0,path.stat().st_size-256*1024))
        tail=stream.read().decode('utf-8',errors='replace').splitlines()
    items=[]
    for line in tail[-101:]:
        try: item=json.loads(line)
        except ValueError: continue                  # also the line cut by the seek
        if isinstance(item,dict): items.append(item)
    return {'entries':items[-100:]}


def actor():
    """Who asked: the panel account (handed over by awg31mgr), the bot, or root at the console."""
    caller=os.environ.get('AWG31_CALLER','') or os.environ.get('SUDO_USER','')
    if caller=='awgpanel':
        name=os.environ.get('AWG31_ACTOR','')
        return name if ACCOUNT_RE.fullmatch(name) else ''
    if caller=='awgbot': return 'telegram'
    if os.environ.get('SUDO_USER'): return 'console'
    return ''


def primary_name(auth):
    name=str(auth.get('name') or 'admin')
    return name if ACCOUNT_RE.fullmatch(name) else 'admin'


def account_record(auth, name=''):
    """The credentials of one account: the main one lives at the top of auth.json, the others under 'users'."""
    name=str(name or '')
    if not name or name==primary_name(auth): return auth
    users=auth.get('users') if isinstance(auth.get('users'),dict) else {}
    record=users.get(name)
    if not ACCOUNT_RE.fullmatch(name) or not isinstance(record,dict): raise ValueError('No such account')
    return record


def account_role(auth, name=''):
    record=account_record(auth,name)
    return 'admin' if record is auth else (record.get('role') if record.get('role') in ROLES else 'viewer')


def _hash_password(record, new):
    salt=secrets.token_bytes(16)
    record['salt']=salt.hex()
    record['password_hash']=hashlib.scrypt(new.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32).hex()


def _require_admin_password(auth, data):
    """Account changes: the acting account must be an administrator and type its own password."""
    who=str(data.get('actor',''))
    try: record=account_record(auth,who)
    except ValueError: raise ValueError('Incorrect password') from None
    if account_role(auth,who)!='admin' or not _password_ok(record,data.get('password','')): raise ValueError('Incorrect password')
    return primary_name(auth) if record is auth else who


def account_set(data):
    """Create an account, or change its role or password. The main account always stays an administrator."""
    file=auth_file(); auth=json.loads(file.read_text())
    who=_require_admin_password(auth,data)
    name=str(data.get('name',''))
    if not ACCOUNT_RE.fullmatch(name): raise ValueError('Account name: 2-32 characters a-z, 0-9, . _ -, starting with a letter')
    users=auth.setdefault('users',{})
    if not isinstance(users,dict): raise ValueError('auth.json is damaged')
    role=str(data.get('role',''))
    new=str(data.get('new_password',''))
    if role and role not in ROLES: raise ValueError('Role: admin or viewer')
    if new: _check_new_password(new)
    if data.get('create'):
        if name==primary_name(auth) or name in users: raise ValueError('The account already exists')
        if len(users)>=MAX_ACCOUNTS-1: raise ValueError('At most 20 accounts')
        if not new: raise ValueError('Password must be 12-256 characters')
        record={'role':role or 'viewer','created':datetime.now(timezone.utc).isoformat(timespec='seconds')}
        _hash_password(record,new); users[name]=record
        _save_auth(auth,file,rotate=False)
        audit({'event':'account_created','target':f'{name} ({record["role"]})'})
        return {'ok':True,'name':name,'ended':False}
    record=account_record(auth,name)
    if record is auth and role and role!='admin': raise ValueError('The main account is always an administrator')
    if name==who and role and role!='admin': raise ValueError('You cannot take the administrator role from yourself')
    changes=[]
    if role and record is not auth and role!=record.get('role'): record['role']=role; changes.append('role '+role)
    if new: _hash_password(record,new); changes.append('password')
    if not changes: return {'ok':True,'name':name,'ended':False}
    _save_auth(auth,file,rotate=False)
    audit({'event':'account_changed','target':f'{name}: '+', '.join(changes)})
    return {'ok':True,'name':name,'ended':True}            # the panel ends that account's sessions


def account_delete(data):
    file=auth_file(); auth=json.loads(file.read_text())
    who=_require_admin_password(auth,data)
    name=str(data.get('name',''))
    if name==primary_name(auth): raise ValueError('The main account cannot be deleted')
    if name==who: raise ValueError('You cannot delete yourself')
    users=auth.get('users') if isinstance(auth.get('users'),dict) else {}
    if name not in users: raise ValueError('No such account')
    users.pop(name)
    _save_auth(auth,file,rotate=False)
    audit({'event':'account_deleted','target':name})
    return {'ok':True,'name':name}


SESSION_ID=re.compile(r'^[0-9a-f]{16}$')


def sessions_file():
    return auth_file().with_name('sessions.json')


def session_save(data):
    """The panel keeps its sign-ins in memory and hands them here to survive a restart: only hashes of the
    cookies' session numbers, never the numbers themselves."""
    items=data.get('sessions')
    if not isinstance(items,list) or len(items)>200: raise ValueError('Invalid sessions')
    clean=[]
    for item in items:
        if not isinstance(item,dict): raise ValueError('Invalid sessions')
        entry={'hash':str(item.get('hash','')),'account':str(item.get('account','')),'addr':str(item.get('addr',''))[:64],
               'agent':str(item.get('agent',''))[:160],'created':int(item.get('created',0) or 0),'seen':int(item.get('seen',0) or 0)}
        if not re.fullmatch(r'[0-9a-f]{64}',entry['hash']) or not ACCOUNT_RE.fullmatch(entry['account']):
            raise ValueError('Invalid sessions')
        if any(ord(x)<32 for x in entry['addr']+entry['agent']): raise ValueError('Invalid sessions')
        clean.append(entry)
    file=sessions_file()
    fd,path=tempfile.mkstemp(prefix='.awg31-sessions-',dir=file.parent)
    try:
        with os.fdopen(fd,'w') as fp:
            json.dump({'sessions':clean},fp); fp.flush(); os.fsync(fp.fileno()); os.fchmod(fp.fileno(),0o640)
        original=auth_file().stat()
        os.chown(path,original.st_uid,original.st_gid)
        os.replace(path,file)
    finally:
        Path(path).unlink(missing_ok=True)
    if data.get('ended'):
        what=str(data['ended'])[:120]
        if not any(ord(x)<32 for x in what): audit({'event':'session_ended','target':what})
    return {'ok':True,'count':len(clean)}


def session_revoke():
    """Sign out everywhere: cookies issued before this moment stop working.

    The panel is stateless (signed cookies), so logging out has to change the
    version every cookie is checked against.
    """
    file=auth_file(); auth=json.loads(file.read_text())
    _save_auth(auth,file)
    try: sessions_file().unlink(missing_ok=True)
    except OSError: pass
    audit({'event':'logout','target':'all sessions'})
    return {'ok':True}


def _store_password(auth, new, file):
    """Write a new scrypt hash atomically and expire every issued session."""
    salt=secrets.token_bytes(16)
    auth['salt']=salt.hex()
    auth['password_hash']=hashlib.scrypt(new.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32).hex()
    _save_auth(auth,file)


def _save_auth(auth, file, rotate=True):
    # Keep middleware signing key; rotate=True expires every issued session (sign out everywhere, console reset).
    if rotate or not auth.get('auth_version'): auth['auth_version']=secrets.token_hex(16)
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


def _password_ok(auth, password):
    check=hashlib.scrypt(str(password).encode(), salt=bytes.fromhex(auth['salt']), n=2**14,r=8,p=1,dklen=32)
    return secrets.compare_digest(check.hex(),auth['password_hash'])


def totp_counter_for(secret, code, now=None):
    """RFC 6238 (SHA-1, 30 s, 6 digits). Returns the matching time step or None; one step of clock drift is allowed."""
    import hmac, struct, time
    code=str(code).strip().replace(' ','')
    if not re.fullmatch(r'[0-9]{6}',code): return None
    key=base64.b32decode(secret,casefold=True)
    step=int((time.time() if now is None else now)//30)
    for counter in (step,step-1,step+1):
        digest=hmac.new(key,struct.pack('>Q',counter),hashlib.sha1).digest()
        offset=digest[-1]&15
        value=(struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000
        if secrets.compare_digest(f'{value:06d}',code): return counter
    return None


SERVICE_USERS={'awgpanel','awgbot'}


def from_service():
    """True when the request comes from the panel or the bot (through the control helper or sudo),
    False for an administrator at the root console. Neither caller can set these variables itself:
    the helper sets AWG31_CALLER from the kernel's peer credentials, sudo sets SUDO_USER."""
    return os.environ.get('AWG31_CALLER','') in SERVICE_USERS or os.environ.get('SUDO_USER','') in SERVICE_USERS


def require_panel_password(data):
    """Changes with a lasting effect ask for the panel password again when they come from the panel:
    a stolen session alone must not be enough to hand the server to somebody else's Telegram account
    or to switch off backup encryption. The root console is not asked."""
    if not from_service(): return
    try: auth=json.loads(auth_file().read_text())
    except (OSError,ValueError): raise ValueError('Cannot read the panel credentials') from None
    try: record=account_record(auth,str(os.environ.get('AWG31_ACTOR','') or ''))
    except ValueError: raise ValueError('Incorrect panel password') from None
    if record is not auth and record.get('role')!='admin': raise ValueError('Incorrect panel password')
    if not _password_ok(record,data.get('password','')): raise ValueError('Incorrect panel password')


RECOVERY_ALPHABET='abcdefghjkmnpqrstuvwxyz23456789'      # no 0/o, 1/l/i: read from paper without doubt
RECOVERY_COUNT=10


def _recovery_norm(code):
    return re.sub(r'[\s-]','',str(code)).lower()


def _recovery_hash(salt, code):
    return hashlib.sha256((salt+':'+_recovery_norm(code)).encode()).hexdigest()


def _recovery_issue(auth):
    """Ten one-time codes for a lost phone; only their salted hashes are stored."""
    codes=[]
    for _ in range(RECOVERY_COUNT):
        raw=''.join(secrets.choice(RECOVERY_ALPHABET) for _ in range(10))
        codes.append(raw[:5]+'-'+raw[5:])
    salt=secrets.token_hex(16)
    auth['totp_recovery_salt']=salt
    auth['totp_recovery']=[_recovery_hash(salt,code) for code in codes]
    return codes


def totp_recovery_new(data):
    """New recovery codes (the old ones stop working): the password and a current code."""
    file=auth_file(); root=json.loads(file.read_text()); auth=account_record(root,data.get('account',''))
    if not auth.get('totp_secret'): raise ValueError('Two-factor sign-in is off')
    if not _password_ok(auth,data.get('password','')): raise ValueError('Incorrect password')
    if totp_counter_for(auth['totp_secret'],data.get('code','')) is None: raise ValueError('Incorrect code')
    codes=_recovery_issue(auth)
    _save_auth(root,file,rotate=False)
    audit({'event':'totp_recovery_new','target':str(data.get('account','') or '')})
    return {'ok':True,'recovery_codes':codes}


def totp_recovery_use(data):
    """Sign-in with a recovery code instead of the app: the password too, and every code works once."""
    file=auth_file(); root=json.loads(file.read_text()); auth=account_record(root,data.get('account',''))
    if not auth.get('totp_secret') or not auth.get('totp_recovery'): raise ValueError('No recovery codes')
    if not _password_ok(auth,data.get('password','')): raise ValueError('Incorrect password')
    code=_recovery_norm(data.get('code',''))
    if not re.fullmatch(r'[a-z0-9]{10}',code): raise ValueError('Incorrect recovery code')
    wanted=_recovery_hash(auth.get('totp_recovery_salt',''),code)
    left=[x for x in auth['totp_recovery'] if not secrets.compare_digest(x,wanted)]
    if len(left)==len(auth['totp_recovery']): raise ValueError('Incorrect recovery code')
    auth['totp_recovery']=left
    _save_auth(root,file,rotate=False)
    audit({'event':'totp_recovery_used','target':(str(data.get('account') or '')+' ' if data.get('account') else '')+f'{len(left)} left'})
    return {'ok':True,'left':len(left)}


def totp_enable(data):
    """Turn on the second factor, or replace its key: the password, a code from the new key and,
    when a key is already set, a code from the current one."""
    secret=str(data.get('secret','')).strip().upper()
    if not re.fullmatch(r'[A-Z2-7]{32}',secret): raise ValueError('Invalid TOTP secret')
    file=auth_file(); root=json.loads(file.read_text()); auth=account_record(root,data.get('account',''))
    if not _password_ok(auth,data.get('password','')): raise ValueError('Incorrect password')
    if auth.get('totp_secret'):
        if secret==auth['totp_secret']: raise ValueError('The new key must differ from the current one')
        if totp_counter_for(auth['totp_secret'],data.get('current_code','')) is None:
            raise ValueError('Incorrect code of the current key')
    if totp_counter_for(secret,data.get('code','')) is None:
        raise ValueError('The code does not match: check the clock of the server and of the phone')
    auth['totp_secret']=secret
    codes=_recovery_issue(auth)            # a new key comes with new recovery codes
    _save_auth(root,file,rotate=False)     # the panel ends this account's sessions
    audit({'event':'totp_enabled','target':str(data.get('account','') or '')})
    return {'ok':True,'recovery_codes':codes}


def totp_disable(data):
    file=auth_file(); root=json.loads(file.read_text()); auth=account_record(root,data.get('account',''))
    if not auth.get('totp_secret'): return {'ok':True}
    if not _password_ok(auth,data.get('password','')): raise ValueError('Incorrect password')
    if totp_counter_for(auth['totp_secret'],data.get('code','')) is None: raise ValueError('Incorrect code')
    for key in ('totp_secret','totp_recovery','totp_recovery_salt'): auth.pop(key,None)
    _save_auth(root,file,rotate=False)
    audit({'event':'totp_disabled','target':str(data.get('account','') or '')})
    return {'ok':True}


def totp_reset():
    """Console recovery (`sudo awg31 totp-off`): root only, not in any sudoers list."""
    file=auth_file(); auth=json.loads(file.read_text())
    for key in ('totp_secret','totp_recovery','totp_recovery_salt'): auth.pop(key,None)
    _save_auth(auth,file)
    audit({'event':'totp_disabled','target':'console reset'})
    return {'ok':True}


# ---- Telegram bot settings shown and edited in the panel (never the token) ----
def bot_config_file():
    return Path(os.environ.get('AWG31_BOT_CONFIG','/etc/awg31-bot/telegram.json'))


NOTIFY_GROUPS=('server','clients','security','backups')
TELEGRAM_PENDING_TTL=900
# The same switches as in awg31bot.py (a test keeps the two lists equal).
TELEGRAM_EVENTS={
    'server_state':'server','module':'server','kernel':'server','panel':'server',
    'client_auto':'clients','client_expiring':'clients','client_quota':'clients',
    'login':'security','login_failed':'security','password':'security','owner_export':'security',
    'totp_recovery':'security','invite':'clients','owner_limit':'clients','update':'server','rotation':'server','blocking':'server',
    'backup_created':'backups','backup_failed':'backups','upload_failed':'backups',
    'cpu':'system','memory':'system','disk':'system',
}
TELEGRAM_THRESHOLDS={'cpu':90,'memory':90,'disk':90}
TELEGRAM_API='https://api.telegram.org'
TELEGRAM_PROBE=Path('/usr/local/libexec/awg31/telegram-probe.py')     # a root-owned copy of awg31bot.py
_CRON_ALIASES={'@hourly':'0 * * * *','@daily':'0 9 * * *','@weekly':'0 9 * * 1','@monthly':'0 9 1 * *',
               'daily':'0 9 * * *','weekly':'0 9 * * 1'}


def telegram_schedule(value):
    """'off' or a five-field crontab line (aliases accepted); returns the stored form."""
    text=re.sub(r'\s+',' ',str(value or 'off').strip())
    if text in ('','off'): return 'off'
    text=_CRON_ALIASES.get(text,text)
    parts=text.split(' ')
    if len(parts)!=5: raise ValueError('Report schedule: five crontab fields, e.g. 0 9 * * *')
    for part,(low,high) in zip(parts,((0,59),(0,23),(1,31),(1,12),(0,7))):
        for item in part.split(','):
            match=re.fullmatch(r'(\*|[0-9]{1,2}(?:-[0-9]{1,2})?)(?:/([0-9]{1,2}))?',item)
            if not match: raise ValueError(f'Report schedule: cannot read "{item}"')
            base,step=match.group(1),int(match.group(2) or 1)
            if base=='*': first,last=low,high
            elif '-' in base: first,last=(int(x) for x in base.split('-'))
            else: first=int(base); last=high if match.group(2) else first
            if step<1 or not low<=first<=last<=high:
                raise ValueError(f'Report schedule: "{item}" is out of range {low}-{high}')
    return text


def telegram_api_base(value):
    """Telegram or a self-hosted Bot API server. Plain http only for one on this host."""
    text=str(value or '').strip().rstrip('/')
    if not text or text==TELEGRAM_API: return TELEGRAM_API
    if len(text)>200 or not (re.fullmatch(r'https://[A-Za-z0-9.-]{1,120}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]+)*',text)
                             or re.fullmatch(r'http://(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]+)*',text)):
        raise ValueError('API server: https://host[:port][/path], or http:// only for 127.0.0.1')
    return text


def _telegram_pending_file():
    return bot_config_file().parent/'telegram-pending.json'


def _telegram_pending_cleanup():
    """Best-effort expiry; failed cleanup cannot make the token readable."""
    path=_telegram_pending_file()
    try:
        if path.is_symlink(): path.unlink(missing_ok=True)
        elif path.is_file():
            pending=json.loads(path.read_text())
            if time.time()-float(pending['created'])>=TELEGRAM_PENDING_TTL:
                path.unlink(missing_ok=True)
    except (OSError,ValueError,KeyError,TypeError): pass


def _telegram_pending_read(setup_id):
    """Consume a single, short-lived pending setup; no secret is returned."""
    path=_telegram_pending_file()
    if path.is_symlink() or not path.is_file(): raise ValueError('Telegram setup expired; enter the token again')
    try:
        pending=json.loads(path.read_text())
        if (not hmac.compare_digest(str(pending.get('id','')),setup_id)
                or time.time()-float(pending['created'])>=TELEGRAM_PENDING_TTL):
            raise ValueError('Telegram setup expired; enter the token again')
        token=str(pending.get('token',''))
        if not re.fullmatch(r'[0-9]{5,14}:[A-Za-z0-9_-]{30,60}',token):
            raise ValueError('Telegram setup expired; enter the token again')
        if not isinstance(pending.get('candidates'),dict):
            raise ValueError('Telegram setup expired; enter the token again')
        return pending
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
        raise ValueError('Telegram setup expired; enter the token again') from exc
    finally: path.unlink(missing_ok=True)


def _telegram_pending_write(pending):
    path=_telegram_pending_file()
    if path.is_symlink(): path.unlink(missing_ok=True)
    _atomic_private_file(path,json.dumps(pending)+'\n')
    os.chown(path,0,0)


def _id_list(value, limit):
    if isinstance(value,str): value=[x for x in re.split(r'[\s,;]+',value) if x]
    if not isinstance(value,list) or len(value)>limit: raise ValueError('Too many Telegram IDs')
    result=[]
    for item in value:
        if not re.fullmatch(r'[1-9][0-9]{2,14}',str(item)): raise ValueError('Telegram ID: digits only (a numeric user ID, not a @name)')
        if int(item) not in result: result.append(int(item))
    return result


def telegram_status():
    _telegram_pending_cleanup()
    file=bot_config_file()
    if not file.is_file(): return {'configured':False}
    config=json.loads(file.read_text())
    try:
        active=subprocess.run(['systemctl','is-active','awg31-bot.service'],capture_output=True,text=True,timeout=10).stdout.strip()
    except (OSError,subprocess.TimeoutExpired): active='unknown'
    try:
        enabled=subprocess.run(['systemctl','is-enabled','awg31-bot.service'],capture_output=True,text=True,timeout=10).stdout.strip()
    except (OSError,subprocess.TimeoutExpired): enabled='unknown'
    notify=config.get('notify') or {}
    groups={g:bool(notify.get(g,True)) for g in NOTIFY_GROUPS}
    chosen=config.get('events') if isinstance(config.get('events'),dict) else {}
    limits=config.get('thresholds') if isinstance(config.get('thresholds'),dict) else {}
    thresholds={}
    for key,default in TELEGRAM_THRESHOLDS.items():
        try: thresholds[key]=min(100,max(10,int(limits.get(key,default))))
        except (TypeError,ValueError): thresholds[key]=default
    try: digest=telegram_schedule(config.get('digest','off'))
    except ValueError: digest='off'
    return {'configured':True,'active':active,'enabled':enabled in ('enabled','enabled-runtime') or active=='active',
            'username':str(config.get('username','')),
            'admins':[int(x) for x in config.get('admins',[])],
            'viewers':[int(x) for x in config.get('viewers',[])],'lang':config.get('lang','ru'),
            'notify':groups,
            'events':{key:bool(chosen.get(key,groups.get(group,True))) for key,group in TELEGRAM_EVENTS.items()},
            'thresholds':thresholds,'digest':digest,
            'backup_file':bool(config.get('backup_file',groups['backups'])),
            'encrypted_backups':backup_key_file().is_file(),
            'api_base':str(config.get('api_base') or TELEGRAM_API)}


def _systemctl(*args):
    cp=subprocess.run(['systemctl',*args],capture_output=True,text=True,timeout=45,check=False)
    if cp.returncode:
        detail=(cp.stderr or cp.stdout).strip()
        # systemctl may include machine-readable command details, but never a token.
        raise ValueError('Telegram service command failed: '+detail[-200:])
    return cp.stdout


def _telegram_provision():
    """Create only the runtime account and directory; installers own units/sudoers."""
    unit=Path('/usr/local/libexec/awg31/scripts/awg31-bot.service')
    if not unit.is_file(): unit=Path('/etc/systemd/system/awg31-bot.service')
    if not unit.is_file(): raise ValueError('Telegram bot service template is not installed')
    cp=subprocess.run(['id','awgbot'],capture_output=True,timeout=10,check=False)
    if cp.returncode:
        cp=subprocess.run(['useradd','--system','--no-create-home','--home','/nonexistent','--shell',
                           '/usr/sbin/nologin','awgbot'],capture_output=True,text=True,timeout=30,check=False)
        if cp.returncode: raise ValueError('Could not create the Telegram service account')
    directory=bot_config_file().parent
    directory.mkdir(parents=True,mode=0o750,exist_ok=True)
    group=pwd.getpwnam('awgbot').pw_gid
    os.chown(directory,0,group);os.chmod(directory,0o750)
    if Path('/opt/awg31-panel/.venv').is_dir():
        # The bot imports the same pinned packages; its configuration stays root:awgbot.
        subprocess.run(['chmod','-R','o+rX','/opt/awg31-panel/.venv'],check=True,timeout=60)
    if shutil.which('getent') and subprocess.run(['getent','group','awg31ctl'],capture_output=True,check=False).returncode==0:
        subprocess.run(['usermod','-a','-G','awg31ctl','awgbot'],check=True,timeout=30)
    target=Path('/etc/systemd/system/awg31-bot.service')
    _atomic_private_file(target,unit.read_text(),mode=0o644)
    os.chown(target,0,0)
    _telegram_install_bot_sudoers()
    _systemctl('daemon-reload')
    _systemctl('enable','awg31-bot.service')
    return group


def _telegram_install_bot_sudoers():
    """Keep the helper's dynamically parsed allowlist in sync with bot access."""
    import shutil
    manager='/usr/local/sbin/awg31mgr'
    commands=('servers','server-start','server-stop','server-restart','list','add','download','enable',
              'disable','delete','client-policy','diagnostics','backup-create','backup-list',
              'backup-export-encrypted','audit','audit-list')
    target=Path('/etc/sudoers.d/awg31-bot')
    if not target.parent.is_dir() or not shutil.which('visudo'):
        raise ValueError('sudo with visudo is required to connect the Telegram bot')
    temporary=target.with_name('.awg31-bot-'+secrets.token_hex(8))
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o440)
    try:
        with os.fdopen(fd,'w') as fp:
            fp.write('awgbot ALL=(root) NOPASSWD: '+', '.join(f'{manager} {op}' for op in commands)+'\n')
            fp.flush();os.fsync(fp.fileno())
        cp=subprocess.run(['visudo','-cf',str(temporary)],capture_output=True,text=True,timeout=30,check=False)
        if cp.returncode: raise ValueError('Could not validate Telegram sudo permissions')
        os.chown(temporary,0,0);os.replace(temporary,target)
    finally:
        temporary.unlink(missing_ok=True)


def _restore_bot(pending, config, previous=None, ownership=None):
    """Best-effort rollback after discovery or service startup failed."""
    if config is not None:
        try:
            if previous is None:
                config.unlink(missing_ok=True)
            else:
                _atomic_private_file(config,previous,mode=0o640)
                if ownership is not None: os.chown(config,*ownership)
        except OSError:
            # Return the original startup error; remain conservative and do not
            # start a service whose secret could not be restored.
            return
    if pending:
        subprocess.run(['systemctl','start','awg31-bot.service'],capture_output=True,
                       timeout=30,check=False)


def _telegram_service(data):
    lang=str(data.get('lang','ru'))
    if lang not in ('ru','en'): raise ValueError('Language: ru or en')
    notify=data.get('notify',{})
    if not isinstance(notify,dict): raise ValueError('Invalid notification settings')
    return lang,{group:bool(notify.get(group,False)) for group in NOTIFY_GROUPS}


def telegram_connect(data):
    """Discovery stores a root-only pending setup; confirmation sends only its ID."""
    if data.get('cancel') is True:
        _telegram_pending_file().unlink(missing_ok=True)
        return {'ok':True,'cancelled':True}
    confirming=data.get('confirm') is True
    pending=None
    if not confirming:
        require_panel_password(data)
        try: _telegram_pending_file().unlink(missing_ok=True)
        except OSError as exc: raise ValueError('Could not reset the pending Telegram setup') from exc
    if confirming:
        setup_id=str(data.get('setup_id',''))
        if not re.fullmatch(r'[a-f0-9]{64}',setup_id): raise ValueError('Invalid Telegram setup ID')
        pending=_telegram_pending_read(setup_id)
        token=pending['token']
        username=str(pending['username'])
        lang=str(pending['lang'])
        notify=pending['notify']
        valid=pending['candidates']
    else:
        token=str(data.get('token','')).strip()
        if not re.fullmatch(r'[0-9]{5,14}:[A-Za-z0-9_-]{30,60}',token):
            raise ValueError('Invalid Telegram token format')
        lang,notify=_telegram_service(data)
    # Administrator IDs typed in the form (as in 3x-ui): the bot is connected at once.
    # Without them the bot looks for the private /start message and asks to confirm the sender.
    direct=[] if confirming else _id_list(str(data.get('admins','') or ''),20)
    if not direct and data.get('admins') not in (None,'') and not confirming:
        raise ValueError('Telegram ID: digits only (a numeric user ID, not a @name)')
    config=bot_config_file()
    existing=bool(config.is_file())
    if config.is_symlink(): raise ValueError('Invalid Telegram configuration file')
    # Keep the exact previous secret only in root memory until the new service
    # is known to be active; restore it if the replacement cannot start.
    previous=config.read_text() if existing else None
    ownership=None
    if existing:
        stat=config.stat(); ownership=(stat.st_uid,stat.st_gid)
    import sys
    python=Path(sys.executable)
    bot=TELEGRAM_PROBE
    if not bot.is_file():
        raise ValueError('Telegram setup helper is not installed; run scripts/upgrade-core.sh')
    if not confirming:
        cp=subprocess.run([str(python),str(bot),'check-token'],input=token+'\n',text=True,capture_output=True,timeout=40,check=False)
        if cp.returncode:
            raise ValueError('Telegram did not accept the token or api.telegram.org is unreachable')
        username=cp.stdout.strip()
        if not re.fullmatch(r'[A-Za-z0-9_]{1,32}',username): raise ValueError('Invalid response from Telegram')
    if existing and not confirming:
        _systemctl('stop','awg31-bot.service')
    try:
        if not confirming and not direct:
            cp=subprocess.run([str(python),str(bot),'list-candidates'],input=token+'\n',text=True,capture_output=True,timeout=40,check=False)
            if cp.returncode:
                raise ValueError('Could not check the private /start message; try again')
            candidates=json.loads(cp.stdout)
            if not isinstance(candidates,list): raise ValueError('Invalid Telegram administrator response')
            valid={}
            for item in candidates:
                if not isinstance(item,dict) or not re.fullmatch(r'[1-9][0-9]{2,14}',str(item.get('id',''))): continue
                valid[str(item['id'])]=str(item.get('label',''))[:100]
            if existing: _systemctl('start','awg31-bot.service')
            setup_id=secrets.token_hex(32)
            _telegram_pending_write({'id':setup_id,'token':token,'username':username,'lang':lang,
                                    'notify':notify,'candidates':valid,'created':time.time()})
            return {'ok':True,'pending':True,'setup_id':setup_id,'expires':TELEGRAM_PENDING_TTL,
                    'username':username,'candidates':[{'id':int(key),'label':value} for key,value in valid.items()]}
        if direct:
            admins=direct
        else:
            admin=str(data.get('admin_id',''))
            if admin not in valid:
                raise ValueError('Select the administrator who sent /start in a private chat')
            admins=[int(admin)]
        group=_telegram_provision()
        viewers=[]
        digest='off'
        if existing:
            old=json.loads(previous)
            viewers=[x for x in _id_list(old.get('viewers',[]),20) if x not in admins]
            try: digest=telegram_schedule(old.get('digest','off'))
            except ValueError: digest='off'
        settings={'token':token,'admins':admins,'viewers':viewers,'lang':lang,'notify':notify,'digest':digest,
                  'username':username}
        if existing:                    # a new token keeps the notification choices made in the panel
            for key in ('events','thresholds','backup_file','api_base'):
                if key in old: settings[key]=old[key]
        _atomic_private_file(config,json.dumps(settings,indent=1)+'\n',mode=0o640)
        os.chown(config,0,group)
        _systemctl('restart','awg31-bot.service')
        active=_systemctl('is-active','awg31-bot.service').strip()
        if active!='active': raise ValueError('Telegram bot did not start; check journalctl -u awg31-bot.service')
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,json.JSONDecodeError):
        # A failure after confirmation must erase the pending token.
        if confirming: _telegram_pending_file().unlink(missing_ok=True)
        _restore_bot(existing,config,previous,ownership)
        raise
    audit({'event':'telegram_changed','target':f'connected @{username}, '+('administrators entered' if direct else 'administrator confirmed')})
    return {'ok':True,'username':username}



def telegram_disconnect(data=None):
    require_panel_password(data or {})
    _systemctl('disable','--now','awg31-bot.service')
    config=bot_config_file()
    if config.is_symlink(): raise ValueError('Invalid Telegram configuration file')
    config.unlink(missing_ok=True)
    _telegram_pending_file().unlink(missing_ok=True)
    sudoers=Path('/etc/sudoers.d/awg31-bot')
    if sudoers.is_symlink(): raise ValueError('Invalid Telegram sudoers file')
    sudoers.unlink(missing_ok=True)
    state=Path('/var/lib/awg31-bot')
    if state.is_dir() and not state.is_symlink(): shutil.rmtree(state)
    audit({'event':'telegram_changed','target':'disconnected; token removed'})
    return {'ok':True}


def telegram_set(data):
    file=bot_config_file()
    if not file.is_file(): raise ValueError('The bot is not connected: connect it first')
    config=json.loads(file.read_text())
    admins=_id_list(data.get('admins',config.get('admins',[])),10)
    if not admins: raise ValueError('At least one administrator is required')
    viewers=[x for x in _id_list(data.get('viewers',config.get('viewers',[])),20) if x not in admins]
    # Who may control the bot is a lasting way into the server: changing it needs the panel password.
    if sorted(admins)!=sorted(int(x) for x in config.get('admins',[])) or \
       sorted(viewers)!=sorted(int(x) for x in config.get('viewers',[])):
        require_panel_password(data)
    lang=str(data.get('lang',config.get('lang','ru')))
    if lang not in ('ru','en'): raise ValueError('Language: ru or en')
    digest=telegram_schedule(data.get('digest',config.get('digest','off')))
    old_groups={g:bool((config.get('notify') or {}).get(g,True)) for g in NOTIFY_GROUPS}
    events=config.get('events') if isinstance(config.get('events'),dict) else {}
    events={key:bool(events.get(key,old_groups.get(group,True))) for key,group in TELEGRAM_EVENTS.items()}
    if 'events' in data:
        if not isinstance(data['events'],dict): raise ValueError('Invalid notification settings')
        events={key:bool(data['events'].get(key,False)) for key in TELEGRAM_EVENTS}
    elif 'notify' in data:                     # the older form: one switch per group
        if not isinstance(data['notify'],dict): raise ValueError('Invalid notification settings')
        events={key:bool(data['notify'].get(group,False)) if group in NOTIFY_GROUPS else events[key]
                for key,group in TELEGRAM_EVENTS.items()}
    thresholds=dict(TELEGRAM_THRESHOLDS)
    if isinstance(config.get('thresholds'),dict): thresholds.update(config['thresholds'])
    if 'thresholds' in data:
        if not isinstance(data['thresholds'],dict): raise ValueError('Invalid thresholds')
        thresholds.update(data['thresholds'])
    for key in TELEGRAM_THRESHOLDS:
        try: thresholds[key]=int(thresholds[key])
        except (TypeError,ValueError): raise ValueError('Thresholds: whole percent from 10 to 100') from None
        if not 10<=thresholds[key]<=100: raise ValueError('Thresholds: whole percent from 10 to 100')
    thresholds={key:thresholds[key] for key in TELEGRAM_THRESHOLDS}
    stored_api=str(config.get('api_base') or TELEGRAM_API)
    api_base=stored_api
    if 'api_base' in data:                     # an unchanged address is kept as it is, even an older free-form one
        wanted=str(data.get('api_base') or '').strip().rstrip('/') or TELEGRAM_API
        if wanted!=stored_api.rstrip('/'): api_base=telegram_api_base(wanted)
    token=str(data.get('token') or '').strip()
    # Where the token is sent and the token itself are as lasting as who the administrators are.
    if api_base!=stored_api or token:
        require_panel_password(data)
    if token:
        if not re.fullmatch(r'[0-9]{5,14}:[A-Za-z0-9_-]{30,60}',token): raise ValueError('Invalid Telegram token format')
        import sys
        probe=TELEGRAM_PROBE
        if not probe.is_file(): raise ValueError('Telegram setup helper is not installed; run scripts/upgrade-core.sh')
        cp=subprocess.run([sys.executable,str(probe),'check-token'],input=token+'\n',text=True,capture_output=True,
                          timeout=40,check=False,env={**os.environ,'AWG31_TELEGRAM_API':api_base})
        username=cp.stdout.strip()
        if cp.returncode or not re.fullmatch(r'[A-Za-z0-9_]{1,32}',username):
            raise ValueError('Telegram did not accept the new token, or the API server is unreachable')
        config.update(token=token,username=username)
    enabled=data.get('enabled',True) is not False
    config.update({'admins':admins,'viewers':viewers,'lang':lang,'digest':digest,'events':events,
                   'thresholds':thresholds,'backup_file':bool(data.get('backup_file',config.get('backup_file',old_groups['backups']))),
                   # Group switches stay for older tools: on while any event of the group is on.
                   'notify':{g:any(on for key,on in events.items() if TELEGRAM_EVENTS[key]==g) for g in NOTIFY_GROUPS}})
    if api_base==TELEGRAM_API: config.pop('api_base',None)
    else: config['api_base']=api_base
    original=file.stat()
    fd,path=tempfile.mkstemp(prefix='.telegram-',dir=file.parent)
    try:
        with os.fdopen(fd,'w') as fp:
            json.dump(config,fp,indent=1);fp.flush();os.fsync(fp.fileno())
            os.fchmod(fp.fileno(),0o640)
        os.chown(path,original.st_uid,original.st_gid)
        os.replace(path,file)
    finally:
        Path(path).unlink(missing_ok=True)
    if enabled:
        subprocess.run(['systemctl','enable','awg31-bot.service'],capture_output=True,timeout=30,check=False)
        subprocess.run(['systemctl','restart','awg31-bot.service'],capture_output=True,timeout=30,check=False)
    else:
        subprocess.run(['systemctl','disable','--now','awg31-bot.service'],capture_output=True,timeout=30,check=False)
    detail=f'{len(admins)} admin(s), {len(viewers)} viewer(s)'+('' if enabled else ', bot switched off')
    if token: detail+=f', new token @{config.get("username","")}'
    audit({'event':'telegram_changed','target':detail})
    return {'ok':True}


def telegram_test(data=None):
    """Send the test message to every administrator with the saved settings."""
    if not bot_config_file().is_file(): raise ValueError('The bot is not connected: connect it first')
    import sys
    probe=TELEGRAM_PROBE
    if not probe.is_file(): raise ValueError('Telegram setup helper is not installed; run scripts/upgrade-core.sh')
    cp=subprocess.run([sys.executable,str(probe),'send-test'],capture_output=True,text=True,timeout=60,check=False,
                      env={**os.environ,'AWG31_BOT_CONFIG':str(bot_config_file())})
    if cp.returncode:
        raise ValueError('Telegram did not deliver the message: check the token, the API server and that every '
                         'administrator has sent /start to the bot')
    return {'ok':True}


# ---- Backup encryption: one passphrase, standard OpenPGP symmetric encryption ----
def backup_key_file():
    return Path(os.environ.get('AWG31_BACKUP_KEY','/etc/awg31-panel/backup-passphrase'))


def backup_encryption():
    return {'enabled':backup_key_file().is_file()}


def backup_encryption_set(data):
    """Enable/disable encryption. The passphrase stays root-readable only."""
    file=backup_key_file()
    require_panel_password(data)
    # Keep the CLI's off flag; accept the web form's boolean as its equivalent.
    off=data.get('off') is True or data.get('enabled') is False
    if off:
        if file.is_symlink(): raise ValueError('Invalid backup passphrase file')
        file.unlink(missing_ok=True)
        audit({'event':'backup_encryption_changed','target':'off'})
        return {'ok':True,'enabled':False}
    # Only invocations explicitly marked as panel requests are restricted to
    # enabling encryption. Direct root-console calls keep their old behavior.
    if data.get('enabled') is True and (file.exists() or file.is_symlink()):
        raise ValueError('Backup encryption is already enabled: use "backup-encryption change" from the root console')
    if not shutil_which('gpg'): raise ValueError('gpg is not installed: install the gnupg package first')
    passphrase,generated=_new_passphrase(data)
    file.parent.mkdir(parents=True,exist_ok=True)
    _atomic_private_file(file,passphrase+'\n')
    os.chown(file,0,0)
    audit({'event':'backup_encryption_changed','target':'on'})
    return {'ok':True,'enabled':True,'passphrase':passphrase if generated else None}


def shutil_which(name):
    import shutil
    return shutil.which(name)


def _gpg(args, *, input=None, key=None):
    """gpg with a throw-away home: the panel's sandbox hides /root."""
    with tempfile.TemporaryDirectory(prefix='awg31-gpg-') as home:
        cp=subprocess.run(['gpg','--homedir',home,'--batch','--yes','--quiet','--no-tty','--pinentry-mode','loopback',
                           '--passphrase-file',str(key or backup_key_file()),*args],input=input,capture_output=True,timeout=120,check=False)
    if cp.returncode: raise ValueError('gpg failed: '+cp.stderr.decode('utf-8','replace').strip()[-200:])
    return cp.stdout


def _new_passphrase(data):
    passphrase=str(data.get('passphrase','') or '')
    generated=not passphrase
    if generated:
        passphrase='-'.join(secrets.token_hex(3) for _ in range(6))
    if len(passphrase)<16 or len(passphrase)>200 or any(ord(c)<32 for c in passphrase):
        raise ValueError('Passphrase: 16-200 characters, one line')
    return passphrase,generated


def backup_encryption_change(data):
    """A new passphrase, and every archive the current one opens is re-encrypted with it.
    From the panel it needs the panel password.

    Nothing is replaced until every archive has been re-encrypted, so a failure
    half-way leaves the old passphrase and the old archives fully intact.
    """
    require_panel_password(data)
    file=backup_key_file()
    if not file.is_file(): raise ValueError('Backup encryption is off: use "backup-encryption on"')
    passphrase,generated=_new_passphrase(data)
    directory=backup_dir()
    archives=sorted(p for p in directory.glob('awg31-*.tar.gz.gpg') if VALID_BACKUP.fullmatch(p.name)) if directory.is_dir() else []
    new_key=file.with_name(file.name+'.new')
    _atomic_private_file(new_key,passphrase+'\n')
    ready,skipped=[],[]
    try:
        for archive in archives:
            try: plain=_gpg(['--decrypt',str(archive)])
            except ValueError:
                skipped.append(archive.name)          # sealed with some earlier passphrase: left as it is
                continue
            target=archive.with_name(archive.name+'.new')
            _gpg(['--symmetric','--cipher-algo','AES256','--output',str(target),'-'],input=plain,key=new_key)
            os.chmod(target,0o600)
            ready.append((target,archive))
        for target,archive in ready: os.replace(target,archive)
        os.replace(new_key,file)
    except Exception:
        for target,_ in ready: target.unlink(missing_ok=True)
        new_key.unlink(missing_ok=True)
        raise
    audit({'event':'backup_encryption_changed','target':f'passphrase changed, {len(ready)} re-encrypted'})
    return {'ok':True,'reencrypted':len(ready),'skipped':skipped,'passphrase':passphrase if generated else None}


# ---- Copies outside the server: S3-compatible storage or SFTP. Encrypted archives only. ----
def remote_file():
    return Path(os.environ.get('AWG31_BACKUP_REMOTE','/etc/awg31-panel/backup-remote.json'))


def _remote():
    file=remote_file()
    if not file.is_file(): return None
    return json.loads(file.read_text())


def _remote_target(remote):
    if remote['type']=='s3': return f"s3://{remote['bucket']}/{remote.get('prefix','')} ({remote['endpoint']})"
    return f"sftp://{remote['user']}@{remote['host']}:{remote['port']}{remote['path']}"


def backup_remote_status():
    remote=_remote()
    if not remote: return {'configured':False}
    return {'configured':True,'type':remote['type'],'target':_remote_target(remote)}      # never the keys


def backup_remote_set(data):
    """Root console only. S3 keys and the SFTP private key never leave the server."""
    file=remote_file()
    if data.get('off') is True:
        file.unlink(missing_ok=True)
        audit({'event':'backup_remote_changed','target':'off'})
        return {'ok':True,'configured':False}
    if not backup_key_file().is_file():
        raise ValueError('Turn on backup encryption first (backup-encryption on): only encrypted archives leave the server')
    kind=str(data.get('type',''))
    def field(name,pattern,default=None):
        value=str(data.get(name,default if default is not None else '')).strip()
        if not re.fullmatch(pattern,value): raise ValueError(f'Invalid value: {name}')
        return value
    if kind=='s3':
        remote={'type':'s3','endpoint':field('endpoint',r'https?://[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?').rstrip('/'),
                'region':field('region',r'[a-z0-9-]{1,40}','us-east-1'),'bucket':field('bucket',r'[a-z0-9][a-z0-9.-]{1,62}'),
                'prefix':field('prefix',r'(?:[A-Za-z0-9._-]+/)*',''),
                'access_key':field('access_key',r'[A-Za-z0-9+/=_-]{3,128}'),'secret_key':field('secret_key',r'[\x21-\x7e]{8,256}')}
        result={'ok':True,'configured':True}
    elif kind=='sftp':
        if not shutil_which('sftp') or not shutil_which('ssh-keygen'): raise ValueError('The OpenSSH client is not installed')
        remote={'type':'sftp','host':field('host',r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}'),'port':int(field('port',r'[0-9]{1,5}','22')),
                'user':field('user',r'[a-z_][a-z0-9_.-]{0,31}'),'path':field('path',r'/(?:[A-Za-z0-9._-]+/?)*','/')}
        if not 1<=remote['port']<=65535: raise ValueError('Invalid value: port')
        key=file.with_name('backup-remote.key')
        if not key.is_file():
            cp=subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','awg31-backup','-f',str(key)],capture_output=True,text=True,timeout=30)
            if cp.returncode: raise ValueError('ssh-keygen failed: '+cp.stderr.strip()[-200:])
            os.chmod(key,0o600)
        result={'ok':True,'configured':True,'public_key':key.with_name(key.name+'.pub').read_text().strip()}
    else:
        raise ValueError('Storage type: s3 or sftp')
    _atomic_private_file(file,json.dumps(remote,indent=1)+'\n')
    audit({'event':'backup_remote_changed','target':_remote_target(remote)[:110]})
    result['target']=_remote_target(remote)
    return result


def s3_authorization(method,host,path,headers,payload_hash,region,access_key,secret_key,amz_date):
    """AWS Signature Version 4 for one S3 request without a query string. Returns the Authorization header."""
    import hmac
    signed=dict(sorted((k.lower(),' '.join(str(v).split())) for k,v in headers.items()))
    canonical='\n'.join([method,path,'',''.join(f'{k}:{v}\n' for k,v in signed.items()),';'.join(signed),payload_hash])
    scope=f'{amz_date[:8]}/{region}/s3/aws4_request'
    to_sign='\n'.join(['AWS4-HMAC-SHA256',amz_date,scope,hashlib.sha256(canonical.encode()).hexdigest()])
    key=('AWS4'+secret_key).encode()
    for part in (amz_date[:8],region,'s3','aws4_request'):
        key=hmac.new(key,part.encode(),hashlib.sha256).digest()
    signature=hmac.new(key,to_sign.encode(),hashlib.sha256).hexdigest()
    return f'AWS4-HMAC-SHA256 Credential={access_key}/{scope},SignedHeaders={";".join(signed)},Signature={signature}'


def _s3_put(remote,name,body):
    import urllib.error,urllib.parse,urllib.request
    host=urllib.parse.urlsplit(remote['endpoint']).netloc
    path='/'+remote['bucket']+'/'+urllib.parse.quote(remote.get('prefix','')+name,safe='/-_.~')      # path-style: works everywhere
    amz_date=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    payload_hash=hashlib.sha256(body).hexdigest()
    headers={'Host':host,'x-amz-content-sha256':payload_hash,'x-amz-date':amz_date}
    headers['Authorization']=s3_authorization('PUT',host,path,headers,payload_hash,remote['region'],
                                              remote['access_key'],remote['secret_key'],amz_date)
    request=urllib.request.Request(remote['endpoint']+path,data=body,method='PUT',headers=headers)
    try:
        with urllib.request.urlopen(request,timeout=60) as reply: reply.read()
    except urllib.error.HTTPError as exc:
        detail=re.search(r'<Code>([^<]{1,60})</Code>',exc.read(2000).decode('utf-8','replace'))
        raise ValueError(f'S3 answered {exc.code}'+(f' {detail.group(1)}' if detail else '')) from None
    except (urllib.error.URLError,OSError) as exc:
        raise ValueError(f'S3 is unreachable: {getattr(exc,"reason",exc)}'[:150]) from None


def _sftp_put(remote,source,name):
    base=remote_file()
    batch=f'put "{source}" "{remote["path"].rstrip("/")}/{name}"\n'
    cp=subprocess.run(['sftp','-q','-b','-','-i',str(base.with_name('backup-remote.key')),'-P',str(remote['port']),
                       '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=15',
                       # The host key is remembered at the first connection and must not change afterwards.
                       '-o','StrictHostKeyChecking=accept-new','-o',f'UserKnownHostsFile={base.with_name("backup-remote.known_hosts")}',
                       f'{remote["user"]}@{remote["host"]}'],input=batch,capture_output=True,text=True,timeout=90,check=False)
    if cp.returncode:
        lines=[l for l in (cp.stderr or cp.stdout).strip().splitlines() if l.strip()]
        raise ValueError('SFTP failed: '+(lines[-1] if lines else 'unknown error')[:150])


def upload_backup(name):
    """Send one encrypted archive to the configured storage. Raises ValueError with a short reason."""
    remote=_remote()
    if not remote: raise ValueError('Remote storage is not configured')
    if not VALID_BACKUP.fullmatch(str(name)) or not str(name).endswith('.gpg'): raise ValueError('Only encrypted backups are uploaded')
    source=backup_dir()/name
    if not source.is_file(): raise ValueError('Backup not found')
    if remote['type']=='s3': _s3_put(remote,name,source.read_bytes())
    else: _sftp_put(remote,source,name)
    return {'ok':True,'target':_remote_target(remote)}


def backup_remote_test():
    """Root console only: prove that the storage accepts a file, without sending a backup."""
    remote=_remote()
    if not remote: raise ValueError('Remote storage is not configured')
    name='awg31-connection-test.txt'
    body=f'AmneziaWG 3.1 Console backup storage test, {datetime.now(timezone.utc).isoformat()}\n'.encode()
    if remote['type']=='s3': _s3_put(remote,name,body)
    else:
        with tempfile.TemporaryDirectory(prefix='awg31-remote-') as tmp:
            probe=Path(tmp)/name; probe.write_bytes(body)
            _sftp_put(remote,probe,name)
    return {'ok':True,'target':_remote_target(remote),'file':name}


def after_backup(result):
    """Called after every new backup: upload it when a storage is set up. Never fails the backup itself."""
    if not result.get('encrypted') or not _remote(): return result
    try:
        upload_backup(result['name'])
        audit({'event':'backup_uploaded','target':result['name']})
        result['uploaded']=True
    except (ValueError,OSError,subprocess.TimeoutExpired) as exc:
        reason=''.join(c for c in str(exc) if ord(c)>=32)[:60]
        audit({'event':'backup_upload_failed','target':f"{result['name']}: {reason}"})
        result['uploaded']=False; result['upload_error']=reason
    return result


def _check_new_password(new):
    if len(new)<12 or len(new)>256: raise ValueError('Password must be 12-256 characters')


def password_change(data):
    old=str(data.get('old_password',''))
    new=str(data.get('new_password',''))
    _check_new_password(new)
    file=auth_file(); root=json.loads(file.read_text()); auth=account_record(root,data.get('account',''))
    if not _password_ok(auth,old):
        raise ValueError('Incorrect old password')
    _hash_password(auth,new)
    _save_auth(root,file,rotate=False)          # the panel ends this account's sessions
    audit({'event':'password_changed','target':str(data.get('account','') or '')})
    return {'ok':True}


def password_reset(data):
    """Console recovery (`sudo awg31 reset-password`): no old password needed.

    Reachable only by root: the operation is not in the panel's sudoers list.
    """
    new=str(data.get('new_password',''))
    _check_new_password(new)
    file=auth_file(); auth=json.loads(file.read_text())
    if not isinstance(auth,dict) or 'session_key' not in auth:
        raise ValueError('auth.json is damaged; reinstall the panel credentials')
    _store_password(auth,new,file)
    audit({'event':'password_changed','target':'console reset'})
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
            if owners_db().is_file():
                # Owners and their shared limits belong to all servers at once.
                with tempfile.TemporaryDirectory(prefix='awg31-db-') as td:
                    temp=Path(td)/'owners.sqlite3'
                    with sqlite3.connect(owners_db()) as s, sqlite3.connect(temp) as d:
                        s.backup(d)
                    content=temp.read_bytes()
                    _safe_add(tf,'databases/owners.sqlite3',content)
                    manifest['files']['databases/owners.sqlite3']=hashlib.sha256(content).hexdigest()
            _safe_add(tf,'manifest.json',json.dumps(manifest,sort_keys=True).encode())
        if archive.stat().st_size>20*1024*1024: raise ValueError('Archive exceeds 20 MiB limit')
        if backup_key_file().is_file():
            # The plain archive never outlives this function.
            sealed=directory/(name+'.gpg')
            try:
                _gpg(['--symmetric','--cipher-algo','AES256','--output',str(sealed),str(archive)])
                os.chmod(sealed,0o600)
            except Exception:
                sealed.unlink(missing_ok=True);raise
            archive.unlink()
            archive,name=sealed,name+'.gpg'
    except Exception:
        archive.unlink(missing_ok=True);raise
    audit({'event':'backup_created','target':name})
    return {'ok':True,'name':name,'size':archive.stat().st_size,'encrypted':name.endswith('.gpg')}


def list_backups():
    directory=backup_dir()
    if not directory.exists(): return {'backups':[]}
    found=[]
    for p in directory.iterdir():
        if VALID_BACKUP.fullmatch(p.name) and p.is_file() and not p.is_symlink():
            found.append({'name':p.name,'size':p.stat().st_size,'created_at':p.name[6:22],'encrypted':p.name.endswith('.gpg')})
    return {'backups':sorted(found,key=lambda x:x['name'],reverse=True)[:30]}


def export_backup(data, *, encrypted_only=False):
    name=str(data.get('name',''))
    if not VALID_BACKUP.fullmatch(name): raise ValueError('Invalid backup name')
    # The Telegram bot may fetch an archive only when it is encrypted.
    if encrypted_only and not name.endswith('.gpg'): raise ValueError('Only encrypted backups can be sent')
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
            'panel':command(['systemctl','is-active','awg31-panel.service']),
            'next_kernel':next_kernel_state()}


def next_kernel_state():
    """What kernel-check.sh found for a newer installed kernel that is not running yet."""
    file=Path(os.environ.get('AWG31_NEXT_KERNEL','/var/lib/awg31-panel/next-kernel'))
    try: state,_,version=file.read_text().strip().partition(' ')
    except OSError: return {'ok':True,'output':''}
    if state=='missing' and re.fullmatch(r'[A-Za-z0-9._+~-]{1,100}',version): return {'ok':False,'output':version}
    return {'ok':True,'output':version if state=='ok' else ''}


# ------------------------------------------------------------------ logging: settings and IP masking
# The same settings file and masking rules as in awg31ctl (a test keeps the two equal).
LOGGING_DEFAULTS={'history':False,'retention_days':30,'masking':'partial'}
MASK_MODES=('none','partial','full')
_IPV4=re.compile(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])')
_IPV6=re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])')


def logging_file():
    return Path(os.environ.get('AWG31_LOGGING','/etc/awg31-panel/logging.json'))


def mask_key_file():
    return Path(os.environ.get('AWG31_IP_MASK_KEY','/etc/awg31-panel/ip-mask.key'))


def logging_settings():
    try: data=json.loads(logging_file().read_text())
    except (OSError,ValueError): data={}
    result=dict(LOGGING_DEFAULTS)
    if isinstance(data,dict):
        result['history']=bool(data.get('history',False))
        try: result['retention_days']=min(365,max(1,int(data.get('retention_days',30))))
        except (TypeError,ValueError): pass
        if data.get('masking') in MASK_MODES: result['masking']=data['masking']
    return result


def mask_key():
    """A random per-server key: the same address always gets the same label, and the label cannot be reversed."""
    path=mask_key_file()
    try: return path.read_bytes()
    except FileNotFoundError: pass
    path.parent.mkdir(parents=True,exist_ok=True)
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        return path.read_bytes()
    key=secrets.token_bytes(32)
    try: os.write(fd,key)
    finally: os.close(fd)
    return key


def mask_ip(text,mode):
    """One address (IPv4 or IPv6, without a port) as the chosen mode shows it."""
    import ipaddress
    try: address=ipaddress.ip_address(text)
    except ValueError: return text
    if mode=='none': return text
    if mode=='partial':
        if address.version==4: return '.'.join(text.split('.')[:3])+'.x'
        return ':'.join(address.exploded.split(':')[:3])+':…'
    return 'IP-'+hmac.new(mask_key(),address.packed,hashlib.sha256).hexdigest()[:6]


def mask_text(text,mode=None):
    """Public addresses inside free text (log lines, audit targets). Private and local ones stay:
    client tunnel addresses and LAN routes are needed to read the logs and say nothing about people."""
    import ipaddress
    mode=mode or logging_settings()['masking']
    if mode=='none' or not text: return text
    def replace(match):
        raw=match.group(0)
        try: address=ipaddress.ip_address(raw)
        except ValueError: return raw
        return mask_ip(raw,mode) if address.is_global else raw
    return _IPV6.sub(replace,_IPV4.sub(replace,str(text)))


def logging_set(data):
    current=logging_settings()
    history=bool(data.get('history',current['history']))
    try: retention=int(data.get('retention_days',current['retention_days']))
    except (TypeError,ValueError): raise ValueError('History: keep it from 1 to 365 days') from None
    if not 1<=retention<=365: raise ValueError('History: keep it from 1 to 365 days')
    masking=str(data.get('masking',current['masking']))
    if masking not in MASK_MODES: raise ValueError('Address masking: none, partial or full')
    settings={'history':history,'retention_days':retention,'masking':masking}
    path=logging_file(); path.parent.mkdir(parents=True,exist_ok=True)
    _atomic_private_file(path,json.dumps(settings,indent=1)+'\n',mode=0o644)
    if masking=='full': mask_key()
    if settings!=current:
        audit({'event':'logging_changed','target':f"history {'on' if history else 'off'}, {retention}d, masking {masking}"})
    return {'ok':True,'settings':settings}


# ------------------------------------------------------------------ journals
LOG_SOURCES={'panel':['-u','awg31-panel.service'],'bot':['-u','awg31-bot.service'],
             'helper':['-u','awg31-helper.service'],'sampler':['-u','awg31-sampler.service'],
             'backup':['-u','awg31-backup.service'],'kernel-check':['-u','awg31-kernel-check.service'],
             'kernel':['-k']}
LOG_LEVELS={'error':'3','warning':'4','all':''}


def logs_read(data,manager=None):
    """Lines from a fixed list of journals; nothing else can be read this way."""
    source=str(data.get('source','panel'))
    if source in LOG_SOURCES: args=list(LOG_SOURCES[source])
    elif re.fullmatch(r'server:awg(?:0|[1-9][0-9]?)',source):
        iface=source.split(':',1)[1]
        if manager is not None and iface not in manager.interfaces(): raise ValueError('Server not found')
        args=['-u',f'awg-quick@{iface}.service']
    else: raise ValueError('Unknown log source')
    try: lines=int(data.get('lines',200))
    except (TypeError,ValueError): lines=200
    lines=min(2000,max(20,lines))
    level=str(data.get('level','all'))
    if level not in LOG_LEVELS: raise ValueError('Level: error, warning or all')
    query=str(data.get('query',''))[:100]
    if any(ord(c)<32 for c in query): raise ValueError('Invalid search text')
    command=['journalctl','--no-pager','--no-hostname','-o','short-iso','-q']+args
    if LOG_LEVELS[level]: command+=['-p',LOG_LEVELS[level]]
    # The kernel journal is shared by everything on the host: read more, keep the AmneziaWG lines.
    command+=['-n',str(lines*20 if source=='kernel' else lines if not query else lines*10)]
    try: cp=subprocess.run(command,capture_output=True,text=True,timeout=20,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc: raise RuntimeError(f'journalctl: {exc}') from None
    if cp.returncode not in (0,1): raise RuntimeError((cp.stderr or 'journalctl failed').strip()[:300])
    found=cp.stdout.splitlines()
    if source=='kernel': found=[x for x in found if 'amneziawg' in x.lower() or 'awg' in x.lower().split(':',3)[-1][:40]]
    if query: found=[x for x in found if query.lower() in x.lower()]
    mode=logging_settings()['masking']
    return {'source':source,'level':level,'lines':[mask_text(x[:2000],mode) for x in found[-lines:]]}


# ------------------------------------------------------------------ AmneziaWG handshake debug
DEBUG_CONTROL=Path('/sys/kernel/debug/dynamic_debug/control')
MODULE_DIR=Path('/sys/module/amneziawg')


def _debug_until():
    return Path(os.environ.get('AWG31_DEBUG_UNTIL','/run/awg31/debug-until'))


def handshake_debug(data=None):
    """Kernel messages about handshakes for 15 minutes, then off by itself."""
    data=data or {}
    state=_debug_until()
    if 'enable' not in data:
        try: until=int(state.read_text().strip())
        except (OSError,ValueError): until=0
        if until and until<time.time(): until=0
        return {'enabled':bool(until),'until':until,'available':DEBUG_CONTROL.exists()}
    enable=bool(data.get('enable'))
    if not DEBUG_CONTROL.exists():
        if DEBUG_CONTROL==Path('/sys/kernel/debug/dynamic_debug/control') and not any(Path('/sys/kernel/debug').glob('*')):
            subprocess.run(['mount','-t','debugfs','none','/sys/kernel/debug'],capture_output=True,timeout=10,check=False)
        if not DEBUG_CONTROL.exists():
            raise ValueError('This kernel has no dynamic debug (CONFIG_DYNAMIC_DEBUG); handshake messages are not available')
    if not MODULE_DIR.exists(): raise ValueError('The AmneziaWG module is not loaded')
    with open(DEBUG_CONTROL,'w') as control:
        control.write('module amneziawg '+('+p' if enable else '-p')+'\n')
    subprocess.run(['systemctl','stop','awg31-debug-off.timer'],capture_output=True,timeout=10,check=False)
    if enable:
        until=int(time.time())+900
        state.parent.mkdir(parents=True,exist_ok=True); state.write_text(f'{until}\n')
        cp=subprocess.run(['systemd-run','--quiet','--collect','--on-active=15min','--unit','awg31-debug-off',
                           '--description','Switch AmneziaWG handshake debug off','/bin/sh','-c',
                           f"echo 'module amneziawg -p' > {DEBUG_CONTROL}; rm -f {state}"],
                          capture_output=True,text=True,timeout=15,check=False)
        if cp.returncode:
            with open(DEBUG_CONTROL,'w') as control: control.write('module amneziawg -p\n')
            state.unlink(missing_ok=True)
            raise RuntimeError('Could not schedule switching it off again: '+(cp.stderr or '').strip()[:200])
        audit({'event':'debug_changed','target':'handshake debug on for 15 min'})
        return {'enabled':True,'until':until,'available':True}
    state.unlink(missing_ok=True)
    audit({'event':'debug_changed','target':'handshake debug off'})
    return {'enabled':False,'until':0,'available':True}


# ------------------------------------------------------------------ audit log: paging and filters
def audit_list(data=None):
    """Newest first, filtered by event, date range and text; read as a stream, whatever the file size."""
    data=data or {}
    event=str(data.get('event',''))
    if event and event not in VALID_AUDIT: raise ValueError('Unknown event')
    text=str(data.get('query',''))[:80].lower()
    since=str(data.get('since',''))[:10]; until=str(data.get('until',''))[:10]
    for value in (since,until):
        if value and not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}',value): raise ValueError('Dates: YYYY-MM-DD')
    try: page=max(1,int(data.get('page',1)))
    except (TypeError,ValueError): page=1
    try: size=min(1000,max(10,int(data.get('size',50))))
    except (TypeError,ValueError): size=50
    matched=[]
    import gzip
    base=audit_file()
    # logrotate keeps up to 30 older files (audit.jsonl.N.gz, the newest is .1): oldest first, then the live one.
    rotated=sorted((p for p in base.parent.glob(base.name+'.*') if re.fullmatch(re.escape(base.name)+r'\.[0-9]{1,3}(?:\.gz)?',p.name)),
                   key=lambda p:-int(p.name[len(base.name)+1:].split('.')[0])) if base.parent.is_dir() else []
    for path in rotated+[base]:
        if not path.is_file() or path.is_symlink(): continue
        opener=gzip.open if path.name.endswith('.gz') else open
        with opener(path,'rt',encoding='utf-8',errors='replace') as stream:
            for line in stream:
                try: item=json.loads(line)
                except ValueError: continue
                if not isinstance(item,dict): continue
                stamp=str(item.get('timestamp',''))
                if event and item.get('event')!=event: continue
                if since and stamp[:10]<since: continue
                if until and stamp[:10]>until: continue
                if text and text not in (str(item.get('event',''))+' '+str(item.get('target',''))+' '+str(item.get('actor',''))).lower(): continue
                matched.append({'timestamp':stamp,'event':str(item.get('event','')),'target':str(item.get('target',''))})
    matched.reverse()
    total=len(matched)
    return {'entries':matched[(page-1)*size:page*size],'total':total,'page':page,'size':size,
            'pages':max(1,(total+size-1)//size),'events':sorted(VALID_AUDIT)}


# ------------------------------------------------------------------ support report
_KEY=re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42,43}=(?![A-Za-z0-9+/=])')
_TOKEN=re.compile(r'[0-9]{5,14}:[A-Za-z0-9_-]{30,60}')


def redact(text):
    """Keys, tokens and public addresses out; always the full mask, whatever the panel setting."""
    text=_TOKEN.sub('[token]',_KEY.sub('[key]',str(text)))
    text=re.sub(r'(?im)^(\s*(?:PrivateKey|PresharedKey|PublicKey|HeaderProtectionKey|Endpoint|Password|Secret|Token)\s*=\s*).*$',r'\1[removed]',text)
    text=re.sub(r'(?im)^(\s*endpoint:\s*).*$',r'\1[removed]',text)              # `awg show`
    return mask_text(text,'full')


def support_report(manager):
    """A tar.gz with what is needed to understand a problem, and nothing that opens the server."""
    import sys
    def command(args,timeout=20):
        try:
            cp=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
            return (cp.stdout or '')+(('\n[stderr]\n'+cp.stderr) if cp.stderr.strip() else '')
        except (OSError,subprocess.TimeoutExpired) as exc:
            return f'[{" ".join(args[:2])}: {exc}]'
    files={}
    version=''
    for candidate in (Path('/opt/awg31-panel/VERSION'),):
        try: version=candidate.read_text().strip()
        except OSError: pass
    files['system.txt']='\n'.join((
        f'AmneziaWG 3.1 Console {version or "?"}', f'Generated {datetime.now(timezone.utc).isoformat()}',
        '--- os-release', command(['cat','/etc/os-release']), '--- uname', command(['uname','-a']),
        '--- module', command(['cat','/sys/module/amneziawg/version']), command(['dkms','status','-m','amneziawg']),
        '--- python', sys.version, '--- services',
        command(['systemctl','--no-pager','--plain','list-units','awg*','--all']),
        '--- forwarding', command(['sysctl','net.ipv4.ip_forward']),
        '--- addresses', command(['ip','-brief','address']), '--- routes', command(['ip','route']),
        '--- firewall', command(['nft','list','ruleset'],30) or command(['iptables-save'])))
    for iface in manager.interfaces():
        try: files[f'diagnostics-{iface}.json']=json.dumps(diagnose(manager,iface),indent=1,ensure_ascii=False)
        except Exception as exc: files[f'diagnostics-{iface}.json']=f'[{exc}]'
        files[f'awg-show-{iface}.txt']=command(['awg','show',iface])
        try: files[f'{iface}.conf']=manager.conf_path(iface).read_text()
        except OSError as exc: files[f'{iface}.conf']=f'[{exc}]'
    for source in LOG_SOURCES:
        try: files[f'journal-{source}.txt']='\n'.join(logs_read({'source':source,'lines':300})['lines'])
        except (OSError,RuntimeError,ValueError) as exc: files[f'journal-{source}.txt']=f'[{exc}]'
    for iface in manager.interfaces():
        try: files[f'journal-awg-quick-{iface}.txt']='\n'.join(logs_read({'source':'server:'+iface,'lines':200},manager)['lines'])
        except (OSError,RuntimeError,ValueError) as exc: files[f'journal-awg-quick-{iface}.txt']=f'[{exc}]'
    files['audit.jsonl']='\n'.join(json.dumps(x,ensure_ascii=False) for x in reversed(audit_list({'size':300})['entries']))
    files['README.txt']=('Support report of AmneziaWG 3.1 Console. Keys, tokens, endpoints and public IP addresses\n'
                         'are replaced ([key], [token], [removed], IP-xxxxxx). Check it before you send it anywhere.\n')
    buffer=io.BytesIO()
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
        for name,content in files.items():
            raw=redact(content).encode('utf-8',errors='replace')
            info=tarfile.TarInfo(f'awg31-support-{stamp}/{name}'); info.size=len(raw); info.mtime=int(time.time()); info.mode=0o600
            archive.addfile(info,io.BytesIO(raw))
    audit({'event':'support_report','target':f'{len(files)} files'})
    return {'name':f'awg31-support-{stamp}.tar.gz','data':base64.b64encode(buffer.getvalue()).decode()}


# ------------------------------------------------------------------ update and rollback from the panel
UPDATE_STATE=Path(os.environ.get('AWG31_UPDATE_STATE','/var/lib/awg31-panel/update-state.json'))
UPDATE_LOG=Path(os.environ.get('AWG31_UPDATE_LOG','/var/log/awg31-panel/update.log'))
UPDATE_RUNNER=Path(os.environ.get('AWG31_UPDATE_RUNNER','/usr/local/libexec/awg31/scripts/update-run.sh'))
SNAPSHOT_TOOL=Path(os.environ.get('AWG31_SNAPSHOT_TOOL','/usr/local/libexec/awg31/scripts/awg31-snapshot.py'))
UPDATE_UNIT='awg31-update'
APP_VERSION=Path(os.environ.get('AWG31_APP_VERSION','/opt/awg31-panel/VERSION'))


def _installed_version():
    try: text=APP_VERSION.read_text().strip()
    except OSError: return ''
    return text if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',text) else ''


def _version_key(text):
    found=re.fullmatch(r'v?([0-9]+)\.([0-9]+)\.([0-9]+)',str(text or ''))
    return tuple(int(x) for x in found.groups()) if found else None


def _update_running():
    cp=subprocess.run(['systemctl','is-active','--quiet',UPDATE_UNIT],capture_output=True,timeout=10,check=False)
    return cp.returncode==0


def _snapshot_list():
    if not SNAPSHOT_TOOL.exists(): return []
    cp=subprocess.run(['python3',str(SNAPSHOT_TOOL),'list','--json'],capture_output=True,text=True,timeout=30,check=False)
    try: items=json.loads(cp.stdout or '[]')
    except ValueError: return []
    return [x for x in items if isinstance(x,dict)][:20]


def snapshot_delete(data):
    """Delete one rollback snapshot. Not while an update or a rollback runs: it may be using it."""
    name=str(data.get('name',''))
    if not re.fullmatch(r'awg31-upgrade\.[A-Za-z0-9_.-]{4,64}',name): raise ValueError('Invalid snapshot')
    if _update_running(): raise ValueError('An update or rollback is running; try again when it has finished')
    if not any(x.get('name')==name for x in _snapshot_list()): raise ValueError('No such snapshot')
    cp=subprocess.run(['python3',str(SNAPSHOT_TOOL),'delete',name],capture_output=True,text=True,timeout=120,check=False)
    if cp.returncode: raise RuntimeError((cp.stderr or cp.stdout or 'delete failed').strip()[:200])
    return {'ok':True,'name':name}


def update_status(data=None):
    """The last update or rollback started from the panel, its log, and the snapshots to roll back to."""
    try: state=json.loads(UPDATE_STATE.read_text())
    except (OSError,ValueError): state={}
    running=_update_running()
    if state.get('status')=='running' and not running:
        state['status']='failed'                  # the unit died without writing an outcome
    try:
        with open(UPDATE_LOG,'rb') as log:
            log.seek(0,2); size=log.tell(); log.seek(max(0,size-24000))
            tail=log.read().decode('utf-8','replace')
    except OSError:
        tail=''
    lines=tail.splitlines()[-200:]
    return {'state':state,'running':running,'log':redact('\n'.join(lines)),
            'version':_installed_version(),'snapshots':_snapshot_list(),
            'available':UPDATE_RUNNER.exists() and SNAPSHOT_TOOL.exists()}


def update_start(data):
    """Start an update to a newer release, or a rollback to a snapshot, in a transient unit.
    Releases come only from this project's GitHub page and are checked against their SHA256 by the installer."""
    file=auth_file(); auth=json.loads(file.read_text())
    if not _password_ok(auth,data.get('password','')): raise ValueError('Incorrect password')
    action=str(data.get('action','')); target=str(data.get('target',''))
    if action=='update':
        wanted,current=_version_key(target),_version_key(_installed_version())
        if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',target) or not wanted: raise ValueError('Invalid version')
        if current and wanted<=current: raise ValueError('Only a newer release can be installed here; use a rollback to go back')
    elif action=='rollback':
        if not re.fullmatch(r'awg31-upgrade\.[A-Za-z0-9_.-]{4,64}',target): raise ValueError('Invalid snapshot')
        if not any(x.get('name')==target and x.get('usable') for x in _snapshot_list()): raise ValueError('No such snapshot')
    else:
        raise ValueError('action: update or rollback')
    if not UPDATE_RUNNER.exists(): raise ValueError('The update runner is not installed; run sudo awg31 update once')
    if _update_running(): raise ValueError('An update is already running')
    # A private copy: the update replaces the installed runner while it runs. It is read by
    # bash rather than executed, because /run is mounted noexec on some systems.
    fd,copy=tempfile.mkstemp(prefix='awg31-update-run.',suffix='.sh',dir='/run')
    with os.fdopen(fd,'wb') as out: out.write(UPDATE_RUNNER.read_bytes())
    os.chmod(copy,0o700)
    cp=subprocess.run(['systemd-run','--quiet','--collect','--unit',UPDATE_UNIT,'--description',
                       'AmneziaWG 3.1 Console update started from the panel',
                       '--property=TimeoutStartSec=30min','/bin/bash','-c','/bin/bash "$0" "$1" "$2"; code=$?; rm -f "$0"; exit $code',
                       copy,action,target],capture_output=True,text=True,timeout=20,check=False)
    if cp.returncode:
        os.unlink(copy)
        raise RuntimeError('Could not start the update: '+(cp.stderr or '').strip()[:200])
    audit({'event':'panel_update_started','target':f'{action} {target}'})
    return {'ok':True,'action':action,'target':target}


# ------------------------------------------------------------------ 0.20: owners with several devices
# An owner is a person with clients ("devices") on any server. Their shared limits (traffic, term,
# number of devices) live here, in one file for all servers; each client keeps only owner_id, and its
# telegram_id mirrors the owner's so that the bot keeps finding people the way it always did.
OWNER_ID=re.compile(r'^o[0-9a-f]{10}$')
OWNER_TELEGRAM=re.compile(r'^[1-9][0-9]{2,14}$')
OWNER_KINDS=('phone','laptop','tablet','router','tv')
OWNER_MAX_DEVICES=100
_OWNERS_SCHEMA="""CREATE TABLE IF NOT EXISTS owners (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, telegram_id TEXT NOT NULL DEFAULT '',
    comment TEXT NOT NULL DEFAULT '', traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
    quota_period TEXT NOT NULL DEFAULT '', quota_month TEXT NOT NULL DEFAULT '',
    used_bytes INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL DEFAULT '',
    max_devices INTEGER NOT NULL DEFAULT 0, self_add INTEGER NOT NULL DEFAULT 0,
    home_server TEXT NOT NULL DEFAULT '', blocked TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)"""
OWNER_COLUMNS=('id','name','telegram_id','comment','traffic_limit_bytes','quota_period','quota_month','used_bytes',
               'expires_at','max_devices','self_add','home_server','blocked','created_at')


def owners_db():
    return base_dir()/'owners.sqlite3'


def _owners_open():
    path=owners_db()
    fresh=not path.exists()
    path.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(path,timeout=20)
    con.row_factory=sqlite3.Row
    if fresh: os.chmod(path,0o600)
    con.execute(_OWNERS_SCHEMA)
    con.execute('CREATE UNIQUE INDEX IF NOT EXISTS owners_name ON owners(name COLLATE NOCASE)')
    return con, fresh


class _OwnersLock:
    """Owner changes are read-check-write across several databases: one at a time."""
    def __enter__(self):
        base_dir().mkdir(parents=True,exist_ok=True)
        self.handle=open(base_dir()/'owners.lock','a+')
        fcntl.flock(self.handle.fileno(),fcntl.LOCK_EX)
        return self
    def __exit__(self,*exc):
        self.handle.close()


def _owner_name(raw):
    name=' '.join(str(raw or '').split())
    if not 1<=len(name)<=40 or any(ord(c)<32 or c in '<>"\'`;\\' for c in name):
        raise ValueError('Имя владельца: от 1 до 40 символов, без < > " \' ` ; \\')
    return name


def _owner_expiry(raw):
    text=str(raw or '').strip()
    if not text: return ''
    try:
        if re.fullmatch(r'[0-9]{2}\.[0-9]{2}\.[0-9]{4}',text):
            moment=datetime.strptime(text,'%d.%m.%Y').replace(hour=23,minute=59,second=59)
        else:
            moment=datetime.fromisoformat(text.replace('Z','+00:00'))
            if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}',text): moment=moment.replace(hour=23,minute=59,second=59)
        if moment.tzinfo is None: moment=moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat()
    except (ValueError,OverflowError):
        raise ValueError('Срок владельца: дата ДД.ММ.ГГГГ или ГГГГ-ММ-ДД') from None


def _owner_fields(data, old, manager):
    old=old or {}
    def number(key,low,high,label):
        try: value=int(data.get(key,old.get(key,0)) or 0)
        except (TypeError,ValueError): raise ValueError(f'{label}: целое число') from None
        if not low<=value<=high: raise ValueError(f'{label}: от {low} до {high}')
        return value
    telegram=str(data.get('telegram_id',old.get('telegram_id','')) or '').strip()
    if telegram=='0': telegram=''
    if telegram and not OWNER_TELEGRAM.fullmatch(telegram):
        raise ValueError('Telegram ID: только цифры (числовой ID пользователя, не @имя)')
    comment=str(data.get('comment',old.get('comment','')) or '').strip()
    if len(comment)>200 or any(ord(c)<32 for c in comment): raise ValueError('Комментарий: до 200 символов')
    period=str(data.get('quota_period',old.get('quota_period','')) or '')
    if period not in ('','monthly'): raise ValueError('Период лимита: пусто или monthly')
    home=str(data.get('home_server',old.get('home_server','')) or '')
    if home and home not in manager.interfaces(): raise ValueError('Сервер для новых устройств не найден')
    self_add=data.get('self_add',old.get('self_add',0)) in (True,1,'1','on','true')
    return {'name':_owner_name(data.get('name',old.get('name',''))),'telegram_id':telegram,'comment':comment,
            'traffic_limit_bytes':number('traffic_limit_bytes',0,10**15,'Общий лимит трафика'),'quota_period':period,
            'expires_at':_owner_expiry(data.get('expires_at',old.get('expires_at',''))),
            'max_devices':number('max_devices',0,OWNER_MAX_DEVICES,'Максимум устройств'),
            'self_add':int(self_add),'home_server':home}


def owner_devices(manager):
    """{owner_id: [device, ...]} read straight from every server's database (read only)."""
    found={}
    for iface in manager.interfaces():
        try:
            with sqlite3.connect(f'file:{manager.db_path(iface)}?mode=ro',uri=True,timeout=10) as con:
                con.row_factory=sqlite3.Row
                columns={row[1] for row in con.execute('PRAGMA table_info(clients)')}
                if 'owner_id' not in columns: continue
                for row in con.execute("SELECT name,enabled,disabled_reason,used_bytes,telegram_id,owner_id,last_handshake "
                                       "FROM clients WHERE owner_id<>'' ORDER BY created_at,name"):
                    found.setdefault(row['owner_id'],[]).append({'interface':iface,'name':row['name'],'enabled':bool(row['enabled']),
                        'disabled_reason':row['disabled_reason'],'used_bytes':int(row['used_bytes'] or 0),
                        'last_handshake':int(row['last_handshake'] or 0)})
        except sqlite3.Error:
            continue
    return found


def _owner_state(row, now=None):
    """'' when the owner's devices may work, else 'quota' or 'expired'."""
    now=now or datetime.now(timezone.utc)
    if row['expires_at'] and datetime.fromisoformat(row['expires_at'])<=now: return 'expired'
    if row['traffic_limit_bytes'] and int(row['used_bytes'])>=int(row['traffic_limit_bytes']): return 'quota'
    return ''


def owners_blocked():
    """{owner_id: reason} for owners whose devices must stay off. Read by every sample and enable."""
    if not owners_db().exists(): return {}
    con,_=_owners_open()
    try: return {row['id']:row['blocked'] for row in con.execute("SELECT id,blocked FROM owners WHERE blocked<>''")}
    finally: con.close()


def _owner_public(row, devices):
    item={k:row[k] for k in OWNER_COLUMNS}
    item['self_add']=bool(item['self_add'])
    item['devices']=devices.get(row['id'],[])
    item['device_count']=len(item['devices'])
    return item


def _sync_servers(manager, payload):
    """Tell every server what changed; returns {iface: result}."""
    results={}
    for iface in manager.interfaces():
        try: results[iface]=manager.child(iface,'owner-sync',payload)
        except (RuntimeError,ValueError) as exc: results[iface]={'ok':False,'error':str(exc)[:200]}
    return results


def owners_migrate(manager, con=None):
    """Clients that only have a Telegram ID (as before 0.20, or restored from an old backup) get an owner:
    one per Telegram ID, named after it until the administrator renames it."""
    own=con is None
    if own: con,_=_owners_open()
    try:
        ids=set()
        for iface in manager.interfaces():
            try:
                with sqlite3.connect(f'file:{manager.db_path(iface)}?mode=ro',uri=True,timeout=10) as db:
                    columns={row[1] for row in db.execute('PRAGMA table_info(clients)')}
                    query=("SELECT DISTINCT telegram_id FROM clients WHERE telegram_id<>''"
                           +(" AND owner_id=''" if 'owner_id' in columns else ''))
                    ids|={str(row[0]) for row in db.execute(query) if OWNER_TELEGRAM.fullmatch(str(row[0]))}
            except sqlite3.Error:
                continue
        if not ids: return {}
        link={}
        for telegram in sorted(ids):
            row=con.execute('SELECT id FROM owners WHERE telegram_id=?',(telegram,)).fetchone()
            link[telegram]=row['id'] if row else _owner_insert(con,{'name':f'Telegram {telegram}','telegram_id':telegram})
        con.commit()
        _sync_servers(manager,{'link':link})
        return link
    finally:
        if own: con.close()


def _owner_insert(con, fields):
    name=fields['name']
    base,n=name,2
    while con.execute('SELECT 1 FROM owners WHERE name=? COLLATE NOCASE',(name,)).fetchone():
        name=f'{base[:36]} {n}';n+=1
    owner_id='o'+secrets.token_hex(5)
    values={'traffic_limit_bytes':0,'quota_period':'','quota_month':'','used_bytes':0,'expires_at':'','max_devices':0,
            'self_add':0,'home_server':'','blocked':'','comment':'','telegram_id':'',**fields,'id':owner_id,'name':name,
            'created_at':datetime.now(timezone.utc).isoformat(timespec='seconds')}
    if values['quota_period']=='monthly' and not values['quota_month']:
        values['quota_month']=datetime.now(timezone.utc).strftime('%Y-%m')
    con.execute(f'INSERT INTO owners ({",".join(OWNER_COLUMNS)}) VALUES ({",".join("?"*len(OWNER_COLUMNS))})',
                [values[c] for c in OWNER_COLUMNS])
    return owner_id


def owners_list(manager, data=None):
    with _OwnersLock():
        con,_=_owners_open()
        try:
            owners_migrate(manager,con)
            devices=owner_devices(manager)
            rows=[_owner_public(row,devices) for row in con.execute('SELECT * FROM owners ORDER BY name COLLATE NOCASE')]
        finally: con.close()
    wanted=str((data or {}).get('telegram_id','') or '')
    if wanted: rows=[row for row in rows if row['telegram_id']==wanted]
    return {'owners':rows,'kinds':list(OWNER_KINDS)}


def owner_set(manager, data):
    """Create (no id) or change an owner. Devices follow at once: Telegram ID, and on or off by the limits."""
    owner_id=str(data.get('id','') or '')
    if owner_id and not OWNER_ID.fullmatch(owner_id): raise ValueError('Неверный владелец')
    with _OwnersLock():
        con,_=_owners_open()
        try:
            old=dict(con.execute('SELECT * FROM owners WHERE id=?',(owner_id,)).fetchone() or {}) if owner_id else {}
            if owner_id and not old: raise ValueError('Владелец не найден')
            fields=_owner_fields(data,old,manager)
            clash=con.execute('SELECT id FROM owners WHERE name=? COLLATE NOCASE AND id<>?',(fields['name'],owner_id)).fetchone()
            if clash: raise ValueError('Владелец с таким именем уже есть')
            if fields['telegram_id']:
                clash=con.execute('SELECT name FROM owners WHERE telegram_id=? AND id<>?',(fields['telegram_id'],owner_id)).fetchone()
                if clash: raise ValueError(f'Этот Telegram ID уже у владельца «{clash["name"]}»')
            devices=owner_devices(manager)
            if fields['max_devices'] and owner_id and len(devices.get(owner_id,[]))>fields['max_devices']:
                raise ValueError(f'У владельца уже {len(devices[owner_id])} устройств: удалите лишние или увеличьте максимум')
            if owner_id:
                month=datetime.now(timezone.utc).strftime('%Y-%m')
                if fields['quota_period']=='monthly' and old['quota_period']!='monthly': fields['quota_month']=month
                con.execute('UPDATE owners SET '+','.join(f'{k}=?' for k in fields)+' WHERE id=?',[*fields.values(),owner_id])
            else:
                owner_id=_owner_insert(con,fields)
            if data.get('reset_used') in (True,1,'1','on'):
                con.execute('UPDATE owners SET used_bytes=0 WHERE id=?',(owner_id,))
            row=con.execute('SELECT * FROM owners WHERE id=?',(owner_id,)).fetchone()
            state=_owner_state(row)
            con.execute('UPDATE owners SET blocked=? WHERE id=?',(state,owner_id))
            con.commit()
            blocked={r['id']:r['blocked'] for r in con.execute("SELECT id,blocked FROM owners WHERE blocked<>''")}
            payload={'blocked':blocked}
            if old and old.get('telegram_id','')!=fields['telegram_id']: payload['telegram']={owner_id:fields['telegram_id']}
            results=_sync_servers(manager,payload)
            row=con.execute('SELECT * FROM owners WHERE id=?',(owner_id,)).fetchone()
            item=_owner_public(row,owner_devices(manager))
        finally: con.close()
    audit({'event':'owner_changed' if old else 'owner_created','target':f'{item["name"]} ({owner_id})'[:120]})
    _owner_audit_changes(results)
    return {'ok':True,'owner':item}


def _owner_audit_changes(results):
    for iface,result in results.items():
        for name in result.get('disabled',[]) if isinstance(result,dict) else []:
            audit({'event':'client_disabled','target':f'{iface}/{name} (owner limit)'})
        for name in result.get('enabled',[]) if isinstance(result,dict) else []:
            audit({'event':'client_enabled','target':f'{iface}/{name} (owner limit)'})


def owner_delete(manager, data):
    """The owner goes; their devices stay, without an owner (and without the Telegram link)."""
    owner_id=str(data.get('id','') or '')
    if not OWNER_ID.fullmatch(owner_id): raise ValueError('Неверный владелец')
    with _OwnersLock():
        con,_=_owners_open()
        try:
            row=con.execute('SELECT name FROM owners WHERE id=?',(owner_id,)).fetchone()
            if not row: raise ValueError('Владелец не найден')
            con.execute('DELETE FROM owners WHERE id=?',(owner_id,))
            con.commit()
            blocked={r['id']:r['blocked'] for r in con.execute("SELECT id,blocked FROM owners WHERE blocked<>''")}
        finally: con.close()
        results=_sync_servers(manager,{'removed':[owner_id],'blocked':blocked})
    audit({'event':'owner_deleted','target':f'{row["name"]} ({owner_id})'[:120]})
    _owner_audit_changes(results)
    return {'ok':True,'id':owner_id}


def owner_get(owner_id):
    if not OWNER_ID.fullmatch(str(owner_id or '')) or not owners_db().exists(): return None
    con,_=_owners_open()
    try:
        row=con.execute('SELECT * FROM owners WHERE id=?',(owner_id,)).fetchone()
        return dict(row) if row else None
    finally: con.close()


def owner_by_telegram(telegram, *, create_name=None):
    """The owner with this Telegram ID; with create_name a new one is made when there is none."""
    if not OWNER_TELEGRAM.fullmatch(str(telegram or '')): return None
    con,_=_owners_open()
    try:
        row=con.execute('SELECT * FROM owners WHERE telegram_id=?',(str(telegram),)).fetchone()
        if row or not create_name: return dict(row) if row else None
        owner_id=_owner_insert(con,{'name':_owner_name(create_name),'telegram_id':str(telegram)})
        con.commit()
        audit({'event':'owner_created','target':f'{create_name} ({owner_id})'[:120]})
        return dict(con.execute('SELECT * FROM owners WHERE id=?',(owner_id,)).fetchone())
    finally: con.close()


def owner_resolve(manager, op, iface, payload):
    """Before a client gets an owner (add, client-policy, client-batch owner): the owner must exist,
    the device count must fit, and the client's telegram_id becomes the owner's. A bare telegram_id (the bot,
    older forms) is turned into that person's owner, made on the spot when needed."""
    if 'owner_id' in payload:
        owner_id=str(payload.get('owner_id') or '')
        owner=owner_get(owner_id) if owner_id else None
        if owner_id and not owner: raise ValueError('Владелец не найден')
    elif 'telegram_id' in payload:
        telegram=str(payload.get('telegram_id') or '').strip()
        if telegram in ('','0'):
            owner=None
        else:
            if not OWNER_TELEGRAM.fullmatch(telegram):
                raise ValueError('Telegram ID: только цифры (числовой ID пользователя, не @имя)')
            owner=owner_by_telegram(telegram,create_name=f'Telegram {telegram}')
    else:
        return payload
    payload['owner_id']=owner['id'] if owner else ''
    payload['telegram_id']=owner['telegram_id'] if owner else ''
    if not owner: return payload
    if owner['max_devices']:
        mine=owner_devices(manager).get(owner['id'],[])
        here={d['name'] for d in mine if d['interface']==iface}
        if op=='add': new=1
        elif op=='client-batch': new=len([n for n in payload.get('names') or [] if n not in here])
        else: new=0 if str(payload.get('name','')) in here else 1
        if len(mine)+new>owner['max_devices']:
            raise ValueError(f'У владельца «{owner["name"]}» уже {len(mine)} из {owner["max_devices"]} устройств')
    return payload


def owners_sample(manager, usage, now=None):
    """After every sample: add the traffic, start a new month, and work out who is blocked now.
    Returns the new blocked map and the owners whose state changed."""
    if not owners_db().exists() and not usage: return {'blocked':{},'changed':[]}
    now=now or datetime.now(timezone.utc)
    month=now.strftime('%Y-%m')
    with _OwnersLock():
        con,_=_owners_open()
        try:
            for owner_id,amount in (usage or {}).items():
                if OWNER_ID.fullmatch(str(owner_id)) and int(amount)>0:
                    con.execute('UPDATE owners SET used_bytes=used_bytes+? WHERE id=?',(int(amount),owner_id))
            changed=[]
            for row in con.execute('SELECT * FROM owners').fetchall():
                if row['quota_period']=='monthly' and row['quota_month']!=month:
                    con.execute('UPDATE owners SET quota_month=?, used_bytes=? WHERE id=?',
                                (month,0 if row['quota_month'] else row['used_bytes'],row['id']))
                    row=con.execute('SELECT * FROM owners WHERE id=?',(row['id'],)).fetchone()
                state=_owner_state(row,now)
                if state!=row['blocked']:
                    con.execute('UPDATE owners SET blocked=? WHERE id=?',(state,row['id']))
                    changed.append({'id':row['id'],'name':row['name'],'telegram_id':row['telegram_id'],'from':row['blocked'],'to':state})
            con.commit()
            blocked={r['id']:r['blocked'] for r in con.execute("SELECT id,blocked FROM owners WHERE blocked<>''")}
        finally: con.close()
    return {'blocked':blocked,'changed':changed}


def _device_name(owner, kind, taken):
    slug=re.sub(r'[^a-z0-9]+','-',owner['name'].lower()).strip('-')[:16].strip('-')
    if not slug or slug.startswith('telegram'): slug='user'
    for n in range(1,1000):
        name=f'{slug}-{kind}' if n==1 else f'{slug}-{kind}-{n}'
        if name not in taken: return name
    raise ValueError('Не удалось подобрать имя устройства')


def owner_device_add(manager, data):
    """A new device for an owner. From the bot (telegram_id of the person asking): only when the
    administrator allowed it, within the maximum, and while the owner is not blocked."""
    kind=str(data.get('kind','phone'))
    if kind not in OWNER_KINDS: raise ValueError('Неверный тип устройства')
    by_bot='telegram_id' in data
    with _OwnersLock():
        owner=owner_by_telegram(data.get('telegram_id')) if by_bot else owner_get(data.get('owner_id'))
        if not owner: raise ValueError('Владелец не найден')
        if by_bot and not owner['self_add']: raise ValueError('Добавлять устройства самому не разрешено')
        if by_bot and not owner['max_devices']: raise ValueError('Для владельца не задан максимум устройств')
        if owner['blocked']: raise ValueError('У владельца исчерпан общий лимит или истёк срок')
        mine=owner_devices(manager).get(owner['id'],[])
        if owner['max_devices'] and len(mine)>=owner['max_devices']:
            raise ValueError(f'Уже {len(mine)} из {owner["max_devices"]} устройств')
        servers=manager.interfaces()
        iface=str(data.get('interface') or owner['home_server'] or (servers[0] if servers else ''))
        if iface not in servers: raise ValueError('Сервер не найден')
        with sqlite3.connect(f'file:{manager.db_path(iface)}?mode=ro',uri=True,timeout=10) as db:
            taken={row[0] for row in db.execute('SELECT name FROM clients')}
        name=str(data.get('name') or '') or _device_name(owner,kind,taken)
        comment='Добавлено владельцем в Telegram' if by_bot else str(data.get('comment','') or '')
        created=manager.child(iface,'add',{'name':name,'owner_id':owner['id'],'telegram_id':owner['telegram_id'],
                                           'owner_export':bool(owner['telegram_id']) and (by_bot or bool(data.get('owner_export'))),
                                           'comment':comment})
    audit({'event':'client_added','target':f'{iface}/{name} (owner {owner["id"]}{", telegram" if by_bot else ""})'[:120]})
    return {'ok':True,'interface':iface,'name':name,'owner':owner['name'],'config':created.get('config','')}


# ------------------------------------------------------------------ 0.21: clients from other panels
IMPORT_SOURCES=('wg-easy-15','wg-easy-14','3x-ui','amnezia','conf')
IMPORT_MAX=500


def clients_import(manager, iface, data):
    """Records read by the panel (awg31import.py) become clients of one server. Owners named in the
    records are found or made first, so the devices of one person stay together."""
    clients=data.get('clients'); owners=data.get('owners') or []
    if not isinstance(clients,list) or not 1<=len(clients)<=IMPORT_MAX: raise ValueError(f'Импорт: от 1 до {IMPORT_MAX} клиентов')
    if not isinstance(owners,list) or len(owners)>IMPORT_MAX: raise ValueError('Импорт: неверный список владельцев')
    source=str(data.get('source',''))
    if source not in IMPORT_SOURCES: raise ValueError('Импорт: неизвестный источник')
    make_owners=data.get('create_owners') is not False
    made=0
    with _OwnersLock():
        con,_=_owners_open()
        try:
            by_name={}
            if make_owners:
                for item in owners:
                    if not isinstance(item,dict): raise ValueError('Импорт: неверный владелец')
                    fields=_owner_fields({**item,'self_add':False,'home_server':''},None,manager)
                    row=con.execute('SELECT id FROM owners WHERE name=? COLLATE NOCASE',(fields['name'],)).fetchone()
                    if not row and fields['telegram_id']:
                        row=con.execute('SELECT id FROM owners WHERE telegram_id=?',(fields['telegram_id'],)).fetchone()
                    if row: by_name[str(item.get('name','')).lower()]=row['id']; continue
                    owner_id=_owner_insert(con,fields); made+=1
                    con.execute('UPDATE owners SET blocked=? WHERE id=?',(_owner_state(con.execute('SELECT * FROM owners WHERE id=?',(owner_id,)).fetchone()),owner_id))
                    by_name[str(item.get('name','')).lower()]=owner_id
            telegram_owner={r['telegram_id']:r['id'] for r in con.execute("SELECT id,telegram_id FROM owners WHERE telegram_id<>''")}
            telegram_of={r['id']:r['telegram_id'] for r in con.execute('SELECT id,telegram_id FROM owners')}
            prepared=[]
            for item in clients:
                if not isinstance(item,dict): raise ValueError('Импорт: неверная запись')
                record={k:item.get(k) for k in ('name','private_key','public_key','psk','address','enabled','expires_at',
                                                'traffic_limit_bytes','quota_period','comment','group')}
                owner_id=''
                if make_owners:
                    owner_id=by_name.get(str(item.get('owner') or '').lower(),'')
                    telegram=str(item.get('telegram_id') or '')
                    if not owner_id and OWNER_TELEGRAM.fullmatch(telegram):
                        owner_id=telegram_owner.get(telegram,'')
                        if not owner_id:
                            owner_id=_owner_insert(con,{'name':f'Telegram {telegram}','telegram_id':telegram}); made+=1
                            telegram_owner[telegram]=owner_id; telegram_of[owner_id]=telegram
                record['owner_id']=owner_id
                record['telegram_id']=telegram_of.get(owner_id,'') if owner_id else ''
                prepared.append(record)
            con.commit()
            blocked={r['id']:r['blocked'] for r in con.execute("SELECT id,blocked FROM owners WHERE blocked<>''")}
        finally: con.close()
    result=manager.child(iface,'import-batch',{'clients':prepared,'keep_keys':data.get('keep_keys') is not False,
                                               'keep_addresses':data.get('keep_addresses') is not False,'owners_blocked':blocked})
    audit({'event':'clients_imported','target':f'{iface}: {len(result.get("created",[]))} clients from {source}'})
    return {**result,'owners_created':made}
