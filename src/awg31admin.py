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

VALID_BACKUP = re.compile(r'^awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz(?:\.gpg)?$')
VALID_AUDIT = {'login_success', 'login_failed', 'password_changed', 'client_added',
               'client_modified', 'client_deleted', 'client_enabled', 'client_disabled',
               'server_created', 'server_started', 'server_stopped', 'server_restarted', 'server_deleted', 'logout',
               'server_settings_changed', 'profile_imported', 'backup_created',
               'backup_downloaded', 'backup_deleted', 'backup_policy_changed', 'backup_pruned',
               'backup_failed', 'client_config_sent', 'totp_enabled', 'totp_disabled',
               'telegram_changed', 'backup_encryption_changed', 'backup_uploaded', 'backup_upload_failed',
               'backup_remote_changed'}


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


def session_revoke():
    """Sign out everywhere: cookies issued before this moment stop working.

    The panel is stateless (signed cookies), so logging out has to change the
    version every cookie is checked against.
    """
    file=auth_file(); auth=json.loads(file.read_text())
    _save_auth(auth,file)
    audit({'event':'logout'})
    return {'ok':True}


def _store_password(auth, new, file):
    """Write a new scrypt hash atomically and expire every issued session."""
    salt=secrets.token_bytes(16)
    auth['salt']=salt.hex()
    auth['password_hash']=hashlib.scrypt(new.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32).hex()
    _save_auth(auth,file)


def _save_auth(auth, file):
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


def totp_enable(data):
    """Turn on the second factor: needs the password and a code from the new secret."""
    secret=str(data.get('secret','')).strip().upper()
    if not re.fullmatch(r'[A-Z2-7]{32}',secret): raise ValueError('Invalid TOTP secret')
    file=auth_file(); auth=json.loads(file.read_text())
    if not _password_ok(auth,data.get('password','')): raise ValueError('Incorrect password')
    if totp_counter_for(secret,data.get('code','')) is None:
        raise ValueError('The code does not match: check the clock of the server and of the phone')
    auth['totp_secret']=secret
    _save_auth(auth,file)
    audit({'event':'totp_enabled'})
    return {'ok':True}


def totp_disable(data):
    file=auth_file(); auth=json.loads(file.read_text())
    if not auth.get('totp_secret'): return {'ok':True}
    if not _password_ok(auth,data.get('password','')): raise ValueError('Incorrect password')
    if totp_counter_for(auth['totp_secret'],data.get('code','')) is None: raise ValueError('Incorrect code')
    auth.pop('totp_secret',None)
    _save_auth(auth,file)
    audit({'event':'totp_disabled'})
    return {'ok':True}


def totp_reset():
    """Console recovery (`sudo awg31 totp-off`): root only, not in any sudoers list."""
    file=auth_file(); auth=json.loads(file.read_text())
    auth.pop('totp_secret',None)
    _save_auth(auth,file)
    audit({'event':'totp_disabled','target':'console reset'})
    return {'ok':True}


# ---- Telegram bot settings shown and edited in the panel (never the token) ----
def bot_config_file():
    return Path(os.environ.get('AWG31_BOT_CONFIG','/etc/awg31-bot/telegram.json'))


NOTIFY_GROUPS=('server','clients','security','backups')


def _id_list(value, limit):
    if isinstance(value,str): value=[x for x in re.split(r'[\s,;]+',value) if x]
    if not isinstance(value,list) or len(value)>limit: raise ValueError('Too many Telegram IDs')
    result=[]
    for item in value:
        if not re.fullmatch(r'[1-9][0-9]{2,14}',str(item)): raise ValueError('Telegram ID: digits only (a numeric user ID, not a @name)')
        if int(item) not in result: result.append(int(item))
    return result


def telegram_status():
    file=bot_config_file()
    if not file.is_file(): return {'configured':False}
    config=json.loads(file.read_text())
    try:
        active=subprocess.run(['systemctl','is-active','awg31-bot.service'],capture_output=True,text=True,timeout=10).stdout.strip()
    except (OSError,subprocess.TimeoutExpired): active='unknown'
    notify=config.get('notify') or {}
    return {'configured':True,'active':active,'admins':[int(x) for x in config.get('admins',[])],
            'viewers':[int(x) for x in config.get('viewers',[])],'lang':config.get('lang','ru'),
            'notify':{g:bool(notify.get(g,True)) for g in NOTIFY_GROUPS},
            'digest':config.get('digest','off') if config.get('digest') in ('daily','weekly') else 'off'}


def telegram_set(data):
    file=bot_config_file()
    if not file.is_file(): raise ValueError('The bot is not connected: run sudo awg31 telegram on the server')
    config=json.loads(file.read_text())
    admins=_id_list(data.get('admins',config.get('admins',[])),10)
    if not admins: raise ValueError('At least one administrator is required')
    viewers=[x for x in _id_list(data.get('viewers',config.get('viewers',[])),20) if x not in admins]
    lang=str(data.get('lang',config.get('lang','ru')))
    if lang not in ('ru','en'): raise ValueError('Language: ru or en')
    digest=str(data.get('digest',config.get('digest','off')))
    if digest not in ('off','daily','weekly'): raise ValueError('Digest: off, daily or weekly')
    notify=data.get('notify',config.get('notify') or {})
    if not isinstance(notify,dict): raise ValueError('Invalid notification settings')
    config.update({'admins':admins,'viewers':viewers,'lang':lang,'digest':digest,
                   'notify':{g:bool(notify.get(g,False)) for g in NOTIFY_GROUPS}})
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
    subprocess.run(['systemctl','restart','awg31-bot.service'],capture_output=True,timeout=30,check=False)
    audit({'event':'telegram_changed','target':f'{len(admins)} admin(s), {len(viewers)} viewer(s)'})
    return {'ok':True}


# ---- Backup encryption: one passphrase, standard OpenPGP symmetric encryption ----
def backup_key_file():
    return Path(os.environ.get('AWG31_BACKUP_KEY','/etc/awg31-panel/backup-passphrase'))


def backup_encryption():
    return {'enabled':backup_key_file().is_file()}


def backup_encryption_set(data):
    """Root console only. Returns a generated passphrase exactly once."""
    file=backup_key_file()
    if data.get('off') is True:
        file.unlink(missing_ok=True)
        audit({'event':'backup_encryption_changed','target':'off'})
        return {'ok':True,'enabled':False}
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
    """Root console only: a new passphrase, and every archive the current one opens is re-encrypted with it.

    Nothing is replaced until every archive has been re-encrypted, so a failure
    half-way leaves the old passphrase and the old archives fully intact.
    """
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
    file=auth_file(); auth=json.loads(file.read_text())
    if not _password_ok(auth,old):
        raise ValueError('Incorrect old password')
    _store_password(auth,new,file)
    audit({'event':'password_changed'})
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
