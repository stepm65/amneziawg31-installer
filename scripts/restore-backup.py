#!/usr/bin/env python3
"""Offline, root-only recovery of awg31-backup-v1 archives.

Usage: restore-backup.py --check NAME | --apply NAME
The --apply operation must be run outside the panel process (systemd-run).
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile

BACKUP_DIR=Path(os.environ.get('AWG31_BACKUP_DIR','/var/backups/awg31-panel/full'))
BASE=Path(os.environ.get('AWG31_ROOT','/var/lib/awg31-panel'))
CONF=Path(os.environ.get('AWG31_CONFIG_DIR','/etc/amnezia/amneziawg'))
AUTH=Path(os.environ.get('AWG31_AUTH','/etc/awg31-panel/auth.json'))
VALID_NAME=re.compile(r'^awg31-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\.tar\.gz$')
VALID_IFACE=re.compile(r'^awg(?:0|[1-9][0-9]?)$')
MAX_ARCHIVE=20*1024*1024
MAX_CONTENT=20*1024*1024


def execute(*args,check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=90)


def validate(name):
    if not VALID_NAME.fullmatch(name):raise ValueError('Invalid backup name')
    path=BACKUP_DIR/name
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_ARCHIVE:
        raise ValueError('Backup missing or oversized')
    try:
        with tarfile.open(path,'r:gz') as tf:
            members=tf.getmembers()
            if len(members)>210:raise ValueError('Too many files in backup')
            raw={}
            total_size=0
            for m in members:
                if not m.isfile() or m.name in raw or m.size<0 or m.size>MAX_CONTENT:
                    raise ValueError('Unsafe backup archive member')
                if not (m.name=='manifest.json' or m.name=='auth/auth.json' or
                        re.fullmatch(r'configs/awg(?:0|[1-9][0-9]?)\.conf',m.name) or
                        re.fullmatch(r'databases/awg(?:0|[1-9][0-9]?)\.sqlite3',m.name)):
                    raise ValueError('Unexpected backup path')
                total_size+=m.size
                if total_size>48*1024*1024:raise ValueError('Backup uncompressed size limit exceeded')
                stream=tf.extractfile(m)
                if stream is None:raise ValueError('Unreadable archive member')
                raw[m.name]=stream.read(MAX_CONTENT+1)
                if len(raw[m.name])!=m.size:raise ValueError('File size mismatch')
            manifest=json.loads(raw['manifest.json'])
    except (KeyError,tarfile.TarError,UnicodeError) as e:
        raise ValueError('Invalid backup archive') from e
    if manifest.get('format')!='awg31-backup-v1':raise ValueError('Unsupported backup format')
    ifaces=manifest.get('interfaces')
    if not isinstance(ifaces,list) or not ifaces or len(set(ifaces))!=len(ifaces) or len(ifaces)>8 or any(not isinstance(x,str) or not VALID_IFACE.fullmatch(x) for x in ifaces):
        raise ValueError('Invalid server inventory')
    required={'auth/auth.json'}|{f'configs/{x}.conf' for x in ifaces}|{f'databases/{x}.sqlite3' for x in ifaces}
    digests=manifest.get('files')
    if not isinstance(digests,dict) or set(digests)!=required or set(raw)!=(required|{'manifest.json'}):
        raise ValueError('Backup manifest does not match files')
    for key in required:
        if not isinstance(digests[key],str) or hashlib.sha256(raw[key]).hexdigest()!=digests[key]:
            raise ValueError('Backup checksum mismatch')
    auth=json.loads(raw['auth/auth.json'])
    if not isinstance(auth,dict) or not all(k in auth for k in ('salt','password_hash','session_key')):
        raise ValueError('Invalid backup authentication file')
    with tempfile.TemporaryDirectory(prefix='awg31-restore-verify-') as temp:
        for iface in ifaces:
            cfg=raw[f'configs/{iface}.conf']
            if b'[Interface]' not in cfg or b'PrivateKey' not in cfg:
                raise ValueError('Invalid interface configuration')
            db=Path(temp)/(iface+'.sqlite3')
            db.write_bytes(raw[f'databases/{iface}.sqlite3'])
            con=sqlite3.connect(f'file:{db}?mode=ro',uri=True)
            try:
                if con.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Corrupt SQLite database')
                names={row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {'clients','config'}.issubset(names):raise ValueError('Unsupported SQLite schema')
            finally:con.close()
    return manifest,raw


def target_files(ifaces):
    result={'auth/auth.json':AUTH}
    for x in ifaces:
        result[f'configs/{x}.conf']=CONF/(x+'.conf')
        result[f'databases/{x}.sqlite3']=BASE/'state.sqlite3' if x=='awg0' else BASE/'servers'/(x+'.sqlite3')
    return result


def atomic_write(path,data,mode,owner=None):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix='.awg31-restore-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)
            if owner:os.fchown(f.fileno(),*owner)
        os.replace(temp,path)
    finally:
        Path(temp).unlink(missing_ok=True)


def apply(name):
    manifest,raw=validate(name)
    ifaces=manifest['interfaces']
    desired=target_files(ifaces)
    # An old archive must not bring back an old administrator password or
    # session key: panel credentials are restored only when none exist.
    if AUTH.exists():
        desired.pop('auth/auth.json')
    # Refuse to remove additional interfaces in an unrecognized current inventory.
    existing={p.stem for p in CONF.glob('awg*.conf') if VALID_IFACE.fullmatch(p.stem)}
    if existing-set(ifaces):
        raise ValueError('Backup lacks existing interfaces: '+', '.join(sorted(existing-set(ifaces))))
    # Safety snapshot of all current files BEFORE modifying anything.
    import importlib.util
    module_path=Path('/usr/local/sbin/awg31admin.py')
    spec=importlib.util.spec_from_file_location('awg31admin_recovery',module_path)
    if not spec or not spec.loader:raise ValueError('Installed admin module not found')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    from importlib.machinery import SourceFileLoader
    manager=SourceFileLoader('awg31mgr_recovery','/usr/local/sbin/awg31mgr').load_module()
    # The safety snapshot must never be refused because the archive limit is
    # reached: that would make restoring impossible exactly when 30 copies exist.
    safe_copy=mod.create_backup(manager, enforce_limit=False)
    prior={}
    owners={}
    for key,path in target_files(sorted(existing)).items():
        if path.exists():
            prior[key]=path.read_bytes()
            stat=path.stat();owners[key]=(stat.st_uid,stat.st_gid,stat.st_mode & 0o777)
    # Existing service state matters: don't silently enable previously stopped interfaces.
    active={iface:execute('systemctl','is-active','--quiet',f'awg-quick@{iface}.service',check=False).returncode==0 for iface in ifaces}
    # On an empty destination we must start the restored instances; on existing destination only restart ones formerly up.
    if not existing:active={iface:True for iface in ifaces}
    panel_running=execute('systemctl','is-active','--quiet','awg31-panel.service',check=False).returncode==0
    changed=[]
    def stop_services():
        execute('systemctl','stop','awg31-sampler.timer',check=False)
        for iface in reversed(ifaces):execute('systemctl','stop',f'awg-quick@{iface}.service',check=False)
        execute('systemctl','stop','awg31-panel.service',check=False)
    try:
        stop_services()
        # An older SQLite WAL must not be replayed into the restored database.
        for key,path in desired.items():
            if key.startswith('databases/') and path.exists():
                with sqlite3.connect(path) as connection:
                    connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                for suffix in ('-wal','-shm'):
                    (Path(str(path)+suffix)).unlink(missing_ok=True)
        for key,path in desired.items():
            old=owners.get(key)
            owner=(old[0],old[1]) if old else (0,0)
            mode=old[2] if old else (0o640 if key=='auth/auth.json' else 0o600)
            if key=='auth/auth.json' and not old:
                import pwd
                owner=(0,pwd.getpwnam('awgpanel').pw_gid)
            atomic_write(path,raw[key],mode,owner)
            changed.append(key)
        for iface in ifaces:
            if active[iface]:execute('systemctl','start',f'awg-quick@{iface}.service')
        if panel_running:execute('systemctl','start','awg31-panel.service')
        execute('systemctl','start','awg31-sampler.timer',check=False)
    except Exception:
        stop_services()
        for key in changed:
            path=desired[key]
            if key in prior:
                old=owners[key];atomic_write(path,prior[key],old[2],old[:2])
            else:path.unlink(missing_ok=True)
        for iface in ifaces:
            if active[iface]:execute('systemctl','start',f'awg-quick@{iface}.service',check=False)
        if panel_running:execute('systemctl','start','awg31-panel.service',check=False)
        execute('systemctl','start','awg31-sampler.timer',check=False)
        raise
    print(json.dumps({'ok':True,'restored':name,'pre_restore_backup':safe_copy['name'],'interfaces':ifaces}))


def main():
    if os.geteuid()!=0:raise PermissionError('Root required')
    parser=argparse.ArgumentParser()
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check',metavar='NAME')
    modes.add_argument('--apply',metavar='NAME')
    args=parser.parse_args()
    name=args.check or args.apply
    if args.check:
        man,_=validate(name)
        print(json.dumps({'ok':True,'name':name,'interfaces':man['interfaces'],'created_at':man['created_at']}))
    else:apply(name)

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('ERROR: '+str(exc),file=sys.stderr);sys.exit(1)
