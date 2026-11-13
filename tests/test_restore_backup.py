import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile

import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('restore_awg31',ROOT/'scripts/restore-backup.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)


def make_archive(tmp_path,*,invalid_checksum=False,extra_path=None):
    archive_name='awg31-20261113T010203Z-0123456789.tar.gz'
    db=tmp_path/'source.sqlite3'
    with sqlite3.connect(db) as con:
        con.execute('CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)')
        con.execute('CREATE TABLE clients (name TEXT PRIMARY KEY)')
        con.execute('INSERT INTO clients VALUES (?)',('alice',))
    raw={'auth/auth.json':json.dumps({'salt':'a','password_hash':'b','session_key':'c'}).encode(),
         'configs/awg0.conf':b'[Interface]\nPrivateKey = dummy\n',
         'databases/awg0.sqlite3':db.read_bytes()}
    manifest={'format':'awg31-backup-v1','created_at':'2026-11-13T01:02:03Z','interfaces':['awg0'],
              'files':{k:hashlib.sha256(v).hexdigest() for k,v in raw.items()}}
    if invalid_checksum:manifest['files']['configs/awg0.conf']='0'*64
    raw['manifest.json']=json.dumps(manifest).encode()
    if extra_path:raw[extra_path]=b'attack'
    f=tmp_path/archive_name
    with tarfile.open(f,'w:gz') as tar:
        for path,data in raw.items():
            info=tarfile.TarInfo(path);info.size=len(data)
            tar.addfile(info,io.BytesIO(data))
    return archive_name


def test_valid_archive_is_verified_without_changes(tmp_path,monkeypatch):
    monkeypatch.setattr(mod,'BACKUP_DIR',tmp_path)
    name=make_archive(tmp_path)
    mf,contents=mod.validate(name)
    assert mf['interfaces']==['awg0']
    assert b'alice' in contents['databases/awg0.sqlite3']


def test_reject_modified_checksums(tmp_path,monkeypatch):
    monkeypatch.setattr(mod,'BACKUP_DIR',tmp_path)
    with pytest.raises(ValueError,match='checksum'):
        mod.validate(make_archive(tmp_path,invalid_checksum=True))


def test_reject_unsafe_member(tmp_path,monkeypatch):
    monkeypatch.setattr(mod,'BACKUP_DIR',tmp_path)
    with pytest.raises(ValueError,match='Unexpected backup path'):
        mod.validate(make_archive(tmp_path,extra_path='../../etc/shadow'))


def test_reject_traversal_name(tmp_path,monkeypatch):
    monkeypatch.setattr(mod,'BACKUP_DIR',tmp_path)
    with pytest.raises(ValueError,match='Invalid backup name'):
        mod.validate('../bad.tar.gz')


def test_reject_corrupt_database(tmp_path,monkeypatch):
    monkeypatch.setattr(mod,'BACKUP_DIR',tmp_path)
    name=make_archive(tmp_path)
    archive=tmp_path/name
    with tarfile.open(archive,'r:gz') as tar:
        contents={m.name:tar.extractfile(m).read() for m in tar.getmembers()}
    contents['databases/awg0.sqlite3']=b'not sqlite'
    manifest=json.loads(contents['manifest.json'])
    manifest['files']['databases/awg0.sqlite3']=hashlib.sha256(contents['databases/awg0.sqlite3']).hexdigest()
    contents['manifest.json']=json.dumps(manifest).encode()
    with tarfile.open(archive,'w:gz') as tar:
        for path,data in contents.items():
            info=tarfile.TarInfo(path);info.size=len(data);tar.addfile(info,io.BytesIO(data))
    with pytest.raises(sqlite3.DatabaseError):
        mod.validate(name)
