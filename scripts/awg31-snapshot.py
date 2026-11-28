#!/usr/bin/env python3
"""Snapshots of the installed console, taken before every update, and the rollback to one.

  awg31-snapshot.py create --reason upgrade [--to 0.16.1]   print the new snapshot's path
  awg31-snapshot.py list [--json]
  awg31-snapshot.py restore NAME|latest [--no-snapshot]

A snapshot holds the program: the panel without its virtualenv, the controller,
the helper, the menu, the scripts, the sudo rules and the static systemd units.
The databases and server configurations are copied next to it as recovery
material, but a rollback does not put them back: clients made after the update
stay, and a newer schema only has columns the older code does not read.
The panel's own unit (its port) is left as it is.
"""
import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get('AWG31_SNAPSHOT_ROOT', '/'))
BACKUPS = ROOT / 'var/backups'
PREFIX = 'awg31-upgrade.'
KEEP = 5
APP = 'opt/awg31-panel'
FILES = ('usr/local/sbin/awg31ctl', 'usr/local/sbin/awg31mgr', 'usr/local/sbin/awg31admin.py',
         'usr/local/sbin/awg31helper', 'usr/local/bin/awg31',
         'etc/sudoers.d/awg31-panel', 'etc/sudoers.d/awg31-bot', 'etc/logrotate.d/awg31-panel')
DIRS = ('usr/local/libexec/awg31',)
UNIT_DIR = 'etc/systemd/system'
UNIT_RE = re.compile(r'^awg31-[a-z-]+\.(service|timer)$')
SKIP_UNITS = {'awg31-panel.service'}          # generated at installation: it carries the port
ALLOWED = (APP + '/', *(f + '' for f in FILES), *(d + '/' for d in DIRS), UNIT_DIR + '/awg31-')
NAME_RE = re.compile(r'^awg31-upgrade\.[A-Za-z0-9_.-]{4,64}$')


def say(text):
    print(f'[AWG31 rollback] {text}', flush=True)


def installed_version():
    try:
        text = (ROOT / APP / 'VERSION').read_text().strip()
    except OSError:
        return ''
    return text if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', text) else ''


def code_members():
    """Relative paths of everything that belongs to the program."""
    out = []
    app = ROOT / APP
    if app.is_dir():
        for path in sorted(app.rglob('*')):
            rel = path.relative_to(app)
            if rel.parts[0] == '.venv' or '__pycache__' in rel.parts or path.is_dir():
                continue
            out.append(str(Path(APP) / rel))
    for name in FILES:
        if (ROOT / name).is_file():
            out.append(name)
    for name in DIRS:
        base = ROOT / name
        if base.is_dir():
            out.extend(str(p.relative_to(ROOT)) for p in sorted(base.rglob('*'))
                       if p.is_file() and '__pycache__' not in p.parts)
    units = ROOT / UNIT_DIR
    if units.is_dir():
        out.extend(f'{UNIT_DIR}/{p.name}' for p in sorted(units.iterdir())
                   if UNIT_RE.match(p.name) and p.name not in SKIP_UNITS and p.is_file())
    return out


def snapshots():
    """Every snapshot directory, newest first; those without a manifest are older recovery copies."""
    found = []
    if not BACKUPS.is_dir():
        return found
    for path in BACKUPS.iterdir():
        if not path.is_dir() or not NAME_RE.match(path.name):
            continue
        manifest = {}
        try:
            manifest = json.loads((path / 'manifest.json').read_text())
        except (OSError, ValueError):
            pass
        usable = bool(manifest.get('format') == 1 and (path / 'code.tar').is_file() and manifest.get('version'))
        created = manifest.get('created') or datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(timespec='seconds')
        found.append({'name': path.name, 'version': manifest.get('version', ''), 'to': manifest.get('to', ''),
                      'reason': manifest.get('reason', ''), 'created': created, 'usable': usable})
    found.sort(key=lambda item: (item['created'], item['name']), reverse=True)
    return found


def prune(keep=KEEP, protect=()):
    for item in snapshots()[keep:]:
        if item['name'] in protect:
            continue
        shutil.rmtree(BACKUPS / item['name'], ignore_errors=True)


def create(reason, to='', protect=()):
    BACKUPS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    target = Path(tempfile.mkdtemp(prefix=f'{PREFIX}{stamp}-', dir=BACKUPS))
    target.chmod(0o700)
    members = code_members()
    with tarfile.open(target / 'code.tar', 'w') as archive:
        for rel in members:
            archive.add(str(ROOT / rel), arcname=rel, recursive=False)
    (target / 'code.tar').chmod(0o600)
    # Recovery material, as before: the databases and the server configurations.
    base = ROOT / 'var/lib/awg31-panel'
    for source in [base / 'state.sqlite3', base / 'owners.sqlite3', *sorted((base / 'servers').glob('awg*.sqlite3'))]:
        if source.is_file():
            dest = target / 'databases' / source.name
            dest.parent.mkdir(exist_ok=True)
            with sqlite3.connect(source) as src, sqlite3.connect(dest) as dst:
                src.backup(dst)
            dest.chmod(0o600)
    for source in sorted((ROOT / 'etc/amnezia/amneziawg').glob('awg*.conf')):
        dest = target / 'configs' / source.name
        dest.parent.mkdir(exist_ok=True)
        shutil.copy2(source, dest)
        dest.chmod(0o600)
    manifest = {'format': 1, 'version': installed_version(), 'to': to, 'reason': reason,
                'created': datetime.now(timezone.utc).isoformat(timespec='microseconds'), 'files': len(members)}
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    prune(protect={target.name, *protect})
    return target


def safe_members(archive):
    for member in archive.getmembers():
        name = member.name
        if (name.startswith('/') or '..' in Path(name).parts or not (member.isfile() or member.isdir())
                or not any(name == prefix or name.startswith(prefix) for prefix in ALLOWED)):
            raise SystemExit(f'Refusing a snapshot with an unexpected entry: {name!r}')
    return archive.getmembers()


def panel_port():
    try:
        unit = (ROOT / UNIT_DIR / 'awg31-panel.service').read_text()
    except OSError:
        return 0
    found = re.findall(r'--port\s+([0-9]+)', unit)
    return int(found[-1]) if found else 0


def panel_healthy(seconds=60):
    port = panel_port()
    if not port:
        return False
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=4) as reply:
                if reply.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


def systemctl(*args):
    if ROOT != Path('/'):
        return 0
    return subprocess.run(['systemctl', *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def audit(event, target):
    if ROOT != Path('/'):
        return
    try:
        subprocess.run(['/usr/local/sbin/awg31mgr', 'audit'], input=json.dumps({'event': event, 'target': target}),
                       text=True, capture_output=True, timeout=30)
    except Exception:
        pass


def restore(name, take_snapshot=True):
    items = snapshots()
    if name == 'latest':
        usable = [item for item in items if item['usable']]
        if not usable:
            raise SystemExit('There is no snapshot to roll back to. Snapshots are taken by updates made with version 0.16 or newer.')
        name = usable[0]['name']
    if not NAME_RE.match(name):
        raise SystemExit(f'Invalid snapshot name: {name}')
    item = next((x for x in items if x['name'] == name), None)
    if not item:
        raise SystemExit(f'No such snapshot: {name}')
    if not item['usable']:
        raise SystemExit(f'{name} was made by an older version and holds only part of the program; it cannot be restored automatically.')
    source = BACKUPS / name
    before = installed_version()
    with tarfile.open(source / 'code.tar') as archive:
        members = safe_members(archive)
        staging = Path(tempfile.mkdtemp(prefix='awg31-rollback.'))
        try:
            archive.extractall(staging, members=members)
            for sudoers in ('etc/sudoers.d/awg31-panel', 'etc/sudoers.d/awg31-bot'):
                path = staging / sudoers
                if path.is_file() and ROOT == Path('/') and shutil.which('visudo'):
                    check = subprocess.run(['visudo', '-cqf', str(path)], capture_output=True, text=True)
                    if check.returncode != 0:
                        raise SystemExit(f'The sudo rule in the snapshot is invalid: {check.stderr.strip()}')
            undo = create(f'before rollback to {item["version"]}', item['version'], protect=(name,)) if take_snapshot else None
            if undo:
                say(f'The current state is saved too: {undo.name} (sudo awg31 rollback {undo.name} returns to it)')
            say(f'Restoring {item["version"]} from {name}')
            try:
                replace_program(members, staging)
            except Exception:
                if undo:
                    say(f'Restoring failed; returning to {undo.name}')
                    restore(undo.name, take_snapshot=False)
                raise
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    finish(item, before, undo)
    return item['version']


def replace_program(members, staging):
    # The program is replaced as a whole: files a newer version added are removed.
    app = ROOT / APP
    if app.is_dir():
        for entry in app.iterdir():
            if entry.name == '.venv':
                continue
            shutil.rmtree(entry) if entry.is_dir() and not entry.is_symlink() else entry.unlink()
    for rel in DIRS:
        shutil.rmtree(ROOT / rel, ignore_errors=True)
    saved_units = {Path(m.name).name for m in members if m.name.startswith(UNIT_DIR + '/')}
    units = ROOT / UNIT_DIR
    if units.is_dir():
        for unit in units.iterdir():
            if UNIT_RE.match(unit.name) and unit.name not in SKIP_UNITS and unit.name not in saved_units:
                systemctl('disable', '--now', unit.name)
                unit.unlink()
    for member in members:
        if not member.isfile():
            continue
        src, dst = staging / member.name, ROOT / member.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_name('.' + dst.name + '.awg31-new')
        shutil.copyfile(src, tmp)
        os.chmod(tmp, member.mode & 0o7777)
        if ROOT == Path('/'):
            os.chown(tmp, member.uid, member.gid)
        os.replace(tmp, dst)


def finish(item, before, undo):
    """Start the restored program; if the panel does not come up, go back to where we were."""
    systemctl('daemon-reload')
    systemctl('restart', 'awg31-helper.service')
    systemctl('restart', 'awg31-panel.service')
    if systemctl('is-enabled', '--quiet', 'awg31-bot.service') == 0:
        systemctl('restart', 'awg31-bot.service')
    for timer in ('awg31-sampler.timer', 'awg31-kernel-check.timer'):
        if (ROOT / UNIT_DIR / timer).exists():
            systemctl('enable', '--now', timer)
    if ROOT == Path('/') and not panel_healthy():
        say('The panel did not start with the restored version')
        if undo:
            say(f'Returning to the state before the rollback ({undo.name})')
            restore(undo.name, take_snapshot=False)
        audit('panel_update_failed', f'rollback to {item["version"]}')
        raise SystemExit(1)
    audit('panel_rolled_back', f'{before or "?"} → {item["version"]}')
    say(f'Rolled back: {before or "?"} → {item["version"]}. VPN interfaces, keys and clients were not touched.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    c = sub.add_parser('create')
    c.add_argument('--reason', default='manual')
    c.add_argument('--to', default='')
    l = sub.add_parser('list')
    l.add_argument('--json', action='store_true')
    r = sub.add_parser('restore')
    r.add_argument('name')
    r.add_argument('--no-snapshot', action='store_true')
    args = parser.parse_args(argv)
    if ROOT == Path('/') and os.geteuid() != 0:
        raise SystemExit('Run as root')
    if args.command == 'create':
        print(create(args.reason, args.to))
    elif args.command == 'list':
        items = snapshots()
        if args.json:
            print(json.dumps(items))
        elif not items:
            print('No snapshots yet: one is taken before every update.')
        else:
            for item in items:
                label = f'v{item["version"]}' if item['version'] else 'older copy (partial)'
                why = f'before the update to {item["to"]}' if item['reason'] == 'upgrade' and item['to'] else item['reason']
                print(f'{item["name"]:52} {item["created"]:26} {label:12} {why}')
    else:
        restore(args.name, take_snapshot=not args.no_snapshot)


if __name__ == '__main__':
    sys.exit(main())
