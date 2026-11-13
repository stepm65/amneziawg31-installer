"""Regression tests for installer, controller and panel fixes.

Covers the installer allowlist, primary-server obfuscation, numeric input,
password recovery, backups at the archive limit, host metrics without awg0,
client export errors, typed server deletion, I1-I5 generation and local fonts.
No test touches a real interface, systemd, sudo or the system configuration.
"""
import importlib.util
import json
import re
import sqlite3
import subprocess
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from test_workflows import ui, token  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
ctl = SourceFileLoader('awg31ctl_v093', str(ROOT / 'src' / 'awg31ctl')).load_module()


def load_admin(name='admin_v093'):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src/awg31admin.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rendered_sudo_commands():
    output = subprocess.run(
        ['bash', '-c', 'source "$1" && awg31_render_sudoers', '_', str(ROOT / 'scripts/sudoers.sh')],
        capture_output=True, text=True, check=True).stdout
    assert output.startswith('awgpanel ALL=(root) NOPASSWD: ') and output.count('\n') == 1
    assert '*' not in output and 'ALL=(ALL' not in output
    return set(re.findall(r'/usr/local/sbin/awg31mgr ([a-z-]+)', output))


# --- 2. one sudoers allowlist for every installer ---------------------------

def test_sudoers_allowlist_covers_every_command_the_panel_calls():
    allowed = rendered_sudo_commands()
    web = (ROOT / 'src/web.py').read_text()
    called = set(re.findall(r"\bctl\(\s*'([a-z-]+)'", web)) | set(re.findall(r"\bcontrol\(\s*request\s*,\s*'([a-z-]+)'", web))
    called.discard('server-')  # dynamic: 'server-' + action
    called |= {'server-start', 'server-stop', 'server-restart', 'server-delete', 'enable', 'disable', 'delete'}
    assert called <= allowed, sorted(called - allowed)
    # Regression: these were missing after a fresh install.
    assert {'backup-delete', 'backup-policy', 'backup-policy-set'} <= allowed


def test_sudoers_never_exposes_root_only_operations():
    allowed = rendered_sudo_commands()
    assert not allowed & {'init', 'sample-all', 'backup-run', 'password-reset'}
    manager = (ROOT / 'src/awg31mgr').read_text()
    for command in allowed:
        assert f"'{command}'" in manager, command


def test_installers_share_the_allowlist_instead_of_copies():
    for name in ('install.sh', 'scripts/upgrade-core.sh', 'scripts/resume-panel.sh'):
        script = (ROOT / name).read_text()
        assert 'awg31_install_sudoers' in script, name
        assert 'awgpanel ALL=' not in script, name


# --- 1. primary server obfuscation -------------------------------------------

def test_installer_requests_random_obfuscation_for_awg0():
    script = (ROOT / 'install.sh').read_text()
    assert 'AWG31_GENERATE_PARAMS=1 /usr/local/sbin/awg31ctl init' in script


def test_fresh_obfuscation_is_not_plain_wireguard():
    profile = ctl.fresh_obfuscation()
    headers = [int(profile[key]) for key in ctl.H_KEYS]
    assert len(set(headers)) == 4 and min(headers) > 4
    assert ctl.validate_obfuscation({}, {**profile, 'mtu': 1280})['H1'] == profile['H1']


def test_settings_page_warns_about_static_headers(ui):
    module, client, _ = ui
    original = module.ctl

    def static(op, data=None):
        result = original(op, data)
        if op == 'list':
            result['obfuscation'] = {'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4'}
        return result
    module.ctl = static
    assert 'obf-static-warning' in client.get('/servers/awg0/settings').text
    module.ctl = original
    assert 'obf-static-warning' not in client.get('/servers/awg0/settings').text


# --- 7. numeric input ---------------------------------------------------------

@pytest.mark.parametrize('bad', ['8_080', '+8080', '８０８０', '80.0', '', '0x50', '999999', '-1'])
def test_ports_reject_non_plain_digits(bad):
    with pytest.raises(ValueError):
        ctl.valid_port(bad)


def test_ports_and_mtu_accept_plain_values():
    assert ctl.valid_port('51820') == 51820 and ctl.valid_port(443) == 443
    assert ctl.valid_mtu(' 1280 ') == 1280
    with pytest.raises(ValueError):
        ctl.valid_mtu('1_280')


@pytest.mark.parametrize('value,ok', [('8080', True), ('8_080', False), ('+8080', False),
                                      ('８０８０', False), ('0', False), ('70000', False)])
def test_installer_number_check(value, ok):
    script = (ROOT / 'install.sh').read_text()
    function = re.search(r'need_number\(\) \{.*?\n\}', script, flags=re.S).group(0)
    run = subprocess.run(['bash', '-c', 'die(){ exit 9; }\n' + function + '\nneed_number port "$1" 1 65535', '_', value],
                         capture_output=True, text=True)
    assert (run.returncode == 0) is ok


# --- 8. password confirmation and console reset ------------------------------

def test_installer_asks_for_the_password_twice():
    script = (ROOT / 'install.sh').read_text()
    assert 'Повторите пароль' in script and 'Пароли не совпадают' in script
    assert 'reset-password' in script


def test_console_password_reset(tmp_path, monkeypatch):
    admin = load_admin('admin_reset_v093')
    auth = tmp_path / 'auth.json'
    auth.write_text(json.dumps({'salt': '00' * 16, 'password_hash': 'x', 'session_key': 'S' * 48,
                                'auth_version': 'old'}))
    monkeypatch.setenv('AWG31_AUTH', str(auth))
    monkeypatch.setenv('AWG31_AUDIT', str(tmp_path / 'audit.jsonl'))
    with pytest.raises(ValueError):
        admin.password_reset({'new_password': 'short'})
    assert admin.password_reset({'new_password': 'a-brand-new-password'}) == {'ok': True}
    stored = json.loads(auth.read_text())
    assert stored['session_key'] == 'S' * 48          # signing key kept
    assert stored['auth_version'] != 'old'            # every session expired
    assert stored['password_hash'] != 'x' and 'a-brand-new-password' not in auth.read_text()
    # The same hash the login form computes.
    import hashlib
    expected = hashlib.scrypt(b'a-brand-new-password', salt=bytes.fromhex(stored['salt']), n=2**14, r=8, p=1, dklen=32)
    assert stored['password_hash'] == expected.hex()
    assert 'console reset' in (tmp_path / 'audit.jsonl').read_text()


def test_menu_offers_reset_and_keeps_password_off_argv():
    menu = (ROOT / 'scripts/awg31-menu').read_text()
    assert 'reset-password)' in menu and 'awg31mgr password-reset' in menu
    assert "printf '%s' \"$first\"" in menu and 'password-reset "$' not in menu


# --- 3. backups at the archive limit -----------------------------------------

def test_restore_snapshot_ignores_the_manual_archive_limit():
    script = (ROOT / 'scripts/restore-backup.py').read_text()
    assert 'mod.create_backup(manager, enforce_limit=False)' in script


def test_backup_can_be_created_past_the_limit_only_when_asked(tmp_path, monkeypatch):
    admin = load_admin('admin_limit_v093')
    monkeypatch.setenv('AWG31_BACKUP_DIR', str(tmp_path / 'full'))
    monkeypatch.setenv('AWG31_AUTH', str(tmp_path / 'missing-auth.json'))
    monkeypatch.setenv('AWG31_AUDIT', str(tmp_path / 'audit.jsonl'))
    (tmp_path / 'full').mkdir()
    for index in range(30):
        (tmp_path / 'full' / f'awg31-202611{index % 28 + 1:02}T0000{index:02}Z-{index:010x}.tar.gz').write_bytes(b'x')

    class NoServers:
        @staticmethod
        def interfaces():
            return []
    with pytest.raises(ValueError, match='limit'):
        admin.create_backup(NoServers)
    assert admin.create_backup(NoServers, enforce_limit=False)['ok'] is True


# --- 4. host metrics survive without awg0; deletion needs a typed name --------

def test_host_metrics_work_without_awg0_and_keep_old_history(tmp_path, monkeypatch):
    admin = load_admin('admin_host_v093')
    monkeypatch.setenv('AWG31_ROOT', str(tmp_path))
    assert admin.sample_host_metrics()['ok'] is True      # no awg0 database at all
    assert (tmp_path / 'host.sqlite3').is_file() and not (tmp_path / 'state.sqlite3').exists()
    # Upgrade path: history that older installations kept in state.sqlite3 is carried over once.
    (tmp_path / 'host.sqlite3').unlink()
    with sqlite3.connect(tmp_path / 'state.sqlite3') as legacy:
        legacy.execute(admin._HOST_SCHEMA)
        legacy.execute('INSERT INTO host_samples (measured_at, tcp, udp) VALUES (?,?,?)', (int(time.time()) - 3600, 1, 2))
        legacy.execute('INSERT INTO host_samples (measured_at, tcp, udp) VALUES (?,?,?)', (1234567890, 1, 2))
    assert admin.sample_host_metrics()['ok'] is True
    with sqlite3.connect(tmp_path / 'host.sqlite3') as current:
        # recent legacy row + the new sample; the 2009 row is past the 32-day retention
        assert current.execute('SELECT count(*) FROM host_samples').fetchone()[0] == 2
    assert admin.host_metrics_history({'window': '5m'})['points']


def test_server_delete_form_requires_typing_the_name(ui):
    _, client, calls = ui
    page = client.get('/servers')
    form = re.search(r'<form method="post" action="/server/awg1/delete".*?</form>', page.text, flags=re.S).group(0)
    assert 'type="hidden" name="confirm"' not in form
    assert 'type="text" name="confirm" required' in form and 'pattern="awg1"' in form
    client.post('/server/awg1/delete', data={'csrf': token(page), 'confirm': 'awg1'})
    assert ('server-delete', {'interface': 'awg1', 'confirm': 'awg1'}) in calls


# --- 5. unknown client exports ------------------------------------------------

def test_unknown_client_exports_are_404_not_500(ui):
    module, client, _ = ui
    original = module.ctl

    def missing(op, data=None):
        if op == 'download':
            raise RuntimeError('Клиент не найден')
        return original(op, data)
    module.ctl = missing
    for path in ('/servers/awg0/clients/ghost/download', '/servers/awg0/clients/ghost/qr',
                 '/servers/awg0/clients/ghost/vpn-link', '/servers/awg0/clients/ghost'):
        assert client.get(path).status_code == 404, path


def test_error_pages_carry_an_error_status(ui):
    module, client, _ = ui
    page = client.get('/servers')
    original = module.ctl

    def failing(op, data=None):
        if op == 'server-create':
            raise RuntimeError('UDP port already used by awg0')
        return original(op, data)
    module.ctl = failing
    reply = client.post('/server/create', data={'csrf': token(page), 'interface': 'awg2', 'subnet': '10.9.0.0/24',
                                                'port': '45678', 'mtu': '1280', 'endpoint': 'vpn.example.test',
                                                'dns': '1.1.1.1', 'mode': 'full', 'uplink': 'ens3'})
    assert reply.status_code == 400 and 'UDP port already used' in reply.text


# --- 6. asset versions --------------------------------------------------------

def test_asset_version_follows_file_content(ui):
    module, client, _ = ui
    home = client.get('/').text
    for name in ('panel.css', 'md3.css', 'panel.js'):
        assert f'/assets/{name}?v={module.asset_version(name)}"' in home
        assert re.fullmatch(r'[0-9a-f]{12}', module.asset_version(name))


# --- I1-I5 generation ---------------------------------------------------------

def test_enabling_cps_with_empty_fields_generates_i1():
    result = ctl.validate_i_fields({'i_enabled': '1', **{f'i{n}': '' for n in range(1, 6)}})
    assert result['i_enabled'] == 1 and re.fullmatch(r'<r [0-9]{2,3}>', result['i1'])
    assert all(result[f'i{n}'] == '' for n in range(2, 6))
    # Disabled stays untouched; an explicit value is never replaced.
    assert ctl.validate_i_fields({'i_enabled': '0'})['i1'] == ''
    assert ctl.validate_i_fields({'i_enabled': '1', 'i1': '<r 48>'})['i1'] == '<r 48>'


@pytest.mark.parametrize('preset', ['random', 'dns', 'stun', 'quic'])
def test_cps_presets_pass_the_controller_validator(ui, preset):
    module, client, _ = ui
    assert preset in module.CPS_PRESETS
    reply = client.get('/api/cps/generate', params={'preset': preset})
    assert reply.status_code == 200 and reply.headers['cache-control'] == 'no-store'
    value = reply.json()['value']
    checked = ctl.validate_i_fields({'i_enabled': '1', 'i1': value})
    assert checked['i1'] == value
    # Every other field accepts it too (the per-field button uses "random").
    assert ctl.validate_i_fields({'i_enabled': '1', 'i1': '<r 40>', 'i5': value})['i5'] == value


def test_cps_preset_packets_have_the_documented_shape(ui):
    module, _, _ = ui

    def size(expression):
        total = 0
        for tag in re.findall(r'<([^>]+)>', expression):
            total += len(tag[4:]) // 2 if tag.startswith('b 0x') else int(tag.split()[1])
        return total
    stun = module.cps_value('stun')
    assert stun == '<b 0x000100002112a442><r 12>' and size(stun) == 20           # RFC 5389 header
    assert size(module.cps_value('quic')) == 1200                                # RFC 9000 minimum Initial
    assert module.cps_value('quic').startswith('<b 0xc30000000108><r 8><b 0x0000449e>')
    dns = module.cps_value('dns')
    question = bytes.fromhex(re.search(r'<b 0x([0-9a-f]+)>', dns).group(1))
    assert dns.startswith('<r 2><b 0x0100000100000000000') and question[-4:] == b'\x00\x01\x00\x01'
    labels, position = [], 10
    while question[position]:
        labels.append(question[position + 1:position + 1 + question[position]].decode())
        position += question[position] + 1
    assert '.'.join(labels) in module.CPS_DNS_NAMES


def test_cps_generator_requires_login_and_known_preset(ui):
    module, client, _ = ui
    assert client.get('/api/cps/generate', params={'preset': 'nope'}).status_code == 422
    from fastapi.testclient import TestClient
    assert TestClient(module.app).get('/api/cps/generate').status_code == 401


def test_cps_editor_has_generate_buttons_and_templates(ui):
    _, client, _ = ui
    for path, prefix in (('/servers/awg0/clients', 'new'), ('/servers/awg0/clients/alpha', 'detail')):
        html = client.get(path).text
        for number in range(1, 6):
            assert f'data-cps-generate="{prefix}-i{number}"' in html
            assert f'<textarea id="{prefix}-i{number}" name="i{number}"' in html
        assert f'data-cps-apply="{prefix}-i1"' in html and 'data-cps-preset' in html
        assert all(f'<option value="{name}">' in html for name in ('random', 'dns', 'stun', 'quic'))
    script = (ROOT / 'src/panel.js').read_text()
    assert '/api/cps/generate?preset=' in script and 'innerHTML = data' not in script


# --- self-hosted fonts --------------------------------------------------------

FONT_FILES = ('exo-2-latin-wght-normal.woff2', 'exo-2-cyrillic-wght-normal.woff2',
              'jetbrains-mono-latin-wght-normal.woff2', 'jetbrains-mono-cyrillic-wght-normal.woff2')


def test_fonts_are_served_locally_with_a_strict_name_check(ui):
    _, client, _ = ui
    for name in FONT_FILES:
        reply = client.get(f'/assets/fonts/{name}')
        assert reply.status_code == 200 and reply.headers['content-type'] == 'font/woff2'
        assert reply.content[:4] == b'wOF2'
    for bad in ('OFL-Exo2.txt', '..%2Fweb.py', 'missing.woff2', 'EXO.woff2'):
        assert client.get(f'/assets/fonts/{bad}').status_code == 404


def test_css_uses_only_local_fonts_and_csp_allows_them(ui):
    _, client, _ = ui
    css = client.get('/assets/md3.css').text + client.get('/assets/panel.css').text
    for name in FONT_FILES:
        assert f'url("/assets/fonts/{name}")' in css
    assert '--font-ui:"Exo 2"' in css and '--font-mono:"JetBrains Mono"' in css
    assert 'http://' not in css and 'https://' not in css and '@import' not in css
    assert 'U+0400-045F' in css                                       # Cyrillic subset is declared
    policy = client.get('/').headers['Content-Security-Policy']
    assert "font-src 'self'" in policy and "default-src 'none'" in policy


def test_fonts_ship_with_their_licence_and_are_installed():
    fonts = ROOT / 'src/fonts'
    assert {path.name for path in fonts.glob('*.woff2')} == set(FONT_FILES)
    for licence in ('OFL-Exo2.txt', 'OFL-JetBrainsMono.txt'):
        assert 'SIL Open Font License' in (fonts / licence).read_text()
    for name in ('install.sh', 'scripts/upgrade-core.sh', 'scripts/upgrade-ui.sh'):
        assert '/src/fonts/*' in (ROOT / name).read_text(), name


# --- readable sizes in tables -------------------------------------------------

def test_tables_show_human_readable_sizes(ui):
    module, client, _ = ui
    assert module.human_size(0) == '0 B' and module.human_size(1536) == '1.5 KiB'
    assert module.human_size(901878932) == '860.1 MiB' and module.human_size(None) == '—'
    original = module.ctl

    def busy(op, data=None):
        result = original(op, data)
        if op == 'list':
            result['clients'][0]['stats'] = {'received': 901878932, 'sent': 3354137308, 'handshake': 0}
        return result
    module.ctl = busy
    html = client.get('/servers/awg0/clients').text
    assert '860.1 MiB' in html and '3.1 GiB' in html and '901878932 B' not in html
    assert '1.0 KiB' in client.get('/maintenance?tab=backups').text


def test_dashboard_chart_labels_follow_the_interface_language(ui):
    _, client, _ = ui
    russian = client.get('/').text
    assert 'Сейчас' in russian and '>15м<' in russian
    client.get('/lang/en?next=/')
    english = client.get('/').text
    assert '>Now<' in english and '>15m<' in english and 'Peak: —' in english
    assert 'Сейчас' not in english and '15м' not in english
    assert "'−5m'" in (ROOT / 'src/panel.js').read_text()
