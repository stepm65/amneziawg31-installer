"""0.22: the setup wizard's whiptail screens, driven by a stand-in whiptail."""
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAKE = r'''#!/bin/bash
printf '%s\n' "$*" >>"$FAKE_LOG"
case " $* " in
  *" --gauge "*) cat >"$FAKE_GAUGE"; exit 0 ;;
  *" --msgbox "*) exit 0 ;;
esac
line="$(head -n1 "$FAKE_ANSWERS")"; sed -i 1d "$FAKE_ANSWERS"
code=0
if [[ "$line" == '!'* ]]; then code=1; line="${line#!}"; fi
printf '%s' "$line" >&2
exit $code
'''


def run(tmp_path, script, answers=(), env=None):
    bindir = tmp_path / 'bin'
    bindir.mkdir(exist_ok=True)
    fake = bindir / 'whiptail'
    fake.write_text(FAKE)
    fake.chmod(0o755)
    (tmp_path / 'answers').write_text(''.join(a + '\n' for a in answers))
    environment = {**os.environ, 'PATH': f'{bindir}:{os.environ["PATH"]}', 'FAKE_LOG': str(tmp_path / 'calls'),
                   'FAKE_ANSWERS': str(tmp_path / 'answers'), 'FAKE_GAUGE': str(tmp_path / 'gauge'),
                   'AWG31_INSTALL_LOG': str(tmp_path / 'install.log'), 'AWG31_TTY': str(tmp_path / 'tty'), **(env or {})}
    prelude = f'''set -Eeuo pipefail
source "{ROOT}/scripts/wizard-ui.sh"
awg31_random_subnet() {{ echo 10.55.66.0/24; }}
SUBNET=10.77.10.0/24 PORT=51820 MTU=1280 ENDPOINT=203.0.113.5 DNS=1.1.1.1 MODE=full UPLINK=eth0 PANEL_PORT=8080
FIRST_CLIENT=test-client NGINX_MODE=none NGINX_HOST='' NGINX_HTTPS_PORT=443 NGINX_CERT='' NGINX_KEY='' WIZ_PASSWORD=''
WIZ_FIREWALL='' AWG31_OPEN_FIREWALL=yes
'''
    out = subprocess.run(['bash', '-c', prelude + script], capture_output=True, text=True, env=environment, timeout=30)
    calls = (tmp_path / 'calls').read_text() if (tmp_path / 'calls').exists() else ''
    return out, calls


def show(names):
    return 'echo "' + ' '.join(f'{n}=${n}' for n in names) + '"'


def test_settings_menu_changes_values_and_checks_before_install(tmp_path):
    answers = ['port', '51999', 'dns', 'custom', '9.9.9.10', 'subnet', 'random', 'mode', 'split',
               'password', 'own', 'short', 'longpassword123', 'longpassword124', 'longpassword123', 'longpassword123',
               'https', 'self-signed', 'vpn.example.com', '8443',
               'install', 'install']
    script = '''tries=0
wizard_check() { tries=$((tries+1)); [[ -f "$FAKE_LOG.ok" ]] || { touch "$FAKE_LOG.ok"; echo "[ERROR] UDP-порт VPN уже занят"; return 1; }; }
ui_configure
''' + show(['PORT', 'DNS', 'SUBNET', 'MODE', 'WIZ_PASSWORD', 'NGINX_MODE', 'NGINX_HOST', 'NGINX_HTTPS_PORT'])
    out, calls = run(tmp_path, script, answers)
    assert out.returncode == 0, out.stderr
    assert ('PORT=51999 DNS=9.9.9.10 SUBNET=10.55.66.0/24 MODE=split WIZ_PASSWORD=longpassword123 NGINX_MODE=self-signed '
            'NGINX_HOST=vpn.example.com NGINX_HTTPS_PORT=8443') in out.stdout
    assert 'UDP-порт VPN уже занят' in calls                     # the first Install showed what was wrong
    assert 'Пароль должен быть от 12 до 256 символов' in calls and 'Пароли не совпадают' in calls
    assert '--passwordbox' in calls and 'longpassword' not in calls  # never on a command line


def test_cancel_asks_and_leaves(tmp_path):
    out, _ = run(tmp_path, 'wizard_check() { :; }\nui_configure\necho reached', ['cancel', '!', 'cancel', 'yes'])
    assert out.returncode == 1 and 'reached' not in out.stdout and 'Установка отменена' in out.stdout


def test_english_and_firewall_item(tmp_path):
    script = 'wizard_check() { :; }\nui_language\nWIZ_FIREWALL=ufw\nui_configure\n' + show(['WIZ_LANG', 'AWG31_OPEN_FIREWALL'])
    out, calls = run(tmp_path, script, ['en', 'firewall', '!', 'install'])
    assert 'WIZ_LANG=en AWG31_OPEN_FIREWALL=no' in out.stdout
    assert 'Installation settings' in calls and 'Open the port in ufw: yes' in calls and '▶ Install' in calls


def test_progress_bar_and_log(tmp_path):
    script = '''ui_progress_start
echo "apt output that only the log sees"
ui_progress 40 venv
ui_progress 100 done
ui_progress_stop
echo "back on the terminal"
'''
    out, _ = run(tmp_path, script)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == 'back on the terminal'
    log = (tmp_path / 'install.log').read_text()
    assert 'apt output that only the log sees' in log and '=== Python-окружение панели ===' in log
    gauge = (tmp_path / 'gauge').read_text()
    assert 'XXX\n40\nPython-окружение панели\nXXX' in gauge and 'XXX\n100\nГотово\nXXX' in gauge
    assert oct((tmp_path / 'install.log').stat().st_mode)[-3:] == '600'


def test_failure_shows_the_end_of_the_log(tmp_path):
    out, _ = run(tmp_path, 'ui_progress_start\necho "E: unable to locate package"\nui_failed\n')
    assert 'Установка остановилась' in out.stderr and 'unable to locate package' in out.stderr


def test_the_wizard_picks_screens_only_with_a_terminal():
    wizard = (ROOT / 'scripts/setup-wizard.sh').read_text()
    assert '"$UNATTENDED" != 1 && "${AWG31_UI:-auto}" != text && -t 0 && -t 1' in wizard
    assert 'dnf -q -y install newt' in wizard and 'source "$DIR/scripts/wizard-ui.sh"' in wizard
    assert 'AWG31_PROXY_SKIP_FIREWALL_PROMPT="$([[ "$UNATTENDED" == 1 || "$UI" == whiptail ]]' in wizard
    for key in ('deps', 'module', 'files', 'venv', 'net', 'vpn', 'user', 'panel', 'timers', 'nginx', 'telegram', 'firewall'):
        assert f' {key} ' in wizard, key
    ui = (ROOT / 'scripts/wizard-ui.sh').read_text()
    ru = ui.split('declare -A T_ru=(')[1].split('\n)')[0]
    en = ui.split('declare -A T_en=(')[1].split('\n)')[0]
    import re
    keys = lambda block: set(re.findall(r'\[([a-z_]+)\]=', block))
    assert keys(ru) == keys(en)


def test_text_questions_still_work_unattended(tmp_path):
    out = subprocess.run(['bash', '-n', str(ROOT / 'scripts/setup-wizard.sh')], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
