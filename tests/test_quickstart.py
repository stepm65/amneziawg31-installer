"""One-command installer: arguments, release download, SHA256 verification.

The download tests run the real install.sh with a stand-in `curl` that serves a
locally built release, in read-only `--doctor` mode. They need root (the
installer refuses to run otherwise) and a git checkout, and are skipped elsewhere.
"""
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'
RAW = 'https://raw.githubusercontent.com/stepm65/amneziawg31-installer/main/install.sh'


def test_shell_files_parse():
    files = ['install.sh', 'scripts/setup-wizard.sh', 'scripts/prepare-awg31.sh', 'scripts/awg31-menu',
             'scripts/build-release.sh', 'scripts/upgrade-core.sh']
    p = subprocess.run(['bash', '-n', *[str(ROOT / f) for f in files]], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


def test_entry_point_is_install_sh_and_wizard_moved():
    assert not (ROOT / 'bootstrap.sh').exists()
    script = INSTALL.read_text()
    assert f'bash <(curl -Ls {RAW})' in script
    assert 'scripts/setup-wizard.sh' in script and 'scripts/prepare-awg31.sh' in script
    wizard = (ROOT / 'scripts/setup-wizard.sh').read_text()
    assert 'dirname -- "${BASH_SOURCE[0]}")/.."' in wizard     # project root, not scripts/


def test_installer_never_overwrites_an_existing_vpn():
    s = INSTALL.read_text()
    assert 'state.sqlite3' in s and 'awg0.conf' in s
    assert '--upgrade' in s and '--doctor' in s
    assert 'switching to update mode' in s                      # re-running the command updates
    assert 'Nothing was overwritten' in s


def test_release_archives_are_checksum_verified_before_unpacking():
    s = INSTALL.read_text()
    check = s.index('sha256sum --check --status')
    unpack = s.index('tar -xzf "$WORK/$asset"')
    assert check < unpack
    assert 'SHA256 file for $tag is missing; refusing to install' in s
    assert '--no-same-owner --no-same-permissions' in s


def test_safe_without_a_project_directory():
    s = INSTALL.read_text()
    assert '${BASH_SOURCE[0]:-}' in s
    assert "SCRIPT_DIR=''" in s
    assert '-f "${BASH_SOURCE[0]}"' in s                        # /dev/fd/N is not a project


def test_secure_boot_resume_not_disable_security():
    s = (ROOT / 'scripts/prepare-awg31.sh').read_text()
    assert 'awg31_secure_boot' in s
    assert 'mokutil --sb-state' in (ROOT / 'scripts/os-support.sh').read_text()
    assert 'Enroll MOK' in s
    assert '--disable-validation' not in s
    assert 'KERNEL_COMMIT=4569c4c67f3a57414969260cafbbd04694fbaae0' in s
    assert 'v3.1.20260812' in s


def test_upstream_patch_present():
    text = (ROOT / 'patches/ubuntu-26.04-udp-tunnel-pr265.patch').read_text()
    assert 'src/compat/compat.h' in text
    assert '__builtin_types_compatible_p' in text


def test_wizard_can_generate_the_password_and_shows_it_once():
    wizard = (ROOT / 'scripts/setup-wizard.sh').read_text()
    assert 'secrets.token_urlsafe(18)' in wizard
    assert wizard.count('echo "  Пароль:   $PASSWORD_GENERATED"') == 1
    assert 'unset PASSWORD_GENERATED' in wizard
    assert 'Повторите пароль' in wizard                          # a typed password is still confirmed


def test_menu_has_update_and_version():
    menu = (ROOT / 'scripts/awg31-menu').read_text()
    assert 'update)' in menu and 'version)' in menu
    assert f'{RAW} -o "$installer"' in menu and 'bash "$installer" --upgrade "$@"' in menu
    for script in ('scripts/setup-wizard.sh', 'scripts/upgrade-core.sh'):
        assert '/VERSION' in (ROOT / script).read_text()


def test_release_workflow_builds_what_the_installer_downloads():
    workflow = (ROOT / '.github/workflows/release.yml').read_text()
    assert "'v[0-9]+.[0-9]+.[0-9]+'" in workflow and 'contents: write' in workflow
    assert 'scripts/build-release.sh "$GITHUB_REF_NAME" dist' in workflow
    assert 'python -m pytest -q' in workflow                     # no release from a red tree
    # A release drafted on github.com gets the same files instead of failing the job.
    assert 'types: [published]' in workflow and 'gh release upload "$GITHUB_REF_NAME" dist/* --clobber' in workflow
    build = (ROOT / 'scripts/build-release.sh').read_text()
    assert 'asset="awg31-console-$tag.tar.gz"' in build
    assert 'asset="awg31-console-$tag.tar.gz"' in INSTALL.read_text()
    assert 'sha256sum "$asset" > "$asset.sha256"' in build


def run_installer(*args, env=None):
    return subprocess.run(['bash', str(INSTALL), *args], capture_output=True, text=True, env=env, timeout=120)


def test_argument_validation_needs_no_network():
    # Parsed before the root and OS checks, so this runs anywhere.
    assert run_installer('--help').returncode == 0
    for bad in ('latest', 'v1', 'v1.2', '0.9.6', 'v1.2.3-rc1', '--force', 'v1.2.3;id'):
        result = run_installer(bad)
        assert result.returncode == 1 and 'ERROR' in result.stderr, bad


def test_non_root_gets_the_exact_commands_to_run():
    if os.geteuid() == 0:
        pytest.skip('needs a non-root user')
    result = run_installer('v0.9.6')
    assert result.returncode == 1
    assert f'bash <(curl -Ls {RAW}) v0.9.6' in result.stderr
    assert f'curl -Ls {RAW} | sudo bash -s -- v0.9.6' in result.stderr


# --- real download path against a stand-in for GitHub -------------------------

FAKE_CURL = r'''#!/usr/bin/env bash
# Stand-in for curl: serves files from $FAKE_GITHUB by URL, logs every request.
out=''; url=''; head=0; fmt=''
while (($#)); do
  case "$1" in
    -o) out="$2"; shift ;;
    -w) fmt="$2"; shift ;;
    -H|--retry|--connect-timeout|--max-time) shift ;;
    --head) head=1 ;;
    http*) url="$1" ;;
  esac
  shift
done
echo "$url" >> "$FAKE_GITHUB/requests.log"
if ((head)); then
  [[ -f "$FAKE_GITHUB/latest-redirect" ]] && printf '%s' "$(cat "$FAKE_GITHUB/latest-redirect")"
  exit 0
fi
case "$url" in
  https://api.github.com/*/releases/latest) file="$FAKE_GITHUB/latest.json" ;;
  https://github.com/*/releases/download/*) file="$FAKE_GITHUB/assets/${url##*/}" ;;
  https://github.com/*/archive/refs/heads/main.tar.gz) file="$FAKE_GITHUB/main.tar.gz" ;;
  *) exit 22 ;;
esac
[[ -f "$file" ]] || exit 22
if [[ -n "$out" ]]; then cp "$file" "$out"; else cat "$file"; fi
'''


@pytest.fixture
def github(tmp_path):
    if os.geteuid() != 0:
        pytest.skip('install.sh requires root')
    if not (ROOT / '.git').exists() or not shutil.which('git'):
        pytest.skip('needs a git checkout to build a release archive')
    os_release = Path('/etc/os-release').read_text()
    if not re.search(r'^ID="?(ubuntu|rocky)"?$', os_release, flags=re.M):
        pytest.skip('unsupported OS for the installer')
    version = (ROOT / 'VERSION').read_text().strip()
    tag = f'v{version}'
    fake = tmp_path / 'github'
    (fake / 'assets').mkdir(parents=True)
    built = subprocess.run(['bash', str(ROOT / 'scripts/build-release.sh'), tag, str(fake / 'assets')],
                           capture_output=True, text=True, cwd=ROOT)
    if built.returncode != 0:
        pytest.skip('release archive needs the VERSION file to be committed: ' + built.stderr.strip()[:120])
    shutil.copy(fake / 'assets' / f'awg31-console-{tag}.tar.gz', fake / 'main.tar.gz')
    (fake / 'latest.json').write_text('{\n  "url": "x",\n  "tag_name": "%s",\n  "name": "r"\n}\n' % tag)
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    (bin_dir / 'curl').write_text(FAKE_CURL)
    (bin_dir / 'curl').chmod(0o755)
    env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'FAKE_GITHUB': str(fake)}
    env.pop('AWG31_VERSION', None)
    # Run a copy outside the repository, like `bash <(curl ...)`: no local project.
    script = tmp_path / 'install.sh'
    shutil.copy(INSTALL, script)

    def run(*args):
        return subprocess.run(['bash', str(script), '--doctor', *args], capture_output=True, text=True,
                              env=env, timeout=180, cwd=tmp_path)
    return fake, tag, run


def requests(fake):
    log = fake / 'requests.log'
    return log.read_text().split() if log.exists() else []


def test_release_archive_layout_and_checksum_file(github):
    fake, tag, _ = github
    asset = fake / 'assets' / f'awg31-console-{tag}.tar.gz'
    line = (fake / 'assets' / f'{asset.name}.sha256').read_text()
    assert line == f'{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n'
    names = subprocess.run(['tar', '-tzf', str(asset)], capture_output=True, text=True, check=True).stdout.split('\n')
    prefix = f'awg31-console-{tag}/'
    for needed in ('install.sh', 'VERSION', 'scripts/setup-wizard.sh', 'scripts/upgrade-core.sh',
                   'src/web.py', 'src/awg31ctl', 'src/fonts/exo-2-latin-wght-normal.woff2', 'LICENSE'):
        assert prefix + needed in names, needed
    assert not any(name.startswith((prefix + 'tests/', prefix + '.github/', prefix + 'docs/screenshots/'))
                   for name in names)


def test_default_installs_the_latest_release_after_verifying_it(github):
    fake, tag, run = github
    result = run()
    assert result.returncode == 0, result.stderr
    assert f'Downloading release {tag}' in result.stdout and 'SHA256 verified' in result.stdout
    assert '== OS / kernel ==' in result.stdout                  # doctor.sh from the unpacked release ran
    seen = requests(fake)
    assert any(u.endswith('/releases/latest') for u in seen)
    assert any(u.endswith(f'/releases/download/{tag}/awg31-console-{tag}.tar.gz.sha256') for u in seen)


def test_specific_version_skips_the_latest_lookup(github):
    fake, tag, run = github
    result = run(tag)
    assert result.returncode == 0, result.stderr
    assert not any('releases/latest' in u for u in requests(fake))


def test_tampered_archive_is_rejected_and_not_unpacked(github):
    fake, tag, run = github
    asset = fake / 'assets' / f'awg31-console-{tag}.tar.gz'
    asset.write_bytes(asset.read_bytes() + b'\0')
    result = run(tag)
    assert result.returncode == 1 and 'SHA256 mismatch' in result.stderr
    assert '== OS / kernel ==' not in result.stdout


def test_missing_checksum_file_is_refused(github):
    fake, tag, run = github
    (fake / 'assets' / f'awg31-console-{tag}.tar.gz.sha256').unlink()
    result = run(tag)
    assert result.returncode == 1 and 'refusing to install' in result.stderr


def test_checksum_file_naming_another_file_is_refused(github):
    fake, tag, run = github
    asset = fake / 'assets' / f'awg31-console-{tag}.tar.gz'
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    (fake / 'assets' / f'{asset.name}.sha256').write_text(f'{digest}  /etc/passwd\n')
    assert run(tag).returncode == 1


def test_unknown_release_fails_cleanly(github):
    _, _, run = github
    result = run('v9.9.9')
    assert result.returncode == 1 and 'Release v9.9.9 not found' in result.stderr


def test_dev_latest_uses_main_and_says_it_is_not_a_release(github):
    fake, _, run = github
    result = run('dev-latest')
    assert result.returncode == 0, result.stderr
    assert 'rolling build from main' in result.stdout and 'SHA256 verified' not in result.stdout
    assert any(u.endswith('/archive/refs/heads/main.tar.gz') for u in requests(fake))


def test_without_any_release_falls_back_to_the_rolling_build(github):
    fake, _, run = github
    (fake / 'latest.json').unlink()                              # API: 404, redirect: none
    result = run()
    assert result.returncode == 0, result.stderr
    assert 'No published release found' in result.stdout


def test_latest_lookup_survives_an_api_outage_through_the_redirect(github):
    fake, tag, run = github
    (fake / 'latest.json').unlink()
    (fake / 'latest-redirect').write_text(f'https://github.com/stepm65/amneziawg31-installer/releases/tag/{tag}')
    result = run()
    assert result.returncode == 0, result.stderr
    assert f'Downloading release {tag}' in result.stdout
