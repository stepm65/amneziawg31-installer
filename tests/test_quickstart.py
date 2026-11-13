from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def test_shell_files_parse():
    files=['bootstrap.sh','install.sh','scripts/prepare-awg31.sh','scripts/awg31-menu']
    p=subprocess.run(['bash','-n',*[str(ROOT/f) for f in files]],capture_output=True,text=True)
    assert p.returncode==0, p.stderr

def test_bootstrap_not_overwrite_existing_vpn():
    s=(ROOT/'bootstrap.sh').read_text()
    assert 'state.sqlite3' in s and 'awg0.conf' in s
    assert '--upgrade' in s
    assert '--doctor' in s
    assert 'sha256sum --check' in s

def test_secure_boot_resume_not_disable_security():
    s=(ROOT/'scripts/prepare-awg31.sh').read_text()
    assert 'awg31_secure_boot' in s
    assert 'mokutil --sb-state' in (ROOT/'scripts/os-support.sh').read_text()
    assert 'Enroll MOK' in s
    assert '--disable-validation' not in s
    assert 'KERNEL_COMMIT=4569c4c67f3a57414969260cafbbd04694fbaae0' in s
    assert 'v3.1.20260812' in s

def test_upstream_patch_present():
    text=(ROOT/'patches/ubuntu-26.04-udp-tunnel-pr265.patch').read_text()
    assert 'src/compat/compat.h' in text
    assert '__builtin_types_compatible_p' in text


def test_bootstrap_safe_with_stdin_pipe_mode():
    s = (ROOT/'bootstrap.sh').read_text()
    assert '${BASH_SOURCE[0]:-}' in s
    assert 'SCRIPT_DIR=\'\'' in s
