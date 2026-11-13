from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_no_unsupported_sudo_requiretty_in_installer_or_repair():
    for name in ('install.sh', 'scripts/resume-panel.sh'):
        content = (ROOT / name).read_text()
        assert 'Defaults:awgpanel !requiretty' not in content
        assert 'visudo -cf' in content
        assert '127.0.0.1' in content


def test_repair_does_not_regenerate_server_config_or_client_database():
    script = (ROOT / 'scripts/resume-panel.sh').read_text()
    assert 'awg31ctl init' not in script
    assert 'awg-quick up' not in script
    assert 'awg31mgr add' in script  # sudoers allowlist only
    assert 'awk' not in script
    assert 'state.sqlite3' in script
