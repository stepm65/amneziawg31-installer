from pathlib import Path

ROOT = Path(__file__).parents[1]

def test_supported_distros_declared():
    support = (ROOT/'scripts/os-support.sh').read_text()
    bootstrap = (ROOT/'install.sh').read_text()
    prepare = (ROOT/'scripts/prepare-awg31.sh').read_text()
    installer = (ROOT/'scripts/setup-wizard.sh').read_text()
    for token in ('ubuntu:24.04', 'ubuntu:26.04', 'rocky:9', 'rocky:10'):
        assert token in support and token in bootstrap
    assert 'awg31_detect_os' in installer and 'awg31_detect_os' in prepare
    assert 'kernel-devel-$(uname -r)' in support
    assert 'epel-release' in support and 'crb' in support

def test_secure_boot_optional_and_no_autodisable():
    support = (ROOT/'scripts/os-support.sh').read_text()
    prepare = (ROOT/'scripts/prepare-awg31.sh').read_text()
    assert 'SecureBoot enabled' in support
    assert 'SecureBoot disabled' in support
    assert 'mokutil --import' in prepare
    assert 'if [[ "$secure_boot" == enabled ]]' in prepare
    assert '--disable-validation' not in prepare
    assert 'mokutil --disable' not in prepare

def test_md3_dark_amber_theme_is_local_and_served():
    md3 = (ROOT/'src/md3.css').read_text()
    web = (ROOT/'src/web.py').read_text()
    install = (ROOT/'scripts/setup-wizard.sh').read_text()
    upgrade = (ROOT/'scripts/upgrade-core.sh').read_text()
    for token in ('--md-sys-color-primary:', '--md-sys-color-surface:', '--md-sys-shape-corner-extra-large:', '@media(max-width:670px)'):
        assert token in md3
    assert '#f8b444' in md3 and '#101216' in md3
    assert '/assets/md3.css' in web
    assert 'src/md3.css' in install and 'src/md3.css' in upgrade

def test_rocky_does_not_disable_firewalld_or_claim_nat_works_without_check():
    installer = (ROOT/'scripts/setup-wizard.sh').read_text()
    assert 'is-active --quiet firewalld' in installer
    assert 'после установки проверить NAT' in installer
    assert 'systemctl disable firewalld' not in installer
