"""0.29: changelog sections in release notes, build attestation, the troubleshooting guide."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'scripts/changelog-section.py'


def section(version, name):
    run = subprocess.run(['python3', str(TOOL), version, str(ROOT / name)], capture_output=True, text=True)
    return run.returncode, run.stdout.strip()


def test_every_changelog_has_the_current_version():
    version = (ROOT / 'VERSION').read_text().strip()
    for name in ('CHANGELOG.md', 'CHANGELOG.ru.md'):
        code, text = section(version, name)
        assert code == 0 and text.startswith('- '), f'{name} has no section for {version}'


def test_sections_are_cut_cleanly_and_ranges_count():
    code, text = section('v0.22.1', 'CHANGELOG.md')
    assert code == 0 and 'whiptail' in text and '##' not in text
    code, text = section('0.15.0', 'CHANGELOG.ru.md')
    assert code == 0 and 'Приглашение' in text and 'Более ранние' not in text
    assert section('0.1.0', 'CHANGELOG.md')[0] == 1
    # The two files list the same versions.
    heads = [re.findall(r'^## \[([^\]]+)\]', (ROOT / n).read_text(), re.M) for n in ('CHANGELOG.md', 'CHANGELOG.ru.md')]
    assert heads[0] == heads[1] and heads[0][0] == (ROOT / 'VERSION').read_text().strip()


def test_release_notes_use_the_changelog(tmp_path):
    script = (ROOT / 'scripts/publish-release.sh').read_text()
    assert 'changelog-section.py" "$tag" "$root/CHANGELOG.md"' in script and 'CHANGELOG.ru.md' in script
    assert "## What's new" in script and '## Что нового' in script and 'gh attestation verify' in script
    # The notes part runs as it is: build it without gh.
    start = script.index('root="$(cd')
    end = script.index('} >"$notes"') + len('} >"$notes"')
    snippet = (f'set -Eeuo pipefail\nBASH_SOURCE_DIR={ROOT}/scripts\ntag=v0.28.0 repo=x/y asset=a.tar.gz notes={tmp_path}/n\n'
               + script[start:end].replace('$(dirname -- "${BASH_SOURCE[0]}")', '$BASH_SOURCE_DIR'))
    subprocess.run(['bash', '-c', snippet], check=True)
    notes = (tmp_path / 'n').read_text()
    assert notes.index("## What's new") < notes.index('## Что нового') < notes.index('## Install or update')
    assert 'Access requests in the bot' in notes and 'Запросы доступа в боте' in notes and 'install.sh) v0.28.0' in notes


def test_the_release_is_attested_and_the_installer_can_require_it():
    workflow = (ROOT / '.github/workflows/release.yml').read_text()
    assert 'actions/attest-build-provenance@v2' in workflow and 'id-token: write' in workflow and 'attestations: write' in workflow
    assert workflow.index('attest-build-provenance') < workflow.index('Publish release')
    installer = (ROOT / 'install.sh').read_text()
    assert '"${AWG31_ATTESTATION:-}" == require' in installer and 'gh attestation verify "$WORK/$asset" --repo "$REPO"' in installer
    assert installer.index('sha256sum --check') < installer.index('gh attestation verify')
    assert "has no attestation; choose a release" in installer


def test_the_guide_names_only_real_commands():
    menu = (ROOT / 'scripts/awg31-menu').read_text()
    known = set(re.findall(r'^  ([a-z][a-z0-9-]*)\)', menu, re.M)) | set(re.findall(r'^  ([a-z][a-z0-9-]*)\|', menu, re.M))
    for name in ('docs/TROUBLESHOOTING.md', 'docs/TROUBLESHOOTING.ru.md'):
        text = (ROOT / name).read_text()
        used = set(re.findall(r'sudo awg31 ([a-z][a-z0-9-]*)', text))
        assert used and used <= known | {'telegram'}, (name, used - known)
        assert 'resume-panel.sh' in text and (ROOT / 'scripts/resume-panel.sh').exists()
    for readme in ('README.md', 'README.ru.md'):
        text = (ROOT / readme).read_text()
        assert 'docs/TROUBLESHOOTING' in text and 'CHANGELOG' in text
