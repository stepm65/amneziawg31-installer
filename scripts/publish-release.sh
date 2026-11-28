#!/usr/bin/env bash
# Publish the built archive for a tag. Used by .github/workflows/release.yml.
# Works for both ways of starting a release:
#   - a pushed tag: the release does not exist yet and is created here;
#   - a release drafted on github.com: files are attached to it, and an empty
#     title or description is filled in (text the author wrote is never replaced).
# The title is the version alone (the tag, e.g. v1.2.3): it reads best in the list.
# Usage: scripts/publish-release.sh vX.Y.Z DIST_DIR   (needs the gh CLI and GH_TOKEN)
set -Eeuo pipefail
tag="${1:?usage: publish-release.sh vX.Y.Z DIST_DIR}"
dist="${2:?usage: publish-release.sh vX.Y.Z DIST_DIR}"
repo="${GITHUB_REPOSITORY:-stepm65/amneziawg31-installer}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid tag: $tag" >&2; exit 1; }
asset="awg31-console-$tag.tar.gz"
[[ -f "$dist/$asset" && -f "$dist/$asset.sha256" ]] || { echo "Missing $asset or its .sha256 in $dist" >&2; exit 1; }
title="$tag"
# Titles that earlier versions of this script wrote, and so may be replaced.
old_title="AmneziaWG 3.1 Console ${tag#v}"
notes="$(mktemp)"
trap 'rm -f -- "$notes"' EXIT
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
{
    # What is new: the section of this version from the changelogs, when there is one.
    if english="$(python3 "$root/scripts/changelog-section.py" "$tag" "$root/CHANGELOG.md" 2>/dev/null)"; then
        printf "## What's new\n\n%s\n\n" "$english"
    fi
    if russian="$(python3 "$root/scripts/changelog-section.py" "$tag" "$root/CHANGELOG.ru.md" 2>/dev/null)"; then
        printf '## Что нового\n\n%s\n\n' "$russian"
    fi
    cat <<NOTES
## Install or update

Run as root:

\`\`\`bash
bash <(curl -Ls https://raw.githubusercontent.com/$repo/main/install.sh) $tag
\`\`\`

The installer verifies \`$asset\` against the \`.sha256\` file published here and aborts on a mismatch.
The archive also has a GitHub build provenance attestation:
\`gh attestation verify $asset --repo $repo\` (or install with \`AWG31_ATTESTATION=require\`).
NOTES
} >"$notes"

if gh release view "$tag" >/dev/null 2>&1; then
    gh release upload "$tag" "$dist/$asset" "$dist/$asset.sha256" --clobber
    current_title="$(gh release view "$tag" --json name --jq .name)"
    current_notes="$(gh release view "$tag" --json body --jq .body)"
    # GitHub shows the last commit subject when the title is empty.
    if [[ -z "${current_title//[[:space:]]/}" || "$current_title" == "$old_title" ]]; then
        gh release edit "$tag" --title "$title"
    fi
    if [[ -z "${current_notes//[[:space:]]/}" ]]; then
        gh release edit "$tag" --notes-file "$notes"
    fi
else
    gh release create "$tag" "$dist/$asset" "$dist/$asset.sha256" --verify-tag --title "$title" --notes-file "$notes"
fi

# Earlier releases keep the long title that older versions of this script wrote,
# or none at all; give them the version alone too. Titles authors chose stay.
# Best effort: a failure here never fails the release that was just published.
gh release list --limit 200 --json tagName,name --jq '.[]|[.tagName,.name]|@tsv' 2>/dev/null |
while IFS=$'\t' read -r other other_title; do
    [[ "$other" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && "$other" != "$tag" ]] || continue
    if [[ -z "${other_title//[[:space:]]/}" || "$other_title" == "AmneziaWG 3.1 Console ${other#v}" ]]; then
        gh release edit "$other" --title "$other" >/dev/null || :
    fi
done || :
