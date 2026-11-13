#!/usr/bin/env bash
# Publish the built archive for a tag. Used by .github/workflows/release.yml.
# Works for both ways of starting a release:
#   - a pushed tag: the release does not exist yet and is created here;
#   - a release drafted on github.com: files are attached to it, and an empty
#     title or description is filled in (text the author wrote is never replaced).
# Usage: scripts/publish-release.sh vX.Y.Z DIST_DIR   (needs the gh CLI and GH_TOKEN)
set -Eeuo pipefail
tag="${1:?usage: publish-release.sh vX.Y.Z DIST_DIR}"
dist="${2:?usage: publish-release.sh vX.Y.Z DIST_DIR}"
repo="${GITHUB_REPOSITORY:-stepm65/amneziawg31-installer}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid tag: $tag" >&2; exit 1; }
asset="awg31-console-$tag.tar.gz"
[[ -f "$dist/$asset" && -f "$dist/$asset.sha256" ]] || { echo "Missing $asset or its .sha256 in $dist" >&2; exit 1; }
title="AmneziaWG 3.1 Console ${tag#v}"
notes="$(mktemp)"
trap 'rm -f -- "$notes"' EXIT
cat >"$notes" <<NOTES
Install or update with one command (run as root):

\`\`\`bash
bash <(curl -Ls https://raw.githubusercontent.com/$repo/main/install.sh) $tag
\`\`\`

The installer verifies \`$asset\` against the \`.sha256\` file published here and aborts on a mismatch.
NOTES

if gh release view "$tag" >/dev/null 2>&1; then
    gh release upload "$tag" "$dist/$asset" "$dist/$asset.sha256" --clobber
    current_title="$(gh release view "$tag" --json name --jq .name)"
    current_notes="$(gh release view "$tag" --json body --jq .body)"
    # GitHub shows the last commit subject when the title is empty.
    if [[ -z "${current_title//[[:space:]]/}" || "$current_title" == "$tag" ]]; then
        gh release edit "$tag" --title "$title"
    fi
    if [[ -z "${current_notes//[[:space:]]/}" ]]; then
        gh release edit "$tag" --notes-file "$notes"
    fi
else
    gh release create "$tag" "$dist/$asset" "$dist/$asset.sha256" --verify-tag --title "$title" --notes-file "$notes"
fi
