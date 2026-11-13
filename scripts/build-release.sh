#!/usr/bin/env bash
# Build the release archive and its SHA256 file exactly as install.sh expects:
#   awg31-console-vX.Y.Z.tar.gz         (top-level directory awg31-console-vX.Y.Z/)
#   awg31-console-vX.Y.Z.tar.gz.sha256  ("<sha256>  <file name>", one line)
# Usage: scripts/build-release.sh vX.Y.Z [output-dir] [git-ref]
set -Eeuo pipefail
tag="${1:?usage: build-release.sh vX.Y.Z [output-dir] [git-ref]}"
out="${2:-dist}"
ref="${3:-HEAD}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid tag: $tag" >&2; exit 1; }
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(git -C "$root" show "$ref:VERSION" | tr -d '[:space:]')"
[[ "v$version" == "$tag" ]] || { echo "VERSION file says $version, tag is $tag" >&2; exit 1; }
mkdir -p "$out"
asset="awg31-console-$tag.tar.gz"
git -C "$root" archive --format=tar.gz --prefix="awg31-console-$tag/" -o "$(cd "$out" && pwd)/$asset" "$ref"
(cd "$out" && sha256sum "$asset" > "$asset.sha256")
echo "Built $out/$asset"
cat "$out/$asset.sha256"
