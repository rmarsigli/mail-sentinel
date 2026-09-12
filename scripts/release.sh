#!/usr/bin/env bash
# Check a tag against the tree and build the tarball an operator installs.
#
#   scripts/release.sh v0.2.0 [outdir]
#
# Run by .github/workflows/release.yml on a tag, and by hand to see what a
# release would contain before creating one.
set -euo pipefail
cd "$(dirname "$0")/.."

tag=${1:-}
outdir=${2:-dist}
[ -n "$tag" ] || { echo "usage: $0 <vX.Y.Z> [outdir]" >&2; exit 2; }

version=${tag#v}
declared=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' sentinel/__init__.py)
if [ "$version" != "$declared" ]; then
    echo "tag $tag does not match __version__ $declared" >&2
    exit 1
fi
if ! grep -q "^## $version - " CHANGELOG.md; then
    echo "CHANGELOG.md has no '## $version - <date>' section" >&2
    exit 1
fi

# Release notes are the CHANGELOG section for this version, nothing invented.
mkdir -p "$outdir"
awk -v v="## $version - " '
    index($0, v) == 1 {inside = 1; next}
    inside && /^## / {exit}
    inside {print}
' CHANGELOG.md > "$outdir/notes-$version.md"

# The tarball is what goes on a mail server: no history, no tests, no CI, no notes.
name="mail-sentinel-$version"
rm -rf "${outdir:?}/${name:?}"
mkdir -p "$outdir/$name"
tar -cf - --exclude=.git --exclude=.github --exclude=tests --exclude=local \
    --exclude=__pycache__ --exclude=dist --exclude='CLAUDE.md' --exclude='AGENTS.md' \
    . | tar -xf - -C "$outdir/$name"
tar -czf "$outdir/$name.tar.gz" -C "$outdir" "$name"
rm -rf "${outdir:?}/${name:?}"

echo "built $outdir/$name.tar.gz"
tar -tzf "$outdir/$name.tar.gz" | sort
