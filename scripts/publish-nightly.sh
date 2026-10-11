#!/usr/bin/env bash
# Publishes the files in <dir> as the one and only "nightly" release: the previous nightly release and its tag are
# removed, the tag is made again at <commit>, and a pre-release is created from it with every file in <dir>.
#
#   scripts/publish-nightly.sh dist <commit> <version> <repo>
#
# Needs the GitHub CLI (`gh`) with GH_TOKEN set, and a token that may write contents. The release is a pre-release, so
# `releases/latest` never points at it; the files are at https://github.com/<repo>/releases/download/nightly/<name>.
set -euo pipefail

dir="${1:?usage: publish-nightly.sh <dir> <commit> <version> <repo>}"
commit="${2:?usage: publish-nightly.sh <dir> <commit> <version> <repo>}"
version="${3:?usage: publish-nightly.sh <dir> <commit> <version> <repo>}"
repo="${4:?usage: publish-nightly.sh <dir> <commit> <version> <repo>}"
tag="nightly"

# Everything that can be wrong with the input is found before anything is deleted: a failure after the old release is
# gone leaves people with no download at all.
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "publish-nightly.sh: commit must be a full 40-character SHA, got '$commit'" >&2; exit 2; }
[[ "$version" =~ ^nightly-[0-9]{8}-[0-9a-f]{7,40}$ ]] || { echo "publish-nightly.sh: bad version '$version'" >&2; exit 2; }
[[ "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || { echo "publish-nightly.sh: bad repository '$repo'" >&2; exit 2; }
[ -d "$dir" ] || { echo "publish-nightly.sh: $dir is not a directory" >&2; exit 2; }
for need in SHA1SUMS SHA256SUMS; do
  [ -s "$dir/$need" ] || { echo "publish-nightly.sh: $dir/$need is missing or empty" >&2; exit 2; }
done
files=("$dir"/securl_* "$dir"/SHA1SUMS "$dir"/SHA256SUMS)
[ "${#files[@]}" -ge 3 ] || { echo "publish-nightly.sh: nothing to publish in $dir" >&2; exit 2; }
command -v gh >/dev/null 2>&1 || { echo "publish-nightly.sh: gh is required" >&2; exit 2; }

notes="Built from commit ${commit} (${version}). This release is replaced every night; the tag \`${tag}\` always points at the latest build.

Check a download against SHA256SUMS (SHA1SUMS is also listed; SHA-1 only catches damage, not tampering)."

# gh exits non-zero for "not found", which is fine here; anything else is a failure the next step would hide, so the
# existence of the old release is asked first.
if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  gh release delete "$tag" --repo "$repo" --yes --cleanup-tag
fi
# A tag with no release (an earlier run died in between) is removed too, so the new tag can point at this commit.
if gh api "repos/${repo}/git/ref/tags/${tag}" >/dev/null 2>&1; then
  gh api -X DELETE "repos/${repo}/git/refs/tags/${tag}" >/dev/null
fi

gh release create "$tag" "${files[@]}" \
  --repo "$repo" \
  --target "$commit" \
  --title "Nightly build (${version})" \
  --notes "$notes" \
  --prerelease

echo "published ${tag} at ${commit}: ${#files[@]} files"
