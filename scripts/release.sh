#!/usr/bin/env bash
# Builds securl for every supported platform into <dir>, packs each build, and writes SHA1SUMS and SHA256SUMS next to
# the archives. Used by .github/workflows/release.yml, and runnable by hand to check what a release would contain.
#
#   scripts/release.sh dist nightly-20261012-1a2b3c4
#
# Every build is static (CGO off) and does not embed the working tree's state, so the same source gives the same bytes.
set -euo pipefail

dir="${1:?usage: release.sh <output dir> <version>}"
version="${2:?usage: release.sh <output dir> <version>}"

# The version goes into file names and into what `securl version` prints, so it is held to a fixed shape: the word
# nightly, a date, and a short commit. Nothing a person pushes (a branch or tag name) can reach it.
if ! [[ "$version" =~ ^nightly-[0-9]{8}-[0-9a-f]{7,40}$ ]]; then
  echo "release.sh: version must look like nightly-YYYYMMDD-<commit>, got '$version'" >&2
  exit 2
fi

for tool in go tar zip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "release.sh: $tool is required" >&2; exit 2; }
done
if ! command -v sha1sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "release.sh: sha1sum (or shasum) is required" >&2
  exit 2
fi

# The platforms a person is likely to run an MCP server on. securl uses ssh as a tool, so it needs no more than a binary.
targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)
module="github.com/LeafAI/securl"

rm -rf "$dir"
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)" # absolute, because the archives are written from other directories
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  name="securl_${version}_${os}_${arch}"
  bin="securl"
  [ "$os" = "windows" ] && bin="securl.exe"

  mkdir -p "$stage/$name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X ${module}/internal/mcpserver.Version=${version}" \
    -o "$stage/$name/$bin" .
  cp LICENSE "$stage/$name/" 2>/dev/null || true
  cp README.md THIRD_PARTY_NOTICES.md "$stage/$name/"

  if [ "$os" = "windows" ]; then
    (cd "$stage" && zip -q -r "$dir/$name.zip" "$name")
  else
    if tar --version 2>/dev/null | grep -q "GNU tar"; then
      # A fixed owner, order and time keep the archive from depending on who built it and when.
      tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime='2000-01-01 00:00:00 UTC' \
        -czf "$dir/$name.tar.gz" "$name"
    else
      tar -C "$stage" -czf "$dir/$name.tar.gz" "$name"
    fi
  fi
  # `releases/latest/download/<file>` needs a file name that does not change from release to release, so the same archive
  # is also published under a name without the version. The versioned one says what it is; this one never goes stale.
  archive="$(ls "$dir/$name".*)"
  cp "$archive" "$dir/securl_${os}_${arch}.${archive#"$dir/$name".}"
  echo "built $name"
done

# The checksum files list bare file names, so that `sha1sum --check SHA1SUMS` works in the directory the files were
# downloaded to. SHA-1 is offered because it is what was asked for and is enough to catch a damaged download; SHA-256 is
# the one to rely on against tampering, because SHA-1 collisions can be made.
cd "$dir"
files=(securl_*)
if command -v sha1sum >/dev/null 2>&1; then
  sha1sum "${files[@]}" > SHA1SUMS
  sha256sum "${files[@]}" > SHA256SUMS
else
  shasum -a 1 "${files[@]}" > SHA1SUMS
  shasum -a 256 "${files[@]}" > SHA256SUMS
fi
echo "wrote SHA1SUMS and SHA256SUMS for ${#files[@]} files"
