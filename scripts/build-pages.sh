#!/usr/bin/env bash
# Assembles the GitHub Pages site for the static login page.
# The page files are published byte-for-byte as they are embedded in the `securl` binary, so a user can
# compare the hosted page with `securl page` (which prints the same SHA-256 sums) before trusting it.
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd)/internal/web/static"
out="${1:?usage: build-pages.sh <output-dir>}"

rm -rf "$out"
mkdir -p "$out"
cp "$src"/index.html "$src"/securl.css "$src"/securl.js "$src"/openpgp.min.js "$out"/
touch "$out/.nojekyll"
printf 'User-agent: *\nDisallow: /\n' > "$out/robots.txt"
(cd "$out" && sha256sum index.html securl.css securl.js openpgp.min.js > SHA256SUMS)
echo "built $out:"
cat "$out/SHA256SUMS"
