#!/usr/bin/env bash
# Build the Mode B single-binary collector for every client platform.
# The Bun runtime is embedded: clients install nothing.
# Usage: scripts/build-binaries.sh [target ...]   (default: all targets)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=dist-bin
VERSION="$(node -p 'require("./package.json").version')"
ALL_TARGETS="bun-darwin-arm64 bun-darwin-x64 bun-linux-x64 bun-linux-arm64 bun-windows-x64"
TARGETS="${*:-$ALL_TARGETS}"
mkdir -p "$OUT"
# The JS bundle embedded in every binary is byte-for-byte reproducible from the
# source; publish it and its hash so anyone can check a release against the code.
# (The compiled executables are not bit-identical across builds — Bun writes a
# per-build trailer byte, and macOS builds are ad-hoc signed — so the bundle is the
# reproducible artifact. See scripts/verify-build.sh.)
npx bun build src/bin/collect.ts --minify --target=bun --outfile "$OUT/cf-account-review-collect-${VERSION}.bundle.js"
for t in $TARGETS; do
	name="cf-account-review-collect-${VERSION}-${t#bun-}"
	case "$t" in *windows*) name="$name.exe" ;; esac
	npx bun build src/bin/collect.ts --compile --minify --target="$t" --outfile "$OUT/$name"
done
(cd "$OUT" && shasum -a 256 cf-account-review-collect-* >SHA256SUMS)
cat "$OUT/SHA256SUMS"
