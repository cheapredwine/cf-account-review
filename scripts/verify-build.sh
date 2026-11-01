#!/usr/bin/env bash
# Verify that a release was built from this source.
#
# Rebuilds the collector's JS bundle (the code embedded in every release binary)
# from the checked-out source and compares its SHA-256 with the release's
# SHA256SUMS. Requires the repo's pinned toolchain: `pnpm install` (Bun is a
# pinned dev dependency).
#
# Usage: scripts/verify-build.sh path/to/SHA256SUMS
#
# The compiled executables themselves are not bit-identical between builds, so to
# remove all trust in our binaries, build your own: scripts/build-binaries.sh <target>.
set -euo pipefail
cd "$(dirname "$0")/.."
SUMS="${1:?usage: scripts/verify-build.sh path/to/SHA256SUMS}"
VERSION="$(node -p 'require("./package.json").version')"
NAME="cf-account-review-collect-${VERSION}.bundle.js"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
npx bun build src/bin/collect.ts --minify --target=bun --outfile "$TMP/$NAME" >/dev/null
local_sum="$(shasum -a 256 "$TMP/$NAME" | cut -d' ' -f1)"
release_sum="$(grep " $NAME\$" "$SUMS" | cut -d' ' -f1 || true)"
if [ -z "$release_sum" ]; then
	echo "FAIL: $NAME not listed in $SUMS (version mismatch? checked-out source is $VERSION)" >&2
	exit 1
fi
if [ "$local_sum" = "$release_sum" ]; then
	echo "OK: $NAME from this source matches the release ($local_sum)"
else
	echo "FAIL: bundle built from this source ($local_sum) differs from the release ($release_sum)" >&2
	exit 1
fi
