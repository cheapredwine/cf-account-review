#!/usr/bin/env bash
# Build the standalone cf-account-review binary (Node single-executable).
#
#   scripts/build-binary.sh [node-version]
#
# The SEA embed requires a node binary built with single-executable support —
# distro/Homebrew builds ship it disabled — so this script downloads the
# official nodejs.org build for the current platform (default: the project's
# LTS line), bundles the CLI with esbuild, embeds it, and (on macOS) ad-hoc
# codesigns the result. Output: dist/cf-account-review[-<os>-<arch>].
set -euo pipefail
cd "$(dirname "$0")/.."

NODE_VERSION="${1:-}"
if [ -z "$NODE_VERSION" ]; then
	# default: latest v24 LTS (matches .nvmrc)
	NODE_VERSION="$(curl -fsSL https://nodejs.org/dist/index.json |
		jq -r '[.[] | select(.version | startswith("v24."))][0].version' |
		tr -d v)"
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')" # darwin | linux
ARCH="$(uname -m)"                            # arm64/aarch64 or x86_64
case "$ARCH" in
arm64) ARCH="arm64" ;;
x86_64) ARCH="x64" ;;
aarch64) ARCH="arm64" ;;
*)
	echo "unsupported arch: $ARCH" >&2
	exit 1
	;;
esac

CACHE=".cache/node-v${NODE_VERSION}-${OS}-${ARCH}"
TARBALL="${CACHE}.tar.gz"
URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-${OS}-${ARCH}.tar.gz"

if [ ! -x "${CACHE}/bin/node" ]; then
	echo "downloading official node v${NODE_VERSION} (${OS}-${ARCH}) for the SEA embed…"
	mkdir -p .cache
	curl -fsSL -o "$TARBALL" "$URL"
	tar -xzf "$TARBALL" -C .cache
	rm -f "$TARBALL"
fi
SEA_NODE="${CACHE}/bin/node"

echo "bundling CLI with esbuild…"
pnpm build
./node_modules/.bin/esbuild dist/cli.js --bundle --platform=node --format=cjs \
	--outfile=dist/cli.bundle.cjs

cat >sea-config.json <<'EOF'
{
	"main": "dist/cli.bundle.cjs",
	"output": "dist/sea.blob",
	"disableExperimentalSEAWarning": true
}
EOF

echo "generating SEA blob…"
"$SEA_NODE" --experimental-sea-config sea-config.json

OUT="dist/cf-account-review-${OS}-${ARCH}"
echo "embedding into node binary -> ${OUT}"
cp "${SEA_NODE}" "$OUT"
chmod +w "$OUT"
if [ "$OS" = "darwin" ]; then
	codesign --remove-signature "$OUT" 2>/dev/null || true
fi
# The SEA fuse sentinel string differs across node versions — read it from
# the binary rather than hardcoding the value from older docs.
SENTINEL="$(grep -aoE 'NODE_SEA_FUSE_[a-f0-9]{32}' "${SEA_NODE}" | awk 'NR==1{print; exit}')"
if [ -z "$SENTINEL" ]; then
	echo "error: no SEA fuse sentinel found in the node binary" >&2
	exit 1
fi
./node_modules/.bin/postject "$OUT" NODE_SEA_BLOB dist/sea.blob \
	--sentinel-fuse "$SENTINEL" \
	$([ "$OS" = "darwin" ] && echo "--macho-segment-name NODE_SEA")
if [ "$OS" = "darwin" ]; then
	codesign --sign - "$OUT"
fi
chmod +x "$OUT"

echo "smoke:"
if "$OUT" --help >/dev/null 2>&1; then
	echo "  --help ok"
else
	echo "  error: binary --help failed" >&2
	exit 1
fi
echo "binary ready: $OUT"
