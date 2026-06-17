#!/usr/bin/env bash
#
# package.sh - build (via build.sh) and package the MUSL release into
#   dist/minica-<cargo-version>.x64.tar.gz
# a flat tarball containing both the server binary (minica) and the CLI (mcacli).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

TARGET="x86_64-unknown-linux-musl"
SERVER_BIN="target/$TARGET/release/minica"
CLI_BIN="cli/mcacli"

# Build fresh artifacts first.
"$ROOT/build.sh"

# Read the crate version from Cargo.toml ([package] version = "x.y.z").
VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)"
if [ -z "$VERSION" ]; then
    echo "error: could not determine version from Cargo.toml" >&2
    exit 1
fi

TARBALL="minica-${VERSION}.x64.tar.gz"
DIST="$ROOT/dist"

for f in "$SERVER_BIN" "$CLI_BIN"; do
    if [ ! -f "$f" ]; then
        echo "error: expected artifact missing: $f" >&2
        exit 1
    fi
done

# Stage the binaries flat (no top-level directory inside the tarball).
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp "$SERVER_BIN" "$STAGE/minica"
cp "$CLI_BIN" "$STAGE/mcacli"
chmod +x "$STAGE/minica" "$STAGE/mcacli"

mkdir -p "$DIST"
rm -f "$DIST/$TARBALL"
tar -czf "$DIST/$TARBALL" -C "$STAGE" minica mcacli

echo ">> Packaged dist/$TARBALL"
tar -tzf "$DIST/$TARBALL"
