#!/usr/bin/env bash
#
# Build the MiniCA container image locally with Podman.
#
# Usage:
#   docker/build.sh [image-tag]
#
# The image expects:
#   /opt/minica/minica      server binary
#   /opt/minica/config.yaml Docker config
#   /data                  working directory and persistent volume (owned by
#                           the non-root "minica" user, uid/gid 10001)
#
# The server is built for the host architecture by default; set
# MINICA_TARGET=<rust-target-triple> (e.g. aarch64-unknown-linux-musl) to
# override it. The image platform follows the target.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${1:-minica:local}"

cd "$ROOT"

default_target() {
    case "$(uname -m)" in
        x86_64 | amd64) echo "x86_64-unknown-linux-musl" ;;
        aarch64 | arm64) echo "aarch64-unknown-linux-musl" ;;
        *)
            echo "error: unsupported host architecture $(uname -m); set MINICA_TARGET" >&2
            exit 1
            ;;
    esac
}

TARGET="${MINICA_TARGET:-$(default_target)}"
export MINICA_TARGET="$TARGET"
case "$TARGET" in
    x86_64-*) PLATFORM="linux/amd64" ;;
    aarch64-*) PLATFORM="linux/arm64" ;;
    *)
        echo "error: no container platform known for target $TARGET" >&2
        exit 1
        ;;
esac

echo ">> Building MiniCA release binary"
"$ROOT/build.sh"

echo ">> Building container image ($IMAGE_TAG)"
podman build -f "$ROOT/docker/Dockerfile" \
    --platform "$PLATFORM" \
    --build-arg "RUST_TARGET=$TARGET" \
    -t "$IMAGE_TAG" "$ROOT"

echo ">> Done."
echo "   image: $IMAGE_TAG ($PLATFORM)"
