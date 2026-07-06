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
#   /data                  working directory and persistent volume
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${1:-minica:local}"

cd "$ROOT"

echo ">> Building MiniCA release binary"
"$ROOT/build.sh"

echo ">> Building container image ($IMAGE_TAG)"
podman build -f "$ROOT/docker/Dockerfile" -t "$IMAGE_TAG" "$ROOT"

echo ">> Done."
echo "   image: $IMAGE_TAG"
