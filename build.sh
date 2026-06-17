#!/usr/bin/env bash
#
# build.sh - build the MiniCA server (static MUSL binary) and the Go CLI.
#
# Outputs:
#   target/x86_64-unknown-linux-musl/release/minica   (server)
#   cli/mcacli                                         (CLI)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

TARGET="x86_64-unknown-linux-musl"

echo ">> Building MiniCA server ($TARGET, release)"
# Ensure the MUSL target is installed (no-op if already present).
if command -v rustup >/dev/null 2>&1; then
    rustup target add "$TARGET" >/dev/null 2>&1 || true
fi
cargo build --target "$TARGET" --release

echo ">> Building CLI (cli/mcacli)"
( cd cli && go build -o mcacli . )

echo ">> Done."
echo "   server: target/$TARGET/release/minica"
echo "   cli:    cli/mcacli"
