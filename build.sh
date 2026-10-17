#!/usr/bin/env bash
#
# build.sh - build the MiniCA server (static MUSL binary) and the Go CLI.
#
# Outputs:
#   target/<target>/release/minica   (server)
#   cli/mcacli                       (CLI)
#
# <target> defaults to the host architecture's MUSL triple
# (x86_64-unknown-linux-musl or aarch64-unknown-linux-musl); override it with
# MINICA_TARGET=<rust-target-triple>.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
