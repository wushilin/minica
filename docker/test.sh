#!/usr/bin/env bash
#
# End-to-end container smoke test (Podman by default, Docker with
# MINICA_CONTAINER_ENGINE=docker).
#
# Builds the MiniCA image (or uses MINICA_TEST_IMAGE, already built), runs it with a disposable persistent /data volume,
# creates a CA through the API, then verifies the Go CLI can issue and download
# a certificate through Basic auth.
#
# The CLI output (including private keys) goes to docker/.test-out/<run-id> and
# is removed on exit; set MINICA_TEST_KEEP_OUT=1 to keep it for inspection.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${MINICA_TEST_IMAGE:-${IMAGE_TAG:-minica:test}}"
PREBUILT="${MINICA_TEST_IMAGE:-}"
ENGINE="${MINICA_CONTAINER_ENGINE:-podman}"
ADMIN_USER="${MINICA_TEST_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${MINICA_TEST_ADMIN_PASSWORD:-adminpass}"
HOST_PORT="${MINICA_TEST_PORT:-}"
RUN_ID="minica-test-$(date +%s)-$$"
CONTAINER_NAME="$RUN_ID"
VOLUME_NAME="$RUN_ID-data"
OUT_DIR="$ROOT/docker/.test-out/$RUN_ID"
COOKIE_JAR="$OUT_DIR/cookies.txt"
KEEP_OUT="${MINICA_TEST_KEEP_OUT:-}"

cleanup() {
    set +e
    "$ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1
    "$ENGINE" volume rm "$VOLUME_NAME" >/dev/null 2>&1
    if [ -n "$KEEP_OUT" ]; then
        echo "   kept test output: $OUT_DIR" >&2
    else
        rm -rf "$OUT_DIR"
        rmdir "$ROOT/docker/.test-out" >/dev/null 2>&1
    fi
}
trap cleanup EXIT

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command not found: $1" >&2
        exit 1
    fi
}

pick_port() {
    local port
    for port in 19988 29988 39988 49988 59988; do
        if ! (exec 9<>"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then
            echo "$port"
            return 0
        fi
    done
    echo "error: no free test port found" >&2
    exit 1
}

file_mode() {
    # GNU stat first, then BSD/macOS stat.
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

# check_bundle <dir> <prefix>: all five files exist and are non-empty, and the
# secret files (key, PKCS#12 bundle, its password) are owner-only (600).
check_bundle() {
    local dir="$1" prefix="$2" file mode
    for file in "$prefix.pem" "$prefix.key" "$prefix.p12" "$prefix.p12.password" CA.pem; do
        if [ ! -s "$dir/$file" ]; then
            echo "error: expected CLI output missing or empty: $dir/$file" >&2
            exit 1
        fi
    done
    for file in "$prefix.key" "$prefix.p12" "$prefix.p12.password"; do
        mode="$(file_mode "$dir/$file")"
        if [ "$mode" != "600" ]; then
            echo "error: $dir/$file has mode $mode, expected 600" >&2
            exit 1
        fi
    done
}

json_value() {
    local key="$1"
    sed -n "s/.*\"$key\":\"\\([^\"]*\\)\".*/\\1/p" | head -n1
}

require_cmd "$ENGINE"
require_cmd curl
require_cmd go

mkdir -p "$OUT_DIR"
if [ -z "$HOST_PORT" ]; then
    HOST_PORT="$(pick_port)"
fi
BASE_URL="http://127.0.0.1:$HOST_PORT/minica"

if [ -n "$PREBUILT" ]; then
    echo ">> Using prebuilt image $IMAGE_TAG"
else
    echo ">> Building image $IMAGE_TAG"
    "$ROOT/docker/build.sh" "$IMAGE_TAG"
fi

echo ">> Creating disposable volume $VOLUME_NAME"
"$ENGINE" volume create "$VOLUME_NAME" >/dev/null

echo ">> Starting container $CONTAINER_NAME on $BASE_URL"
"$ENGINE" run -d \
    --name "$CONTAINER_NAME" \
    -p "$HOST_PORT:9988" \
    -v "$VOLUME_NAME:/data" \
    -e MINICA_ADMIN_USER="$ADMIN_USER" \
    -e MINICA_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    "$IMAGE_TAG" >/dev/null

echo ">> Waiting for MiniCA"
ready=0
for _ in $(seq 1 60); do
    if curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" "$BASE_URL/api/cas" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "error: MiniCA did not become ready" >&2
    "$ENGINE" logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi

echo ">> Creating CA through API"
csrf_json="$(curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" -c "$COOKIE_JAR" "$BASE_URL/api/csrf")"
csrf_token="$(printf '%s\n' "$csrf_json" | json_value token)"
if [ -z "$csrf_token" ]; then
    echo "error: could not read CSRF token from: $csrf_json" >&2
    exit 1
fi

ca_json="$(
    curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" \
        -b "$COOKIE_JAR" \
        -H "X-CSRF-Token: $csrf_token" \
        -H "Content-Type: application/json" \
        -X PUT "$BASE_URL/api/cas" \
        --data "{
            \"common_name\":\"Docker Test CA $RUN_ID\",
            \"country_code\":\"US\",
            \"state\":\"Test State\",
            \"city\":\"Test City\",
            \"organization\":\"MiniCA\",
            \"organization_unit\":\"Docker Test\",
            \"valid_days\":3650,
            \"digest_algorithm\":\"sha256\",
            \"key_profile\":\"rsa:2048\",
            \"password\":null
        }"
)"
ca_id="$(printf '%s\n' "$ca_json" | json_value id)"
if [ -z "$ca_id" ]; then
    echo "error: could not read CA id from: $ca_json" >&2
    exit 1
fi
echo "   CA id: $ca_id"

echo ">> Building CLI"
( cd "$ROOT/cli" && go build -o mcacli . )

echo ">> Issuing certificate through CLI"
cert_out="$OUT_DIR/certs"
cert_cn="docker-test-$RUN_ID.example.test"
"$ROOT/cli/mcacli" cert -y \
    --url "$BASE_URL" \
    --user "$ADMIN_USER" \
    --password "$ADMIN_PASSWORD" \
    --ca "$ca_id" \
    --cn "$cert_cn" \
    --hostnames "$cert_cn,127.0.0.1" \
    --country US \
    --org MiniCA \
    --key-profile rsa:2048 \
    --digest sha256 \
    --days 30 \
    --name docker-test \
    --out-dir "$cert_out"

check_bundle "$cert_out" docker-test

echo ">> Reusing/renewing certificate through CLI"
reuse_out="$OUT_DIR/certs-reuse"
"$ROOT/cli/mcacli" cert -y \
    --url "$BASE_URL" \
    --user "$ADMIN_USER" \
    --password "$ADMIN_PASSWORD" \
    --ca "$ca_id" \
    --cn "$cert_cn" \
    --hostnames "$cert_cn,127.0.0.1" \
    --country US \
    --org MiniCA \
    --key-profile rsa:2048 \
    --digest sha256 \
    --days 30 \
    --name docker-test-reuse \
    --out-dir "$reuse_out"

check_bundle "$reuse_out" docker-test-reuse

echo ">> Verifying persisted /data volume contents"
for dir in runtime sqlite logs; do
    if ! "$ENGINE" run --rm --entrypoint /bin/bash -v "$VOLUME_NAME:/data:ro" "$IMAGE_TAG" -lc "test -d /data/$dir"; then
        echo "error: expected /data/$dir to exist in volume" >&2
        exit 1
    fi
done
if ! "$ENGINE" run --rm --entrypoint /bin/bash -v "$VOLUME_NAME:/data:ro" "$IMAGE_TAG" -lc "test -s /data/sqlite/db.sqlite"; then
    echo "error: expected /data/sqlite/db.sqlite to exist in volume" >&2
    exit 1
fi

echo ">> Container smoke test passed"
echo "   image: $IMAGE_TAG"
if [ -n "$KEEP_OUT" ]; then
    echo "   output: $cert_out"
fi
