#!/usr/bin/env bash
#
# End-to-end container smoke test using Podman.
#
# Builds the MiniCA image, runs it with a disposable persistent /data volume,
# creates a CA through the API, then verifies the Go CLI can issue and download
# a certificate through Basic auth.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-minica:test}"
ADMIN_USER="${MINICA_TEST_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${MINICA_TEST_ADMIN_PASSWORD:-adminpass}"
HOST_PORT="${MINICA_TEST_PORT:-}"
RUN_ID="minica-test-$(date +%s)-$$"
CONTAINER_NAME="$RUN_ID"
VOLUME_NAME="$RUN_ID-data"
OUT_DIR="$ROOT/docker/.test-out/$RUN_ID"
COOKIE_JAR="$OUT_DIR/cookies.txt"

cleanup() {
    set +e
    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1
    podman volume rm "$VOLUME_NAME" >/dev/null 2>&1
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

json_value() {
    local key="$1"
    sed -n "s/.*\"$key\":\"\\([^\"]*\\)\".*/\\1/p" | head -n1
}

require_cmd podman
require_cmd curl
require_cmd go

mkdir -p "$OUT_DIR"
if [ -z "$HOST_PORT" ]; then
    HOST_PORT="$(pick_port)"
fi
BASE_URL="http://127.0.0.1:$HOST_PORT/minica"

echo ">> Building image $IMAGE_TAG"
"$ROOT/docker/build.sh" "$IMAGE_TAG"

echo ">> Creating disposable volume $VOLUME_NAME"
podman volume create "$VOLUME_NAME" >/dev/null

echo ">> Starting container $CONTAINER_NAME on $BASE_URL"
podman run -d \
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
    podman logs "$CONTAINER_NAME" >&2 || true
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

for file in docker-test.pem docker-test.key docker-test.p12 docker-test.p12.password CA.pem; do
    if [ ! -s "$cert_out/$file" ]; then
        echo "error: expected CLI output missing or empty: $cert_out/$file" >&2
        exit 1
    fi
done

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

for file in docker-test-reuse.pem docker-test-reuse.key docker-test-reuse.p12 docker-test-reuse.p12.password CA.pem; do
    if [ ! -s "$reuse_out/$file" ]; then
        echo "error: expected CLI reuse output missing or empty: $reuse_out/$file" >&2
        exit 1
    fi
done

echo ">> Verifying persisted /data volume contents"
for dir in runtime sqlite logs; do
    if ! podman run --rm --entrypoint /bin/bash -v "$VOLUME_NAME:/data:ro" "$IMAGE_TAG" -lc "test -d /data/$dir"; then
        echo "error: expected /data/$dir to exist in volume" >&2
        exit 1
    fi
done
if ! podman run --rm --entrypoint /bin/bash -v "$VOLUME_NAME:/data:ro" "$IMAGE_TAG" -lc "test -s /data/sqlite/db.sqlite"; then
    echo "error: expected /data/sqlite/db.sqlite to exist in volume" >&2
    exit 1
fi

echo ">> Container smoke test passed"
echo "   image: $IMAGE_TAG"
echo "   output: $cert_out"
