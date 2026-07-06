# MiniCA container image.
#
# Build context is the repository root, and the server binary must be built
# first (build.sh produces a static MUSL binary, so it runs on Alpine as-is):
#
#   ./build.sh
#   podman build -f docker/Dockerfile -t minica .
#
# Run with all state on a /data volume; every config value can be overridden
# per-container via MINICA_* variables (see config.yaml.docker):
#
#   podman run -p 9988:9988 -v minica-data:/data \
#     -e MINICA_ADMIN_PASSWORD='$2b$12$...' \
#     -e MINICA_HEADER_AUTH_ENABLE=true \
#     -e MINICA_TRUSTED_REMOTE_1=10.0.0.7 \
#     minica

FROM alpine:3.22

# openssl: MiniCA shells out to the openssl binary for all crypto operations.
# bash: included for operators who want an interactive shell in the container.
RUN apk add --no-cache openssl bash \
    && mkdir -p /opt/minica /data

COPY target/x86_64-unknown-linux-musl/release/minica /opt/minica/minica
COPY config.yaml.docker /opt/minica/config.yaml

# Route all mutable state under the /data volume.
ENV MINICA_RUNTIME_FOLDER=/data/runtime \
    MINICA_DB_FOLDER=/data/sqlite \
    MINICA_LOG_FILE=/data/logs/minica.log \
    MINICA_OPENSSL_WORKING_ROOT=/data/runtime/openssl-work \
    MINICA_OPENSSL_PATH=/usr/bin/openssl

WORKDIR /data
VOLUME /data
EXPOSE 9988

ENTRYPOINT ["/opt/minica/minica", "--start", "-c", "/opt/minica/config.yaml"]
