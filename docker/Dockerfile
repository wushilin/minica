# MiniCA container image.
#
# Build context is the repository root, and the server binary must be built
# first (build.sh produces a static MUSL binary, so it runs on Alpine as-is):
#
#   ./build.sh
#   podman build -f docker/Dockerfile -t minica .
#
# The binary path defaults to the x86_64 MUSL target; on other hosts pass the
# target triple build.sh used (docker/build.sh does this automatically):
#
#   podman build -f docker/Dockerfile --build-arg RUST_TARGET=aarch64-unknown-linux-musl -t minica .
#
# The server runs as the non-root user "minica" (uid/gid 10001). A fresh named
# volume inherits /data's ownership from the image; a bind mount, or a volume
# created by an older image that ran as root, must be owned by 10001:10001:
#
#   podman unshare chown -R 10001:10001 <dir>   # rootless podman bind mount
#   sudo chown -R 10001:10001 <dir>             # docker / rootful
#
# MINICA_ADMIN_PASSWORD defaults to "adminpass" (see config.yaml.docker):
# always override it outside of throwaway test containers.
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

ARG RUST_TARGET=x86_64-unknown-linux-musl

# openssl: MiniCA shells out to the openssl binary for all crypto operations.
# bash: included for operators who want an interactive shell in the container.
# minica (uid/gid 10001): unprivileged account the server runs as; it owns /data.
RUN apk add --no-cache openssl bash \
    && addgroup -S -g 10001 minica \
    && adduser -S -D -H -u 10001 -G minica -h /data -s /sbin/nologin minica \
    && mkdir -p /opt/minica /data \
    && chown minica:minica /data \
    && chmod 0750 /data

COPY target/${RUST_TARGET}/release/minica /opt/minica/minica
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

USER minica:minica

ENTRYPOINT ["/opt/minica/minica", "--start", "-c", "/opt/minica/config.yaml"]
