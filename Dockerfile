# syntax=docker/dockerfile:1.7
#
# Bloom Broker service image.
#
#   docker build -t bloom-broker .
#
# The workspace pulls several dependencies straight from bloom-directory Git
# repositories. If those are private, pass credentials to the build without
# baking them into a layer, e.g.
#
#   docker build --secret id=git_credentials,src=$HOME/.git-credentials .
#
# The secret is optional; public checkouts build with no secret at all.

ARG RUST_VERSION=1.96.0

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-bookworm AS builder
ARG RUST_VERSION

WORKDIR /usr/src/bloom-broker

# rust-toolchain.toml asks for `stable`, which would make rustup download a
# second, unpinned toolchain inside the image. Pin the build to the toolchain
# the base image already ships.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0

# Dependency layer: manifests only, with placeholder targets so Cargo can parse
# the workspace. Editing Broker sources leaves this layer — and every crate it
# downloaded — cached.
COPY Cargo.toml Cargo.lock ./
COPY crates/bloom-broker/Cargo.toml crates/bloom-broker/Cargo.toml
COPY crates/bloom-broker-api/Cargo.toml crates/bloom-broker-api/Cargo.toml
COPY crates/bloom-broker-debug-driver/Cargo.toml crates/bloom-broker-debug-driver/Cargo.toml
RUN mkdir -p crates/bloom-broker/src \
             crates/bloom-broker-api/src \
             crates/bloom-broker-debug-driver/src \
 && echo 'fn main() {}' | tee crates/bloom-broker/src/main.rs \
                              crates/bloom-broker-debug-driver/src/main.rs > /dev/null \
 && touch crates/bloom-broker/src/lib.rs \
          crates/bloom-broker-api/src/lib.rs \
          crates/bloom-broker-debug-driver/src/lib.rs

RUN --mount=type=secret,id=git_credentials,target=/root/.git-credentials,required=false \
    if [ -s /root/.git-credentials ]; then git config --global credential.helper store; fi; \
    cargo fetch --locked

# Real sources. Placeholder targets are overwritten; nothing was compiled
# against them, so no stale artifacts survive into the release build.
COPY crates crates

# The release profile is the only build artifact that leaves this stage, so the
# target directory lives in a BuildKit cache mount rather than an image layer.
RUN --mount=type=cache,target=/usr/src/bloom-broker/target,sharing=locked \
    --mount=type=secret,id=git_credentials,target=/root/.git-credentials,required=false \
    if [ -s /root/.git-credentials ]; then git config --global credential.helper store; fi; \
    cargo build --release --locked --package bloom-broker \
 && install -m 0755 target/release/bloom-broker /usr/local/bin/bloom-broker

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="bloom-broker" \
      org.opencontainers.image.source="https://github.com/bloom-directory/bloom-broker"

# No apt packages are installed on purpose: the release binary links only
# libc, libm, libgcc_s and the dynamic loader, all of which debian:bookworm-slim
# already provides. SQLite is statically linked (rusqlite "bundled") and no
# outbound TLS is performed, so neither libsqlite3 nor ca-certificates apply.

# Broker authenticates peers by effective UID against the edge manifest's
# `broker.effective_uid`, so this UID must match the deployment's manifest.
ARG BLOOM_UID=10001
ARG BLOOM_GID=10001
RUN groupadd --system --gid "${BLOOM_GID}" bloom \
 && useradd --system --uid "${BLOOM_UID}" --gid bloom \
      --home-dir /var/lib/bloom --shell /usr/sbin/nologin bloom \
 && install -d -o bloom -g bloom -m 0700 /var/lib/bloom \
 && install -d -o bloom -g bloom -m 0700 /var/db/bloom/broker \
 && install -d -o bloom -g bloom -m 0700 /var/db/bloom/broker/audit-checkpoints \
 && install -d -o bloom -g bloom -m 0755 /run/bloom \
 && install -d -o root  -g root  -m 0755 /etc/bloom

COPY --from=builder /usr/local/bin/bloom-broker /usr/local/bin/bloom-broker

# Mounted at runtime, not baked in:
#   /etc/bloom/broker.json                 mode 0600 or stricter, readable by bloom
#   /etc/bloom/edge-manifest.json          edge manifest
#   /etc/bloom/authority-edge-history.json root-owned
#   the provenance catalog named by broker.json's `provenance_catalog_path`,
#                                          root-owned and not group/other writable
# BLOOM_BROKER_SOCKET and BLOOM_BROKER_CONTROL_SOCKET are required on Linux;
# BLOOM_BROKER_STARTUP_STATUS, if set, must live in a bloom-owned 0750 directory.

USER bloom
WORKDIR /var/lib/bloom

ENTRYPOINT ["/usr/local/bin/bloom-broker"]
