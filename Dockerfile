# syntax=docker/dockerfile:1.4
FROM rust:1-bookworm AS build

RUN cargo install sccache --version ^0.8
ENV RUSTC_WRAPPER=sccache SCCACHE_DIR=/sccache

RUN USER=root cargo new --bin badgeblue
RUN mkdir -p /app/
WORKDIR /app/

RUN --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=static,target=static \
    --mount=type=bind,source=templates,target=templates \
    --mount=type=bind,source=build.rs,target=build.rs \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    <<EOF
set -e
cargo build --locked --release --target-dir . --no-default-features -F embed
EOF

FROM debian:bookworm-slim

RUN set -x \
    && apt-get update \
    && apt-get install ca-certificates -y

RUN groupadd -g 1504 -r badgeblue && useradd -u 1505 -r -g badgeblue -d /var/lib/badgeblue -m badgeblue

ENV RUST_LOG=info
ENV RUST_BACKTRACE=full

COPY --from=build /app/badgeblue/badgeblue /var/lib/badgeblue/

RUN chown -R badgeblue:badgeblue /var/lib/badgeblue

WORKDIR /var/lib/badgeblue

USER badgeblue
ENTRYPOINT ["sh", "-c", "/var/lib/badgeblue/badgeblue"]
