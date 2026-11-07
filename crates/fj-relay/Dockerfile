# syntax=docker/dockerfile:1
# fj-relay — static musl binary on scratch. Zero state: no env, no volumes.
#
# Build context must be the REPO ROOT (Dokploy: build type Dockerfile, path
# crates/fj-relay/Dockerfile):
#   docker build -f crates/fj-relay/Dockerfile .
FROM rust:alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --release -p fj-relay && strip target/release/fj-relay

FROM scratch
COPY --from=build /src/target/release/fj-relay /fj-relay
USER 65534:65534
EXPOSE 8088
ENTRYPOINT ["/fj-relay"]
