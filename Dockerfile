# fj-relay — filejaunt's signaling relay, ready for any Docker host
# (Dokploy, Fly, plain docker). Context: repository root.
#
#   docker build -t fj-relay .
#   docker run -p 8088:8088 fj-relay          # ws://host:8088/ws
#
# Behind Dokploy's Traefik: expose port 8088, route relay.example.com → 8088;
# Traefik terminates TLS (clients then use wss://) and appends the client IP
# to X-Forwarded-For, which the relay uses for its per-IP connection cap.
FROM rust:1-slim-bookworm AS build
WORKDIR /src

# workspace manifests first: dependency layers stay cached across code changes
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo .cargo
COPY crates crates
COPY tests tests

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p fj-relay \
    && cp target/release/fj-relay /fj-relay

# glibc runtime only: no shell, no package manager, runs as nonroot
FROM gcr.io/distroless/cc-debian12
COPY --from=build /fj-relay /usr/local/bin/fj-relay
EXPOSE 8088
USER nonroot
ENTRYPOINT ["/usr/local/bin/fj-relay"]
CMD ["8088"]
