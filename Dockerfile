# NOTE: pin both base images to digests (`@sha256:…`) before production
# deployment so supply-chain compromise on the upstream tag can't poison a
# rebuild. Tracked separately as a deploy-time concern.

FROM rust:1.88-bookworm AS builder
WORKDIR /app

# Cache dependencies in a separate layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/stripe-subscriber-role target/release/deps/stripe_subscriber_role*

# Build actual source. Release profile already sets `strip = true` in
# Cargo.toml, so no explicit `strip` invocation is needed here.
COPY src/ src/
COPY migrations/ migrations/
COPY templates/ templates/
COPY favicon.ico ./
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    # Create a dedicated unprivileged user. A compromise in the Rust process
    # should not be a compromise of the container root.
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /nonexistent --shell /usr/sbin/nologin app

COPY --from=builder /app/target/release/stripe-subscriber-role /usr/local/bin/

EXPOSE 8096

# Healthcheck mirrors the route exposed by `routes::health::health`. We bind
# to localhost since the container is the only thing on `LISTEN_ADDR`.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --max-time 2 \
        http://127.0.0.1:8096/stripe-subscriber-role/health || exit 1

USER app:app

CMD ["stripe-subscriber-role"]
