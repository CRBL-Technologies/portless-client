FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
  && printf 'fn main() {}\n' > src/main.rs \
  && cargo build --release --locked \
  && rm -rf src
COPY src ./src
RUN touch src/main.rs
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
LABEL org.opencontainers.image.source="https://github.com/CRBL-Technologies/portless-client"

RUN useradd --system --uid 10001 --home /var/lib/portless portless \
  && mkdir -p /var/lib/portless \
  && chown -R portless:portless /var/lib/portless

USER portless
COPY --from=build /src/target/release/portless-daemon /usr/local/bin/portless-daemon
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 CMD ["/usr/local/bin/portless-daemon", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/portless-daemon"]
