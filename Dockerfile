FROM rust:1.95-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src \
  && printf 'fn main() {}\n' > src/main.rs \
  && cargo build --release \
  && rm -rf src
COPY src ./src
RUN touch src/main.rs
RUN cargo build --release

FROM debian:bookworm-slim

RUN useradd --system --uid 10001 --home /var/lib/portless portless \
  && mkdir -p /var/lib/portless \
  && chown -R portless:portless /var/lib/portless

USER portless
COPY --from=build /src/target/release/portless-daemon /usr/local/bin/portless-daemon
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 CMD ["/usr/local/bin/portless-daemon", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/portless-daemon"]
