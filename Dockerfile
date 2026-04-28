FROM rust:1.95-bookworm AS build

WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim

RUN useradd --system --uid 10001 --home /var/lib/portless portless \
  && mkdir -p /var/lib/portless \
  && chown -R portless:portless /var/lib/portless

USER portless
COPY --from=build /src/target/release/portless-daemon /usr/local/bin/portless-daemon
ENTRYPOINT ["/usr/local/bin/portless-daemon"]
