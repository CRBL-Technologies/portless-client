# Portless Client

[![Client CI/CD](https://github.com/CRBL-Technologies/portless-client/actions/workflows/ci-cd.yml/badge.svg?branch=dev)](https://github.com/CRBL-Technologies/portless-client/actions/workflows/ci-cd.yml?query=branch%3Adev)
[![Security](https://github.com/CRBL-Technologies/portless-client/actions/workflows/security.yml/badge.svg?branch=dev)](https://github.com/CRBL-Technologies/portless-client/actions/workflows/security.yml?query=branch%3Adev)

Customer-side Portless daemon.

The daemon uses a reveal-once device token to register with the control plane,
opens a QUIC/mTLS tunnel to the relay, and forwards public tunnel traffic to the
configured local Plex URL.

## Requirements

- Rust `1.95.0`
- Docker Compose for the example stack

## Configuration

- `PORTLESS_DEVICE_TOKEN` - reveal-once daemon token from the join/admin flow.
- `PORTLESS_CONTROL_URL` - daemon bootstrap URL, normally
  `https://connect.portless.io` in production.
- `PORTLESS_PMS_URL` - local Plex URL, for example `http://192.168.1.42:32400`.
- `PORTLESS_DATA_DIR` - daemon state directory, default `/var/lib/portless`.
- `PORTLESS_UI_ADDR` - status UI bind address, default `127.0.0.1:43180`; set
  to `off` to disable.
- `PORTLESS_KEEPALIVE_PROFILE` - `residential`, `cellular`, or `conservative`.
- `PORTLESS_DEVICE_KEY_SECRET` - optional external secret for encrypting the
  local daemon private key.

The status UI is available at `/`; machine-readable state is available at
`/status.json`.

## Run With Compose

```sh
cp .env.example .env
docker compose -f docker-compose.example.yml up --build
```

Open `http://127.0.0.1:43180/` for local daemon status.

## Check

```sh
cargo fmt -- --check
cargo test --locked
cargo clippy --locked -- -D warnings
cargo deny check advisories bans licenses sources
```

`cargo deny` intentionally leaves duplicate-version warnings visible. Review
[SECURITY.md](SECURITY.md) and
[docs/public-readiness.md](docs/public-readiness.md) before changing repository
visibility.
