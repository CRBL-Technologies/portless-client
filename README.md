# Portless Client

[![Client CI/CD](https://github.com/CRBL-Technologies/portless-client/actions/workflows/ci-cd.yml/badge.svg?branch=dev)](https://github.com/CRBL-Technologies/portless-client/actions/workflows/ci-cd.yml?query=branch%3Adev)
[![Security](https://github.com/CRBL-Technologies/portless-client/actions/workflows/security.yml/badge.svg?branch=dev)](https://github.com/CRBL-Technologies/portless-client/actions/workflows/security.yml?query=branch%3Adev)

Rust daemon for the customer-side Portless tunnel.

The MVP install path is Docker Compose only. The daemon reads a reveal-once
device token, fetches trust and tunnel config from the control plane, stores
local state under a data directory, opens a QUIC/mTLS tunnel to the relay, and
forwards relay HTTP requests to the configured local Plex URL.

## Environment

- `PORTLESS_DEVICE_TOKEN` - reveal-once daemon token from the admin/control surface.
- `PORTLESS_PMS_URL` - Plex Media Server URL, default `http://plex:32400`.
- `PORTLESS_CONTROL_URL` - daemon bootstrap/control URL, default `https://connect.portless.io`. Do not point this at the Access-protected join/admin hosts.
- `PORTLESS_DATA_DIR` - daemon state directory, default `/var/lib/portless`.
- `PORTLESS_KEEPALIVE_PROFILE` - `residential`, `cellular`, or `conservative`.
- `PORTLESS_UI_ADDR` - local status UI bind address, default `127.0.0.1:43180`; set to `off` to disable.
- `PORTLESS_DEVICE_KEY_SECRET` - optional external secret for encrypting the
  daemon private key. If unset, the daemon creates `device.key.secret` under
  `PORTLESS_DATA_DIR` and stores only `device.key.pem.enc` for the key itself.

The client status UI exposes the public tunnel URL and daemon settings on `/`,
plus machine-readable status on `/status.json`. Status values distinguish
startup, relay reachability, relay disconnects, and local PMS reachability. The
UI never displays the device token.

## Local Compose

```sh
cp .env.example .env
docker compose -f docker-compose.example.yml up --build
```

Open `http://127.0.0.1:43180/` to inspect the local daemon status page.

Rust tooling is required to run local checks:

```sh
cargo fmt
cargo test
```

Before changing repository visibility, review [SECURITY.md](SECURITY.md) and [docs/public-readiness.md](docs/public-readiness.md).
