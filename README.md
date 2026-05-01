# Portless Client

Rust daemon for the customer-side Portless tunnel.

The MVP install path is Docker Compose only. The daemon reads a reveal-once
device token, fetches trust and tunnel config from the control plane, stores
local state under a data directory, opens a QUIC/mTLS tunnel to the relay, and
forwards relay HTTP requests to the configured local Plex URL.

## Environment

- `PORTLESS_DEVICE_TOKEN` - reveal-once daemon token from the admin/control surface.
- `PORTLESS_PMS_URL` - Plex Media Server URL, default `http://plex:32400`.
- `PORTLESS_CONTROL_URL` - control-plane URL, default `https://join.portless.io`.
- `PORTLESS_DATA_DIR` - daemon state directory, default `/var/lib/portless`.
- `PORTLESS_KEEPALIVE_PROFILE` - `residential`, `cellular`, or `conservative`.
- `PORTLESS_UI_ADDR` - local status UI bind address, default `127.0.0.1:43180`; set to `off` to disable.

The client status UI exposes the current tunnel identity and daemon settings on
`/`, plus machine-readable status on `/status.json`. It never displays the
device token.

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
