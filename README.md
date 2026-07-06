# Portless Client

[![Client CI/CD](https://github.com/CRBL-Technologies/portless-client/actions/workflows/ci-cd.yml/badge.svg?branch=main)](https://github.com/CRBL-Technologies/portless-client/actions/workflows/ci-cd.yml?query=branch%3Amain)
[![Security](https://github.com/CRBL-Technologies/portless-client/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/CRBL-Technologies/portless-client/actions/workflows/security.yml?query=branch%3Amain)

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

## Managed Portainer Deployments

`docker-compose.deploy.yml` is the Portainer stack template used by CI. The
stack owns customer-specific settings, including `PORTLESS_DEVICE_TOKEN`; CI only
updates the stack file and `PORTLESS_CLIENT_IMAGE`.

Managed stacks run the daemon on Docker bridge networking and map
`host.docker.internal` to the Docker host gateway. When Plex Media Server runs on
the Docker host, use `PORTLESS_PMS_URL=http://host.docker.internal:32400` so
Plex sees tunnel traffic as non-loopback traffic for its native bandwidth graph.

Required stack environment:

- `PORTLESS_DEVICE_TOKEN`
- `PORTLESS_CONTROL_URL`
- `PORTLESS_PMS_URL`
- `PORTLESS_CONTAINER_NAME`
- `PORTLESS_CLIENT_IMAGE`

Optional stack environment:

- `PORTLESS_UI_ADDR` - container bind address, default `0.0.0.0:43180`.
- `PORTLESS_UI_PUBLISH_ADDR` - host-side UI publish address, default
  `127.0.0.1:43180`.

The GitHub `staging` and `production` environments must provide:

- `OP_SERVICE_ACCOUNT_TOKEN` as a secret.
- `OP_ENVIRONMENT_ID`
- `PORTLESS_CLIENT_NAS_DEPLOY_API_URL`
- `PORTLESS_CLIENT_NAS_DEPLOY_API_KEY` as a secret.
- `PORTLESS_CLIENT_NAS_STACK_ID`
- `PORTLESS_CLIENT_NAS_DEPLOY_ENDPOINT_ID`

The 1Password Environment referenced by `OP_ENVIRONMENT_ID` provides the
primary deploy target:

- `PORTLESS_CLIENT_DEPLOY_API_URL`
- `PORTLESS_CLIENT_DEPLOY_API_KEY`
- `PORTLESS_CLIENT_STACK_ID`
- `CF_ACCESS_CLIENT_ID`
- `CF_ACCESS_CLIENT_SECRET`

`main` publishes the production image but does not deploy it automatically.
`dev` deploys both configured staging targets. Production deployment is manual:
run the `Deploy Production Client` workflow from GitHub after the main CI run
has published the image you want to ship.

## Images and Verification

The public daemon image is published to
`ghcr.io/crbl-technologies/portless-client`. Production builds publish immutable
`sha-<commit>` tags plus `prod` and `latest`; staging builds publish `dev`.

CI publishes build provenance, an SBOM, and keyless cosign signatures. Verify a
production image with:

```sh
cosign verify \
  --certificate-identity-regexp 'https://github.com/CRBL-Technologies/portless-client/.github/workflows/ci-cd.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/crbl-technologies/portless-client:prod
```

## Check

```sh
cargo fmt -- --check
cargo test --locked
cargo clippy --locked -- -D warnings
cargo deny check advisories bans licenses sources
```

`cargo deny` intentionally leaves duplicate-version warnings visible. Security
reporting and sensitive-data guidance are in [SECURITY.md](SECURITY.md).
