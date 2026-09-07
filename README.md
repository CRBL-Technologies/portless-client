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
has published the image you want to ship. Supply `client_image` as
`ghcr.io/crbl-technologies/portless-client:sha-<full commit SHA>`; mutable
`prod`/`latest` tags are not accepted by the production deployment workflow.

## Network Boundary And Firewall Recommendations

Public requests are forwarded only to the origin configured in
`PORTLESS_PMS_URL`. Request paths and headers cannot select another destination.
The daemon does not follow Plex redirects, does not use environment HTTP proxies
for Plex requests, and rejects HTTP `CONNECT`. WebSocket upgrades remain on the
connection to that same Plex server. Point this setting directly at Plex, not a
general-purpose HTTP proxy or a reverse proxy serving other local applications.

Plex still owns authentication and authorization for its exposed endpoints.
Keep Plex patched and do not include the daemon's source address or Docker
subnet in Plex's **List of IP addresses and networks that are allowed without
auth**. Doing so can make tunneled Internet traffic exempt from authentication.
See [Plex local-network authentication](https://support.plex.tv/articles/200890058-authentication-for-local-network-access/).

The Compose templates run the non-root image with all capabilities dropped,
`no-new-privileges`, and a read-only root filesystem. Only the state volume is
writable. These restrictions are not an outbound network firewall: compromise
of the daemon or Plex requires a separate host/router boundary for containment.
No firewall helper is installed by Portless.

Recommended host-owned policy, scoped to the daemon's container network:

| Traffic | Allow |
| --- | --- |
| Plex | Only the configured Plex IP and TCP port (normally `32400`). |
| Control | The configured control endpoint's IPs and TCP port (normally `connect.portless.io:443`). |
| Relay | The assigned relay endpoint's IPs and UDP port (normally `443`; use its actual configured port). |
| DNS | Only your chosen resolver's IP, UDP/TCP `53`, when name resolution is needed. |
| Replies | Responses to permitted connections and your explicitly allowed local status-UI connections. |
| Other destinations | Deny, including NAS administration, other host ports, sibling containers, and other LANs. |

Apply equivalent IPv4 and IPv6 policy, or disable IPv6 for this network. Keep
endpoint address sets current through a trusted host-side process; do not let
the daemon widen its own allowlist. A router VLAN rule alone does not cover
same-host or same-VLAN traffic. With Docker's iptables backend, forwarded
traffic is filtered in `DOCKER-USER`; host-destination traffic also needs host
input rules. Preserve Docker's managed rules and do not assume an ordinary UFW
rule covers container traffic. See [Docker firewall guidance](https://docs.docker.com/engine/network/firewall-iptables/).

Keep the status UI bound to host loopback or disable it. Do not use privileged
or host-network mode, mount the Docker socket, or attach the daemon to shared
application networks. After changing firewall policy, verify Plex playback,
seeking, WebSockets and reconnects, then verify that disallowed host/LAN
destinations fail from the daemon's network. Repeat after host/Docker restarts.

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
