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

`docker-compose.deploy.yml` is the existing operator-managed stack template.
The stack owns customer-specific settings, including `PORTLESS_DEVICE_TOKEN`.
CI builds and publishes images only; it never updates a stack or dispatches a
deployment. The daemon reads ordinary environment variables; deployment-specific
secret loading stays outside this repository and its public image.

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

Both `main` and `dev` publish without deployment. The existing
`deploy/scripts/deploy-client-stacks.sh` remains an explicitly invoked operator
tool. Its production path requires `PORTLESS_CLIENT_DEPLOY_TARGET=production`
and `PORTLESS_CLIENT_DEPLOY_IMAGE=ghcr.io/crbl-technologies/portless-client:sha-<full commit SHA>`.
Operators must resolve and authorize the target before running it. NAS deployments
and redeployments require explicit authorization. Do not
activate a retired staging target merely because its code path still exists.
Mutable `prod`/`latest` tags are not accepted by the production deployment tool.

The tool uses `PORTLESS_CLIENT_NAS_REGISTRY_ID` to select registry credentials
already stored in the target Portainer instance. The primary staging target
also requires `PORTLESS_CLIENT_REGISTRY_ID`. Both IDs must be positive integers.
The tool does not send local `GHCR_USERNAME` or `GHCR_TOKEN` values to Portainer.

Set `PORTLESS_DEPLOY_PROXY` only when an HTTP proxy is needed to reach the
target. Cloudflare Access headers are optional. The tool sends them only when
both `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` are set. It removes
temporary deployment files when it exits, including after a failed rollout.

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
