# Phase 0 Daemon Baseline

Implemented now:

- Environment-driven daemon configuration.
- Control-plane calls for trust bundle and device config.
- Local state persistence under `PORTLESS_DATA_DIR`.
- Docker Compose install path with a fake Plex target.

Next implementation slice:

- Follow `docs/quic-cutover-todo.md`; the interim WebSocket tunnel is not an
  accepted fallback.
- Generate and encrypt a local private key.
- Submit CSR with proof-of-possession and stable request id.
- Establish QUIC/mTLS tunnel to the relay.
- Renew certificates at two-thirds lifetime with jitter.
- Proxy one relay stream to one Plex HTTP request.
