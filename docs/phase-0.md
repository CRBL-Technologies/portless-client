# Daemon Implementation Notes

The current daemon baseline includes:

- Environment-driven daemon configuration.
- Control-plane calls for trust bundle and device config.
- Local state persistence under `PORTLESS_DATA_DIR`.
- Encrypted local private key storage with plaintext key migration.
- Submit CSR with proof-of-possession and stable request id.
- QUIC/mTLS relay tunnel with no WebSocket transport fallback.
- Certificate renewal sized for 24-hour client certificates with jitter.
- Proxy one relay stream to one Plex HTTP request.
- Docker Compose install path with a fake Plex target.

See `docs/quic-cutover-todo.md` for the implemented transport acceptance
criteria.
