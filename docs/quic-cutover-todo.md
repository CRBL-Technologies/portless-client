# QUIC Transport E2E TODO

This daemon checklist mirrors the server transport checklist. The WebSocket tunnel is removed rather than maintained as a fallback, and non-transport work stays out of this milestone.

## Acceptance Criteria

- [x] Daemon generates and persists an encrypted local private key under `PORTLESS_DATA_DIR`.
- [x] Daemon submits a CSR with a stable request id to `/v1/device/certificates` using the device token.
- [x] Daemon stores the issued certificate and CA trust bundle under `PORTLESS_DATA_DIR`.
- [x] Daemon renews certificates before expiry with jitter.
- [x] Daemon connects to the relay with Quinn over UDP and presents its client certificate.
- [x] Daemon no longer sends the device token to the relay data path.
- [x] Each accepted QUIC bidirectional stream maps to one Plex HTTP request.
- [x] Request and response bodies are streamed as raw bytes over QUIC streams.
- [x] Plex WebSocket upgrades are proxied as raw HTTP upgrades over the same QUIC stream.
- [x] SSE and other long-lived response bodies stream over QUIC without full-response buffering.
- [x] Plex Range requests use the same parser-backed HTTP client path; no custom raw HTTP parser remains.
- [x] Reconnect uses bounded exponential backoff with jitter and handles NAT rebinding.
- [x] Request cancellation propagates across the QUIC stream.
- [x] Daemon status UI distinguishes startup, relay unreachable, relay disconnected, connected, and PMS unreachable states.
- [x] Integration coverage exercises normal HTTP, large streaming bodies, Range, Plex WebSocket notifications, SSE, cancellation, daemon reconnect, and certificate rejection.

## Cutover Guardrails

- Do not reintroduce `tokio-tungstenite`.
- Do not reintroduce `/_portless/connect`.
- Do not base64 encode data-plane bodies.
- Do not make WebSocket a fallback transport.
