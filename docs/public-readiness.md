# Public Readiness Checklist

This repository is intended to become auditable by users who will run the Portless daemon locally. Before making it public, keep these checks green.

## Required Before Public Release

- Confirm `portless-contracts` is public or replace the `dev` branch git dependency with a tagged release.
- Run `cargo fmt --check`, `cargo test`, and `cargo clippy -- -D warnings`.
- Run a Rust advisory scan such as `cargo audit` or `cargo deny`.
- Run a repository secret scan, including git history, before changing visibility.
- Verify sample config and docs contain placeholders only.
- Verify Docker images do not bake daemon tokens, local state, or generated device key material.
- Keep the status UI loopback-only by default and document risks for non-loopback binds.

## Current Notes

- Runtime secrets are supplied through environment variables, not source files.
- The daemon token is reveal-once control-plane material and is not displayed in the status UI.
- Device private keys are encrypted at rest by default; generated key files and local secret material are ignored by git.
- Test fixtures use generic sample hostnames and IDs.
