# Security Policy

## Reporting

Report vulnerabilities privately through GitHub Security Advisories for this repository. Do not open public issues for suspected vulnerabilities, secrets, or bypasses.

Include:

- affected version or commit
- reproduction steps
- expected and observed behavior
- impact assessment

## Sensitive Data

Do not commit daemon tokens, device key material, local `.env` files, or generated files from `PORTLESS_DATA_DIR`. The default data directory contains encrypted device key material plus local encryption secrets and is intentionally ignored.

## Local Status UI

The daemon status UI is intended for loopback use. The default bind address is `127.0.0.1:43180`; disable it with `PORTLESS_UI_ADDR=off` or keep it on loopback unless an operator has added separate network access controls.
