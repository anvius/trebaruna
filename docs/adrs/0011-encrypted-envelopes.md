# ADR-0011: Encrypted envelopes (.p7e) are supported

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

Encrypted envelopes for recipients are common practice: AutoFirma writes them, and Italian offices exchange `.p7e` files; trebaruna had excluded them.

## Decision

CMS EnvelopedData with key transport to recipients' certificates (RSA-OAEP, and RSA PKCS#1 v1.5 for compatibility) and AES-256-CBC content encryption, interoperable with `openssl cms`.

## Consequences

Decryption needs the recipient's key from a file, a card or the system store.

Implemented (0.40.0): PKCS#1 v1.5 is the default key transport because the
recipients' tools all read it; RSA-OAEP with SHA-256 is `--oaep`. The CMS is
written in `src/signing/infrastructure/cms/envelope.go`, not taken from the
library at hand, which decrypts only with an in-memory key (so never with a
card), knows no OAEP and defaults to DES. Elliptic-curve recipients (key
agreement) are not supported. Cards often decrypt OAEP only with SHA-1.
