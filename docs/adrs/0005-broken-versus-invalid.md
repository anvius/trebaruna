# ADR-0005: Broken and invalid are different verdicts

- **Status**: Accepted
- **Date**: 2026-11-06

## Context

Reporting a document as altered when its bytes are intact accuses its author of tampering.

## Decision

`broken` (exit 1) means the signed bytes changed. `invalid` (exit 4) means the bytes are intact but the signer could not sign at that moment (expired, revoked). Every verifier change carries a test that an intact document is never `broken`.

## Consequences

The XAdES ECDSA fix of 0.6.4 is an instance: a correct signature from another producer had been reported as broken.
