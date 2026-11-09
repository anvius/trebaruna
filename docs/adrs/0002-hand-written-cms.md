# ADR-0002: CMS structures are written by hand

- **Status**: Accepted
- **Date**: 2026-11-03

## Context

CAdES-T and later levels add attributes to a SignerInfo after it is signed (the signature timestamp, revocation values, archive timestamps). No Go library allows unsigned attributes to be appended to an existing SignedData.

## Decision

`src/signing/infrastructure/cms` builds and edits DER directly. Every structure is checked against `openssl cms` in the integration tests.

## Consequences

More code to own, but every byte is under test and nothing is hidden behind a library's defaults.
