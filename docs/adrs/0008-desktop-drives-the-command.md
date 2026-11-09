# ADR-0008: The desktop window drives the command-line binary

- **Status**: Accepted
- **Date**: 2026-11-05

## Context

Two implementations of signing and verification would drift apart.

## Decision

The window runs `trebaruna` for every operation (sign, certificate, verify, requests) and parses its JSON. It does not link the signing packages.

## Consequences

One validation path; a few milliseconds per operation; the window needs the CLI next to it or on `PATH`. Desktop packages ship the CLI built with PKCS#11 support (ADR-0016).
