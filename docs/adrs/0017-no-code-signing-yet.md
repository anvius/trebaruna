# ADR-0017: Releases are not code-signed yet

- **Status**: Accepted
- **Date**: 2026-11-09

## Context

Authenticode (Windows) and notarisation (macOS) need paid certificates.

## Decision

Releases carry SHA-256 sums and an SBOM; the build is reproducible so anyone can rebuild and compare. The release job has the signing steps ready behind secrets that do not exist yet.

## Consequences

Windows SmartScreen and macOS Gatekeeper warn until certificates are bought.
