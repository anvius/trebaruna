# ADR-0014: Remote signing only through the CSC API

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

Remote signing keeps the key on a provider's server, which limits what the user can check.

## Decision

Only the open Cloud Signature Consortium API v2 is implemented, with no vendor SDK. Remote signatures are labelled as such in every report.

## Consequences

Providers without a CSC endpoint are not supported.
