# ADR-0007: The visible seal prints certificate data

- **Status**: Accepted, amended by ADR-0012
- **Date**: 2026-11-03

## Context

A signature mark whose text the signer types is decoration, not evidence.

## Decision

The seal prints the holder, the identifier and the signing instant read from the certificate and the clock. There is no free caption. If the identity does not fit, the signer refuses instead of truncating.

## Consequences

See ADR-0012 for the handwritten-signature image.
