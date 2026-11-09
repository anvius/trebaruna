# ADR-0003: Trust comes only from authenticated trusted lists

- **Status**: Accepted
- **Date**: 2026-11-04

## Context

Downloading a trusted list does not make it trustworthy: the file must be signed by a certificate the European list of lists names for that territory.

## Decision

A list is used only after its XML signature verifies against the LOTL's certificates for the territory. Self-signed certificates are always `untrusted`, never `advanced`. A subordinate CA the list publishes is treated as an anchor, because that is the list's own statement. Chains are evaluated at the signing time proven by a timestamp, not at the wall clock.

## Consequences

Some territories that publish only PDF lists cannot be used. A signature valid when made and expired today is not reported as untrusted.
