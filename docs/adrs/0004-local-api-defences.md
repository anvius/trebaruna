# ADR-0004: Defences of the local HTTP API and the URI handler

- **Status**: Accepted
- **Date**: 2026-11-05

## Context

A local signing endpoint is how attacker pages obtain signatures from naive signing agents.

## Decision

The API binds loopback only and refuses anything else; every privileged route needs a single-use token stored `0600` and rotated per process; browser requests are rejected unless their `Origin` is the server; client paths must resolve, after symlinks, inside an allowed root. The `trebaruna://` handler verifies the document before asking, keeps a 32-byte approval secret the page never sees, gives a 30-second window, allows a single use, and always requires a human decision.

## Consequences

The same rules apply to the AutoFirma-compatible handler (ADR-0013): a page can ask, only a person can approve.
