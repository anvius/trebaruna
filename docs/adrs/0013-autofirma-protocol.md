# ADR-0013: trebaruna answers AutoFirma's afirma:// protocol

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

Spanish public-administration sites start signatures through `afirma://` (AutoScript). The protocol is public: AutoFirma is free software.

## Decision

trebaruna implements the protocol from its public specification and source, without copying code, and registers as a handler next to AutoFirma; the user picks the default. ADR-0004 applies: every request is shown and approved by a person. No root certificate is ever installed in a browser; if a channel needs one, that channel is not offered. Weaknesses the protocol imposes (DES for the intermediate server) are documented and shown.

## Consequences

Compatibility must be proven against a test server that follows the public servlets and against real sites.
