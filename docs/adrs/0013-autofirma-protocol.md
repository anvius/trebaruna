# ADR-0013: trebaruna answers AutoFirma's afirma:// protocol

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

Spanish public-administration sites start signatures through `afirma://` (AutoScript). The protocol is public: AutoFirma is free software.

## Decision

trebaruna implements the protocol from its public specification and source, without copying code, and registers as a handler next to AutoFirma; the user picks the default. ADR-0004 applies: every request is shown and approved by a person. No root certificate is ever installed in a browser; if a channel needs one, that channel is not offered. Weaknesses the protocol imposes (DES for the intermediate server) are documented and shown.

## Consequences

Compatibility must be proven against a test server that follows the public servlets and against real sites.

## Findings (D1, docs/afirma-protocol.md)

- The WebSocket and the legacy socket channels are always TLS on
  `127.0.0.1`; AutoFirma installs its own root CA (`CN=Autofirma ROOT`) for
  them, and no plain `ws://` variant exists in any version from 1.7 to 1.10.
  Under this decision those channels are not offered.
- The intermediate-server channel needs no local certificate (outbound HTTPS
  to the site) and is implemented. The page chooses the channel: sites that
  force it (Sistema RED does, the only site in the local AutoFirma logs) work;
  pages that default to WebSocket do not.
- Pending owner decision: trusting only trebaruna's self-signed *leaf*
  certificate for `127.0.0.1` as a peer (NSS trust flag `P`, no authority to
  issue other certificates) would open the WebSocket channel without a root
  CA. It is still a change to the browser's trust store, so it is not done
  without the owner's choice.
