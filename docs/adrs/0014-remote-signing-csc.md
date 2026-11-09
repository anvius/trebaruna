# ADR-0014: Remote signing only through the CSC API

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

Remote signing keeps the key on a provider's server, which limits what the user can check.

## Decision

Only the open Cloud Signature Consortium API v2 is implemented, with no vendor SDK. Remote signatures are labelled as such in every report.

## Consequences

Providers without a CSC endpoint are not supported.

## Implementation (0.38.0)

- `sign --csc <base> [--credential <id>]`; the access token, or the user and
  password for `auth/login`, and the PIN and OTP come from the environment
  (ADR-0006).
- The client speaks `credentials/list`, `credentials/info` (v2's `auth`
  object and v1's `authMode`/`PIN`/`OTP`), `credentials/authorize` (explicit
  credentials only, one SAD per hash) and `signatures/signHash`.
- The signature algorithm is the combined OID (`sha256WithRSAEncryption`,
  `ecdsa-with-SHA256`) unless the credential lists only the key's own
  algorithm. ECDSA answers in `r||s` are converted to DER.
- The remote key is a `crypto.Signer`, so every format and level signs
  through it unchanged.
- The receipt carries `key_source: csc` and the provider's host, in text
  and JSON.
- Not implemented: the OAuth2 authorization-code flow (`oauth2code`
  credentials are refused with that reason), and RSA-PSS.
