# ADR-0014: Remote signing only through the CSC API

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

Remote signing keeps the key on a provider's server, which limits what the user can check.

## Decision

Only the open Cloud Signature Consortium API v2 is implemented, with no vendor SDK. Remote signatures are labelled as such in every report.

## Consequences

Providers without a CSC endpoint are not supported.

## Implementation (0.55.0)

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
- A credential read is remembered for a minute, per service, credential
  and secrets (0.77.1): reading the signer's identity and signing ask the
  provider once.
- The receipt carries `key_source: csc` and the provider's host, in text
  and JSON.
- OAuth2 authorization-code flow (0.78.0), with `--csc-client`: `info`
  names the server; the browser opens the authorisation page and comes
  back to a loopback address (RFC 8252); PKCE S256 and the state bind the
  code to the request. Scope `service` signs in when there is no token or
  user; scope `credential` (credentialID, numSignatures, base64url hashes,
  hashAlgorithmOID) authorises each signature of an `oauth2code`
  credential, and the credential-scoped token replaces the SAD in
  `signatures/signHash`.
- Not implemented: RSA-PSS.
