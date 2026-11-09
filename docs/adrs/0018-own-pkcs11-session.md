# ADR-0018: Signatures go through an own PKCS#11 session

- **Status**: Accepted
- **Date**: 2026-11-09

## Context

Card signatures went through `crypto11`, a wrapper over the `miekg/pkcs11`
binding that the token listing already used directly. The wrapper cannot pass
the initialisation parameters NSS needs to open a Firefox profile (C3), takes
the first certificate it pairs, and always sends a PIN, so a reader with its own
keypad cannot be asked to read it. It also brought two more modules into the
build.

## Decision

`src/signing/infrastructure/pkcs11_cgo.go` loads the module (with optional
`C_Initialize` parameters), opens and logs in one session, pairs each private
key with the certificate sharing its `CKA_ID` plus the issuers the token holds,
and signs digests with `CKM_RSA_PKCS` (DigestInfo prefixed), `CKM_RSA_PKCS_PSS`
or `CKM_ECDSA` (r||s re-encoded as ASN.1). One implementation serves cards and
software stores; the listing and the signatures share the module loader.

## Consequences

- Fewer dependencies (`crypto11`, `pkg/errors`, `thales-e-security/pool` gone).
- The code that touches the private key is a few hundred lines in this
  repository, read and tested here (SoftHSM: RSA and ECDSA, verified by OpenSSL
  and pdfsig).
- Mechanisms beyond RSA and ECDSA (EdDSA) need adding here when a card offers
  them.
