# ADR-0009: PKCS#12 files in BER are read by our own decoder

- **Status**: Accepted
- **Date**: 2026-11-09

## Context

NSS (Firefox, Thunderbird) exports PKCS#12 in BER; Go's library reads DER only and rejected such files before checking the passphrase.

## Decision

`keybundle` sends DER to go-pkcs12 and reads BER itself: PBES2 (PBKDF2, AES/3DES), the legacy 3DES scheme, and the integrity MAC checked on the bytes as written.

## Consequences

RC2, the oldest scheme, is supported only in DER files.
