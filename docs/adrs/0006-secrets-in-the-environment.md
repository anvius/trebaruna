# ADR-0006: Secrets travel in the environment, never on the command line

- **Status**: Accepted
- **Date**: 2026-11-09

## Context

Any local user can read any process's command line.

## Decision

`TREBARUNA_PASSPHRASE`, `TREBARUNA_PIN` and `TREBARUNA_TSA_PASS` replace `--pass`, `--pin` and `--tsa-pass` when the flags are absent. The desktop app and every adapter use the variables. Passphrases, PINs and passwords are never stored in preferences.

## Consequences

Flags stay for interactive use; an explicit flag wins.
