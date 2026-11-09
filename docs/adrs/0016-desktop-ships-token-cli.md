# ADR-0016: Desktop packages ship the PKCS#11-enabled CLI

- **Status**: Accepted
- **Date**: 2026-11-09

## Context

Card support needs cgo; the static CLI has none, so the window could not use cards.

## Decision

Desktop packages (which need cgo for Fyne anyway) build `trebaruna` with `-tags token`. The fully static CLI stays available for servers and scripts without cards.

## Consequences

One binary name, two builds; `trebaruna about` says which one is running.
