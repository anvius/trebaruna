# ADR-0001: Vertical slices with domain, application and infrastructure

- **Status**: Accepted
- **Date**: 2026-11-02

## Context

The tool covers several business capabilities — signing, verification, trust lists, the desktop window, the web entry points — that change for different reasons. Organising by technical layer would mix them.

## Decision

Code lives under `src/<slice>/{domain,application,infrastructure}` for the slices `signing`, `verification`, `trust`, `desktop` and `transparency`, plus `src/entrypoint` for the binaries. Dependencies point inwards only. Tests live in `tests/`, mirroring `src/`; tests that need unexported Fyne types sit beside the code under the `gui` build tag.

## Consequences

A capability can be read in one place. Go's convention of `cmd/` is not used; `src/entrypoint` plays that role and `go install` targets `src/entrypoint/main`.
