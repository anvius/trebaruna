# ADR-0010: Every connection is explicit and recorded

- **Status**: Accepted
- **Date**: 2026-11-09

## Context

A signing tool must not talk to anyone the user did not ask it to, and must be able to show whom it talked to.

## Decision

All outbound HTTP goes through the `transparency` slice, which records destination, purpose, method, status and bytes. Machine output carries the record under `network`; the window shows it. Nothing runs without a user action: no telemetry, no update checks, no background downloads. A test fails if any code builds its own HTTP client.

## Consequences

Adding a network feature means naming its purpose.
