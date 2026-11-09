# ADR-0012: A handwritten-signature image may accompany the seal

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

Both tools the project replaces allow an image in the visible signature, and many offices expect a handwritten mark.

## Decision

An image may be added to the seal, always next to the certificate data, never alone. The certificate data keep their size and are never truncated to make room.

## Consequences

ADR-0007 still holds for the text.
