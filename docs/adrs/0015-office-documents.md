# ADR-0015: ODF and OOXML signatures

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

AutoFirma signs office documents in their native formats.

## Decision

ODF (`META-INF/documentsignatures.xml`) and OOXML (`_xmlsignatures`) signatures are implemented after every other format, with XAdES properties.

## Consequences

PDF remains the recommended format for documents meant to be read by other people.
