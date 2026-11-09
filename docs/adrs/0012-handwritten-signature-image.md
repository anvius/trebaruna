# ADR-0012: A handwritten-signature image may accompany the seal

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

Both tools the project replaces allow an image in the visible signature, and many offices expect a handwritten mark.

## Decision

An image may be added to the seal, always next to the certificate data, never alone. The certificate data keep their size and are never truncated to make room.

## Consequences

ADR-0007 still holds for the text.

## As implemented (0.41.0)

- The rubric is a PNG or a JPEG of at most 4 MiB and 4096 pixels a side
  (`domain.Rubric`); anything else is refused when it is given, not when the
  PDF is written.
- It sits at the left of the seal, vertically centred, as large as its
  proportions allow within the padding and half the width
  (`Rubric.Fit`, shared by the signer and the desktop preview); the accent
  rule and the certificate data start 2 pt after it.
- The data are set at the size the same box gives them without a rubric. A
  box whose remaining width cannot hold them is refused ("widen it"), never
  filled with smaller type.
- The default corner seal is 160x48 pt when it carries a rubric (64x48
  without). A box the signer placed keeps its size.
- PNG transparency is kept (a soft mask). pdfsign v1.0.0 copies a JPEG as
  `/DeviceRGB`, which garbles a greyscale or CMYK one; those are re-encoded
  as PNG first.
- Sources: `sign --rubric`, afirma:// `signatureRubricImage` (Base64, used
  only with a seal box, as AutoFirma does), the desktop's rubric row
  (remembered between sessions).
- Checked: pdfsig reports the signatures valid; pages rendered with pdftoppm
  show the rubric beside the data, with PNG, colour, greyscale and CMYK
  JPEG rubrics.
