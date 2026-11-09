# ADR-0015: ODF and OOXML signatures

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

AutoFirma signs office documents in their native formats.

## Decision

ODF (`META-INF/documentsignatures.xml`) and OOXML (`_xmlsignatures`) signatures are implemented after every other format, with XAdES properties.

## Consequences

PDF remains the recommended format for documents meant to be read by other people.

## ODF, as implemented (0.39.0)

- `META-INF/documentsignatures.xml` holds one XAdES signature per signer,
  under `<document-signatures xmlns="urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0" version="1.2">`.
- Every stream is referenced: `mimetype` and `META-INF/manifest.xml`
  included, the signatures file excluded. LibreOffice calls a signature
  without `mimetype` partial and reports it invalid.
- A stream is canonicalised when the manifest says `text/xml`, or, when the
  manifest does not list it, when its name ends in `.xml`
  (LibreOffice's `DocumentSignatureManager::isXML`).
- The manifest is not changed, and the rest of the package is copied byte
  for byte, `mimetype` first and stored.
- The signature redeclares the default namespace as XML-Signature's, as
  LibreOffice writes it, so its canonical form does not depend on the
  holder's default namespace.
- Judged with LibreOffice 26.2.6.3 through UNO
  (`verifyDocumentContentSignatures` on a `ZipFormat` storage): one
  signature, two, and a trebaruna signature added to one LibreOffice made
  all valid; a changed `content.xml` invalid. Also xmlsec1 and Java 25.
