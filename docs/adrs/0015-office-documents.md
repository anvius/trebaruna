# ADR-0015: ODF and OOXML signatures

- **Status**: Accepted (default pending owner confirmation)
- **Date**: 2026-11-09

## Context

AutoFirma signs office documents in their native formats.

## Decision

ODF (`META-INF/documentsignatures.xml`) and OOXML (`_xmlsignatures`) signatures are implemented after every other format, with XAdES properties.

## Consequences

PDF remains the recommended format for documents meant to be read by other people.

## ODF, as implemented (0.56.0)

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

## OOXML, as implemented (0.57.0)

- One signature part per signer, `_xmlsignatures/sigN.xml`, linked from the
  origin (`_xmlsignatures/origin.sigs`, created with its relationship from
  `_rels/.rels` when missing) and declared in `[Content_Types].xml`.
- The signature is Office's: `idPackageSignature` signs the package object,
  Office's `SignatureInfoV1` object and the XAdES signed properties (prefix
  `xd`, `SigningCertificate` with issuer and serial, `SignaturePolicyImplied`
  unless a policy is given); the package object holds the `Manifest` and
  OPC's `SignatureTime`. ECMA-376 Part 2 §13 and [MS-OFFCRYPTO] 2.5.2.
- The Manifest covers every part but the signatures and what LibreOffice
  and Office leave out: the core and extended document properties, which
  applications rewrite on save. A relationships part is signed through the
  RelationshipTransform, for every relationship but those to the left-out
  parts and the origin; the URI carries the part's content type, which is
  therefore signed too.
- The RelationshipTransform follows ECMA-376 §13.2.4.24 (only the selected
  relationships, sorted by Id, `TargetMode` added, text between them
  removed). It matches the digests of the seven Office-signed files of
  Apache POI's test data, pretty-printed relationships included.
- libxmlsec's implementation, which LibreOffice uses, keeps each text node
  between relationships as an empty `<text></text>` element. Over a part
  without such text both agree. So:
  - a package with no signature has its relationships parts written
    compactly before it is signed, as Office writes them (the same
    relationships, formatting only), and the signature verifies in Office,
    LibreOffice and xmlsec1 alike;
  - when an earlier signature digested the relationships in libxmlsec's
    form (LibreOffice signed a file LibreOffice made), the new one does the
    same and nothing is rewritten, so every signature of the file verifies
    in the same applications;
  - `verify` accepts libxmlsec's form and says so
    (`relationships.libxmlsec_form`): Microsoft Office may call such a
    signature broken.
- `verify` checks only the Manifests of objects SignedInfo references (a
  Manifest anywhere else is not signed), names every changed part, and
  names the parts no signature covers but the metadata Office leaves out
  of its own signatures (document properties, thumbnail). Office 2007 and
  plain XMLDSig signatures are dated by OPC's `SignatureTime`.
- Judged with LibreOffice 26.2.6.3 through UNO (`ZipFormat` storage):
  ours, two of ours, ours added to LibreOffice's and to Office 2010's are
  all valid; a changed `word/document.xml` invalid. xmlsec1 1.3.9
  (`--ignore-manifests`) validates the XML signature. Not judged with
  Microsoft Office itself, which does not run here.
