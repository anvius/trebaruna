# Office Open XML files

## Signed by Microsoft Office

From Apache POI's test data (`test-data/xmldsign`, Apache License 2.0),
taken unchanged from <https://github.com/apache/poi/tree/trunk/test-data/xmldsign>:

| File | Signed by | What it shows |
|---|---|---|
| `ms-office-2010-signed.docx`, `.xlsx`, `.pptx` | Office 2010 | XAdES-BES with RSA-SHA1, one per application |
| `Office2010-SP1-XAdES-X-L.docx` | Office 2010 SP1 | a signature timestamp and the X-L properties |
| `hello-world-signed-twice.docx` | two signers | two signature parts under one origin |
| `hyperlink-example-signed.docx` | Office 2010 | an external relationship (`TargetMode="External"`) |
| `office2007prettyPrintedRels.docx` | see below | relationships parts written with line breaks |

`office2007prettyPrintedRels.docx`: its Manifest matches its parts, the
relationships through the RelationshipTransform with the line breaks
removed, as ECMA-376 says. Its SignatureValue does not verify: xmlsec1
1.3.9 (`--ignore-manifests`) reports `Failure reason: SIGNATURE` for it as
trebaruna does. It is kept for the Manifest.

The certificates expired long ago: the files are for integrity, not trust.

## Made and signed by LibreOffice

- `unsigned.docx`: LibreOffice 26.2.6.3 converted a two-line text file
  (`soffice --headless --convert-to docx:"MS Word 2007 XML"`).
- `libreoffice-signed.docx`: the same document signed by LibreOffice through
  its UNO API, with the self-signed certificate `prueba.pem` (CN=Prueba) in
  an NSS database (`MOZILLA_CERTIFICATE_FOLDER`):
  `DocumentDigitalSignatures.signDocumentWithCertificate` on a `ZipFormat`
  storage, then `commit`. LibreOffice reports it valid
  (`verifyDocumentContentSignatures`).

LibreOffice's relationships parts end in a line break, and libxmlsec's
RelationshipTransform, which LibreOffice uses, writes that text node as an
empty `<text></text>` element where ECMA-376 removes it: the digests of its
two relationships parts are libxmlsec's form, not the standard's.
