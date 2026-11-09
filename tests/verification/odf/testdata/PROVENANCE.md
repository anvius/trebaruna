# OpenDocument files from LibreOffice

- `unsigned.odt`: LibreOffice 26.2.6.3 converted a two-line text file
  (`soffice --headless --convert-to odt`).
- `libreoffice-signed.odt`: the same document signed by LibreOffice itself,
  through its UNO API, with the self-signed certificate `prueba.pem` (CN=Prueba)
  imported into an NSS database (`MOZILLA_CERTIFICATE_FOLDER`):
  `DocumentDigitalSignatures.signDocumentWithCertificate` on a `ZipFormat`
  storage of the file, then `commit`. LibreOffice reports the signature valid
  (`verifyDocumentContentSignatures` → `SignatureIsValid`).

Its signature references every stream, `mimetype` and `META-INF/manifest.xml`
included, with C14N for the XML ones, and carries XAdES signed properties: what
trebaruna's ODF signer reproduces.
