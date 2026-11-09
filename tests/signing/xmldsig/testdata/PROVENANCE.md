# XML signatures made by other implementations

These files are signed by tools trebaruna does not share code with, so that
its XML-Signature check is judged against independent producers. Every file
was verified with xmlsec1 1.3.9 (the XML Security Library's reference
command) before being kept.

| File | Producer | What it exercises |
|---|---|---|
| `signxml-enveloped-c14n11.xml` | signxml 5.2.0 | enveloped, C14N 1.1, RSA-SHA256 |
| `signxml-enveloped-exc.xml` | signxml 5.2.0 | enveloped, exclusive C14N, RSA-SHA512, SHA-384 digests |
| `signxml-enveloping-ecdsa.xml` | signxml 5.2.0 | enveloping (`ds:Object`), ECDSA P-256 r‖s, C14N 1.0 |
| `signxml-xades-enveloped.xml` | signxml 5.2.0 `XAdESSigner` | XAdES with a `SignedProperties` reference |
| `xmlsec-sha1-xpath.xml` | xmlsec1 1.3.9 | `URI=""` with a stylesheet instruction and comments in the prolog, the XPath filter `not(ancestor-or-self::ds:Signature)` AutoFirma writes, RSA-SHA1 |
| `xmlsec-detached-base64.xml` | xmlsec1 1.3.9 | AutoFirma's "XAdES Detached" layout: `AFIRMA/CONTENT` in Base64, Base64 transform |
| `xmlsec-detached-xml.xml` | xmlsec1 1.3.9 | the same with XML content, C14N |
| `xmlsec-external.xml` | xmlsec1 1.3.9 | a reference to `documento.txt` beside it, exclusive C14N of `SignedInfo` |
| `xmlsec-xpath-other.xml` | xmlsec1 1.3.9 | an XPath expression trebaruna does not evaluate: must read as unverifiable, not modified |

`rsa.pem` and `ec.pem` are the self-signed test certificates (their keys were
thrown away). The xmlsec1 files come from the templates in `templates/`:

```bash
xmlsec1 --sign --lax-key-search --privkey-pem rsa.key,rsa.pem --id-attr:Id CONTENT \
    --output xmlsec-<name>.xml templates/t-<name>.xml
xmlsec1 --verify --trusted-pem rsa.pem --id-attr:Id CONTENT xmlsec-<name>.xml
```

The signxml files come from `templates/signxml_fixtures.py`
(`python -I signxml_fixtures.py <directory holding rsa.key, rsa.pem, ec.key, ec.pem>`).
