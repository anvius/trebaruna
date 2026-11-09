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
| `xmlsec-autofirma-order.xml` | xmlsec1 1.3.9 | AutoFirma's enveloped transforms in its order: enveloped signature, C14N, then the XPath filter on the canonical octets; RSA-SHA512 |
| `xmlsec-cosigned.xml` | xmlsec1 1.3.9 | the same document signed again with ECDSA (`--node-id Signature-B`): both signatures exclude every signature, so both hold |
| `xmlsec-xpath-other.xml` | xmlsec1 1.3.9 | an XPath expression trebaruna does not evaluate: must read as unverifiable, not modified |
| `xmlsec-pss-sha256.xml` | xmlsec1 1.3.9 | RSA-PSS (`sha256-rsa-MGF1`, RFC 6931) by a key its certificate publishes as id-RSASSA-PSS, as the German trusted list is signed |
| `xmlsec-pss-sha3.xml` | xmlsec1 1.3.9 | RSA-PSS over SHA3-512, SHA3-256 digests |
| `xmlsec-ecdsa-sha3.xml` | xmlsec1 1.3.9 | ECDSA P-256 over SHA3-256 (RFC 9231), SHA3-384 digests |

`rsa.pem`, `ec.pem`, `pss.pem` and `ec-sha3.pem` are the self-signed test
certificates (their keys were thrown away). `pss.pem` and `ec-sha3.pem` were
made with OpenSSL 3:

```bash
openssl req -x509 -newkey rsa-pss -pkeyopt rsa_keygen_bits:2048 -nodes \
    -keyout pss.key -out pss.pem -subj "/CN=trebaruna RSA-PSS test" -days 3650
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ec-sha3.key -out ec-sha3.pem -subj "/CN=trebaruna ECDSA SHA-3 test" -days 3650
``` The xmlsec1 files come from the templates in `templates/`:

The co-signed file adds the second template to the signed first file and
signs that node alone:

```bash
xmlsec1 --sign --lax-key-search --privkey-pem ec.key,ec.pem \
    --id-attr:Id "http://www.w3.org/2000/09/xmldsig#:Signature" --node-id Signature-B \
    --output xmlsec-cosigned.xml templates/t-cosigned.xml
```

```bash
xmlsec1 --sign --lax-key-search --privkey-pem rsa.key,rsa.pem --id-attr:Id CONTENT \
    --output xmlsec-<name>.xml templates/t-<name>.xml
xmlsec1 --verify --trusted-pem rsa.pem --id-attr:Id CONTENT xmlsec-<name>.xml
```

The PSS and SHA-3 files the same way, with `pss.key,pss.pem` and
`ec-sha3.key,ec-sha3.pem`.

The signxml files come from `templates/signxml_fixtures.py`
(`python -I signxml_fixtures.py <directory holding rsa.key, rsa.pem, ec.key, ec.pem>`).
