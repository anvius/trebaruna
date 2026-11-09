# ASiC containers made with other tools

Each container is a ZIP built with Info-ZIP 3.0, `mimetype` first and stored,
following ETSI EN 319 162-1. The signatures inside come from tools that share
no code with trebaruna, and each was verified before packing: the CAdES
signatures with `openssl cms -verify -content`, the XAdES ones with xmlsec1
1.3.9. `rsa.pem` is the self-signed signer (its key was thrown away).

| File | Container | Signature | What it exercises |
|---|---|---|---|
| `asics-cades.asics` | ASiC-S | `META-INF/signature.p7s`, OpenSSL 3 `cms -sign -binary -cades` (detached) | one data object, `informe.pdf` |
| `asice-cades.asice` | ASiC-E | `META-INF/signature.p7s` over `META-INF/ASiCManifest.xml` (OpenSSL) | the manifest lists `a.txt` and `docs/b.pdf` with SHA-256 digests (`templates/ASiCManifest.xml`) |
| `asics-xades.asics` | ASiC-S | `META-INF/signatures.xml`, xmlsec1 | `asic:XAdESSignatures` root; a reference to `informe.pdf` and to `SignedProperties` (`templates/t-asics-xades.xml`) |
| `asice-xades.asice` | ASiC-E | `META-INF/signatures.xml`, xmlsec1 | references to `a.txt` and `docs/b.pdf`, a file in a folder (`templates/t-asice-xades.xml`) |
| `asice-xades-unsigned-file.asice` | ASiC-E | the same signature | plus `notas.txt`, which no signature covers |

Packing, mimetype first and uncompressed:

```bash
printf '%s' application/vnd.etsi.asic-e+zip > mimetype
zip -X -0 out.asice mimetype
zip -X -r out.asice a.txt docs META-INF
```

The XAdES templates were signed at the container root, so their relative
URIs resolve as ASiC requires, then moved to `META-INF/`:

```bash
xmlsec1 --sign --lax-key-search --privkey-pem rsa.key,rsa.pem \
    --id-attr:Id http://uri.etsi.org/01903/v1.3.2#:SignedProperties \
    --output signatures.xml t-asice-xades.xml
```
