# RSA-PSS in CMS and PDF

Made with OpenSSL 3 on 9 November 2026; the keys were thrown away. Each
envelope was accepted by `openssl cms -verify -CAfile pss-ca.pem`, and the
PDF by poppler's `pdfsig` ("Signature is Valid").

| File | What it is |
|---|---|
| `pss-ca.pem` | an authority whose key is published as id-RSASSA-PSS (RFC 4055), as D-TRUST CA 3-1 2016 and the German HBA authorities are; Go's crypto/x509 leaves that key unread |
| `signer.pem` | Erika Mustermann, an RSA key, issued by it with RSASSA-PSS |
| `pss-embedded.p7m` | CAdES-BES (`-cades`: signing-certificate-v2), RSASSA-PSS SHA-256, salt 32, the document inside |
| `pss-detached.p7s` | the same, detached, SHA-384, over `documento.txt` |
| `pss-pades.pdf` | a PDF trebaruna signed whose CMS was replaced by an OpenSSL RSASSA-PSS one over the same `/ByteRange` |

```bash
openssl req -x509 -newkey rsa-pss -pkeyopt rsa_keygen_bits:2048 -nodes \
    -keyout ca.key -out pss-ca.pem -subj "/C=DE/O=trebaruna test/CN=trebaruna PSS CA" \
    -days 36500 -extensions ext -config <(cat /etc/ssl/openssl.cnf ca.cnf)   # CA:TRUE, keyCertSign
openssl req -newkey rsa:2048 -nodes -keyout signer.key -out signer.csr \
    -subj "/C=DE/O=trebaruna test/CN=Erika Mustermann"
openssl x509 -req -in signer.csr -CA pss-ca.pem -CAkey ca.key -set_serial 2 -days 36500 \
    -extfile leaf.cnf -extensions ext -out signer.pem                         # digitalSignature, nonRepudiation
openssl cms -sign -binary -nodetach -cades -in documento.txt -signer signer.pem -inkey signer.key \
    -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:-1 -md sha256 -outform DER -out pss-embedded.p7m
openssl cms -sign -binary -cades -in documento.txt -signer signer.pem -inkey signer.key \
    -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:-1 -md sha384 -outform DER -out pss-detached.p7s
```

For the PDF, `trebaruna sign in.pdf --pem signer+key.pem --invisible`, then
the bytes its `/ByteRange` covers were signed with the third command above
(detached, SHA-256) and the DER written, hex, zero-padded, into `/Contents`.
