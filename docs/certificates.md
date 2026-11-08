# Certificates

Which certificates and keys are accepted, how to inspect one, and where to get a
qualified one.

- [Key sources](#key-sources)
- [PKCS#12](#pkcs12)
- [PEM](#pem)
- [Which key types are accepted](#which-key-types-are-accepted)
- [Self-signed certificates](#self-signed-certificates)
- [Inspecting a certificate](#inspecting-a-certificate)
- [Where to get a qualified certificate](#where-to-get-a-qualified-certificate)
- [Exporting from a smartcard](#exporting-from-a-smartcard)
- [Common problems](#common-problems)

---

## Key sources

Exactly one, always:

```bash
--p12  file.p12  --pass <passphrase>
--pem  bundle.pem [--pass <passphrase>]
--token <label>  --pin <pin> [--module <path>]
```

Passing two is an error, not a preference order. The tool will not silently pick
one, because "which key did it use" must never be a guess.

The certificate is **always taken from the key material**. There is no option to
supply a certificate separately, which means the signature can never claim a name
that does not belong to the key that produced it.

---

## PKCS#12

The format every authority hands out: `.p12` or `.pfx`, certificate plus private
key in one container, protected by a passphrase.

```bash
pignus sign atto.pdf --p12 mia-chiave.p12 --pass "la mia passphrase"
```

Both extension names work; the tool reads the container, not the name.

### What is accepted

- Any PKCS#12 produced by any authority.
- Self-signed certificates.
- Keys encrypted with a passphrase. An empty passphrase is allowed if the
  container has none.

If the passphrase is wrong you get a clear error rather than a crash:

```
cannot read the P12: pkcs12: decryption password incorrect
```

---

## PEM

A text file containing the certificate and the key, concatenated. Common when you
generate keys yourself or export from a server.

```bash
cat certificate.pem key.pem > bundle.pem
pignus sign atto.pdf --pem bundle.pem
```

Order does not matter: the tool reads every block and pairs them. The bundle may
also contain intermediate certificates, which are included in the signature — do
that when the CA provides them, because some validators need the chain.

An encrypted key in the bundle works with `--pass`.

---

## Which key types are accepted

| Key | Signing | Notes |
|---|---|---|
| **RSA** 2048+ | ✅ | The common case. 1024 is accepted by the tool but authorities no longer issue it. |
| **RSA** 4096 | ✅ | Works; larger signatures, slower. |
| **ECDSA** (P-256, P-384) | ✅ | Smaller and faster. Supported in CAdES, PAdES and XAdES. |
| **Ed25519** | ⛔ | Not accepted: the AdES profiles in use do not specify it. |

Accepted encodings for PEM keys: **PKCS#8**, **PKCS#1** (RSA), **SEC1** (EC),
plain or passphrase-encrypted.

Within a signature, the digest is **SHA-256** throughout.

### Certificate extensions that matter

| Extension | Why it matters |
|---|---|
| `keyUsage` | Must allow digital signature (`digitalSignature` or `nonRepudiation`) |
| `extendedKeyUsage` | Should include `emailProtection` or document signing |
| `qcStatements` | What makes a certificate *qualified*; without it, no QES verdict |
| `authorityInfoAccess` | Where OCSP and the issuer certificate live; without it, no online revocation check |
| `subjectAltName` / `serialNumber` | Where the seal takes the identifier from |

A certificate without `digitalSignature` in `keyUsage` will produce a signature
that validators reject. The tool does not stop you — the key may be usable in
contexts it cannot see — but `verify` will report the problem.

---

## Self-signed certificates

Accepted, and flagged:

```bash
pignus sign atto.pdf --pem selfsigned.pem
```

```
signed  atto_signed.pdf
  warning self-signed certificate: valid cryptography, no third-party trust
```

The signature is real: anyone can check that the bytes were not changed and that
the same key produced them. What a self-signed certificate cannot do is prove
**who** holds the key, because nobody vouches for it.

`verify` reports it as `untrusted`:

```
! el certificado es autofirmado: criptografía válida, sin confianza de terceros
```

That is the honest answer, and it is the right verdict for internal testing,
development, and documents that circulate inside an organisation which distributes
the certificate by other means.

---

## Inspecting a certificate

```bash
pignus certificate mia-chiave.p12 --pass segreto
```

```
  Subject     MARIA LOPEZ GARCIA
  Identifier  IDCES-00000000X
  Issuer      Example TSP
  Valid       2025-01-01 → 2028-01-01
  Key         RSA 2048
  Qualified   yes (QcCompliance, QcRetention)
  Self-signed no
```

Machine-readable:

```bash
pignus certificate k.p12 --pass x --json
```

To see where the issuer sits in the trust lists:

```bash
pignus certificate k.p12 --pass x --territory IT
```

Useful **before** signing: if your issuer is not listed, your counterparty will
see `untrusted`, and it is better to know that first.

Accepts `.p12`, `.pfx`, `.pem`, `.crt`, `.cer`.

---

## Where to get a qualified certificate

A **qualified** certificate comes from a trust service provider supervised in an
EU member state. The lists this tool downloads are exactly the register of those
providers:

```bash
pignus trust sync
pignus trust show IT | grep -i "CA/QC" | head
```

Typical routes:

- **National identity cards** with a signing certificate: the Italian CIE and CNS,
  the Spanish DNIe, the Belgian eID, the Estonian eID.
- **Commercial qualified providers**: purchased per year, usually with identity
  verification by video or in person.
- **Your employer**, if it has a qualified CA for professional signatures.

A certificate from a private CA, a bank portal, or a self-generated key can still
produce a valid advanced signature. It will not produce a `qualified` verdict, and
that is a property of the certificate, not a limitation of this tool.

---

## Exporting from a smartcard

Many national cards let you export the certificate and key as a `.p12`. If yours
does not, use the card directly: see [Smartcards](smartcards.md).

A card that will not export is usually the better-designed one: the key never
leaves the hardware, which is what makes it a qualified device.

---

## Common problems

### "decryption password incorrect"

The passphrase is wrong. Note that PKCS#12 passphrases are case-sensitive and may
contain characters your shell interprets — quote them.

### "no certificate paired with a private key"

For smartcards: the token holds a certificate and a key that are not linked. See
[Smartcards](smartcards.md).

### "unsupported private key format"

A PEM containing a key type this build does not parse. Convert it:

```bash
openssl pkcs8 -topk8 -nocrypt -in old.key -out key.pem
```

### The signature verifies but the name is wrong

The name comes from the certificate's subject. If it is wrong, the certificate is
wrong; the tool does not take a name from anywhere else.

### "the identity does not fit the seal box"

Enlarge the box, or drop the visible seal. See
[Signing](signing.md#when-the-identity-does-not-fit).

---

## Next

- [Smartcards](smartcards.md) — PKCS#11 in detail
- [Trust lists](trust-lists.md) — where the issuer check comes from
- [Verification](verification.md) — what the verdict means