# Signing

Choosing the right format and level, positioning the seal, and what the result
actually contains.

- [Choosing a format](#choosing-a-format)
- [Choosing a level](#choosing-a-level)
- [The level matrix](#the-level-matrix)
- [The visible seal](#the-visible-seal)
- [Chained signatures](#chained-signatures)
- [Reasons and locations](#reasons-and-locations)
- [What ends up inside the file](#what-ends-up-inside-the-file)
- [Practical recipes](#practical-recipes)

---

## Choosing a format

The format is decided by what the document *is*, not by preference:

| Your document | Format | Because |
|---|---|---|
| PDF | **PAdES** | The signature is embedded in the PDF itself; any PDF reader can check it |
| XML (invoice, form, contract) | **XAdES** | The signature is an XML element, so XML tooling can process it |
| Anything else (zip, docx, jpg, csv) | **CAdES** | A CMS container wraps the file; nothing about the file is assumed |

`trebaruna` infers this from the suffix. `sign fattura.xml` produces XAdES
without being told. Override with `--format` when the suffix lies — a PDF named
`.bin`, for instance.

Asking for a format that cannot hold the document is refused:

```
$ trebaruna sign doc.xml --format pades
signing failed: signature format not applicable to this document:
.xml cannot hold a pades signature
```

That is better than producing a file that looks signed and that no XML tool can
open.

---

## Choosing a level

Levels come from the **AdES baseline** profiles (ETSI EN 319 122/132/142). Each
one adds a thing the previous one lacked:

| Level | Adds | Protects against |
|---|---|---|
| `bes` | Nothing | Nothing beyond the obvious |
| `t` | A trusted timestamp | The signer later claiming a different date |
| `lt` | Revocation data embedded | The CA's OCSP responder disappearing |
| `lta` | An archive timestamp | The timestamp authority's own certificates expiring |

**Most signatures are `bes` or `t`.** Use `lt` only if you need the signature to
stay verifiable for years after the signing infrastructure is gone — a contract
with a 20-year term, a notarial record, an audit trail.

Each step costs something: `t` needs a reachable TSA, `lt` needs a reachable
OCSP responder, `lta` needs both.

---

## The level matrix

Not every level exists for every format. This is what actually works, verified
against the binary:

| | `bes` | `t` | `lt` | `lta` |
|---|---|---|---|---|
| **CAdES** | ✅ | ✅ | ✅ `--online-revocation` | ✅ `--online-revocation` |
| **PAdES** | ✅ | ✅ | ✅ `--online-revocation` | ✅ `--online-revocation` |
| **XAdES** | ✅ | ✅ | ✅ `--online-revocation` | ✅ `--online-revocation` |

All twelve combinations are implemented and each is verified with an independent
tool. Where a level is refused, it is because an input is missing — a TSA for `t`
and above, a reachable responder for `lt` and `lta` — and the error names the flag
that supplies it. Nothing silently produces a lower level than you asked for;
that would be a false claim about the file.

---

## The visible seal

A seal is the human-readable mark: a box on the page containing the signer's name
and the signing time, drawn from the certificate.

```bash
--box 60,600,300,700
```

That is `x1,y1,x2,y2` in **PDF points**, with the origin at the bottom-left of the
page. A4 is 595×842 points.

Multiple marks, one cryptographic signature:

```bash
--box 1:60,60,280,160 --box 3:60,600,280,700
```

`PAGE:x1,y1,x2,y2`. Every mark shares the same signature value; you are not
signing twice.

### What goes in the seal

Only what the certificate says:

```
┌──────────────────────────────┐
│ ▌MARIA LOPEZ GARCIA          │  name, bold, wrapped, never truncated
│  MARTINEZ                    │
│  IDCES-00000000X · 02/11/2026│  identifier and date
│  14:05:09 +01:00             │  time, with the offset made explicit
└──────────────────────────────┘
```

There is deliberately **no option to type arbitrary text onto a signature**. A
stamp carrying the signer's own prose is decoration; the cryptographic value is
what proves anything, and giving the impression otherwise is misleading.

### When the identity does not fit

The signature is refused rather than printed truncated:

```
signing failed: page 1: the identity does not fit the seal box
  "MARIA LOPEZ GARCIA MARTINEZ" needs 3 lines at 12pt in 240x100 pt
  options:
    enlarge the box:   --box 60,540,340,700
    drop the seal:     omit --box for an invisible signature
```

A truncated name on a signature is worse than no seal at all: it looks like a
different person.

### Without `--box`

Omitting `--box` places a default seal, 64x48 pt, 18 pt from the bottom and
right edges of the page given by `--page`, measured on the page's real visible
box (CropBox, else MediaBox, inherited from the page tree when needed): a
Letter or landscape page gets the seal in its own corner.

### Invisible signature

`--invisible` signs without any mark on the page: the signature is complete and
every reader lists it in its signature panel, but its widget is empty
(`/Rect [0 0 0 0]`). It excludes `--box`.

Signing into an existing empty signature field of a form is not supported yet:
the PDF library always adds a new field.

---

## Detached signatures

`--detached` leaves the document untouched and writes the signature beside
it: `<document>.p7s` for CAdES, `<document>.xsig` for XAdES. A detached XAdES
names the file it signs in its reference and digests its bytes; `verify`
reads the file of that name in the signature's directory, never a path or
an address. Every level works.

```bash
trebaruna sign offerta.docx --format cades --detached --p12 k.p12   # → offerta.docx.p7s
trebaruna verify offerta.docx.p7s                  # uses offerta.docx beside it
trebaruna verify firma.p7s --content offerta.docx  # or name the document
trebaruna sign offerta.docx --format xades --detached --p12 k.p12   # → offerta.docx.xsig
```

XAdES can also carry any file inside the signature (`--enveloping`): XML as
XML in a `ds:Object`, other files in Base64 with the Base64 transform, so the
digest is the file's own. AutoFirma's "XAdES Detached" is a third layout: a
new document whose `AFIRMA` root holds the content (`CONTENT`) and, beside it,
the signature. trebaruna writes it when a page asks for it through
afirma://, and verifies it like any other.

`--format xmldsig` writes a plain XML-Signature in any of these layouts: the
same signature without XAdES's signed properties, so it states no signing
time, policy or role and takes no timestamp (level B only). Some older
systems still ask for it, and AutoFirma keeps it for them; prefer XAdES
otherwise. `verify` names such a signature XMLDSig.

Without the document the bytes cannot be compared: the integrity is reported as
unknown, never as altered (ADR-0005).

---

## OpenDocument files

`sign acta.odt` signs inside the file, as LibreOffice does: a XAdES
signature over every part of the package, in
`META-INF/documentsignatures.xml`, and `acta_signed.odt` opens in
LibreOffice with the signature shown. Signing a signed file adds a signature
beside the earlier ones, LibreOffice's included. Texts, spreadsheets,
presentations and drawings (`.odt`, `.ods`, `.odp`, `.odg`, and their
templates) are signed the same way; every level works.

`verify` reads them, and names any part added after the signature.

---

## Remote signing (CSC)

Some providers keep the key on their server and sign for you. trebaruna
speaks their open interface, the Cloud Signature Consortium API v2, and no
vendor's software (ADR-0014):

```bash
export TREBARUNA_CSC_TOKEN=…            # or TREBARUNA_CSC_USER and _PASSWORD
read -rs TREBARUNA_PIN && export TREBARUNA_PIN
trebaruna sign contratto.pdf --csc https://provider.example/csc/v2 --credential firma-qualificata
```

- The document stays here. What travels is its hash, and the provider
  returns the signature over it.
- A credential that asks for a PIN (or a one-time password,
  `TREBARUNA_OTP`) is authorised for that one hash before each signature.
- `--credential` can be left out when the account holds a single
  credential; otherwise the error lists them.
- The receipt says the key is remote and names the provider, and every
  connection appears with the purpose `remote-signing` (ADR-0010). Neither
  the token nor the PIN is ever printed.
- Every format and level works, and the timestamps are fetched as usual.
- Providers that only authorise through an OAuth2 browser flow are not
  supported.

---

## ASiC containers

`--asic s` packs the document and its detached signature into one file, an
ASiC-S container (ETSI EN 319 162-1): `<document>.asics`, a ZIP whose first
entry is its media type, the document at the root, and the signature under
`META-INF`. CAdES writes `signature.p7s`; XAdES and XMLDSig write
`signatures.xml`, the signature inside `asic:XAdESSignatures`. Some offices
ask for this wrapper, and it keeps a signature from travelling without its
document.

```bash
trebaruna sign atto.pdf --format cades --asic s --p12 k.p12   # → atto.pdf.asics
trebaruna verify atto.pdf.asics
```

Several documents go under one signature in an ASiC-E container:

```bash
trebaruna sign acta.txt plano.pdf presupuesto.xml --format xades --asic e --out expediente.asice
trebaruna sign acta.txt plano.pdf --format cades --asic e --out expediente.asice
```

XAdES writes one signature with a reference to each document. CAdES signs
`META-INF/ASiCManifest.xml`, which lists every document with its digest.
Documents are stored by their name, so two with the same name are refused.

`verify` judges every signature of a container against the files it covers,
and names any file no signature covers.

---

## Adding signatures to an envelope

A `.p7m` or `.p7s` can receive more signatures without opening it:

| Operation | Command | Result |
|---|---|---|
| Parallel signature (co-sign): you sign the same document as the others | `sign atto.pdf.p7m --cosign --p12 k.p12` | `atto.pdf_cosigned.p7m`, one more SignerInfo |
| Counter-signature: you sign over the signatures already there | `sign atto.pdf.p7m --countersign leaves --p12 k.p12` | `atto.pdf_countersigned.p7m` |
| Counter-sign every signature, already counter-signed ones included | `--countersign all` | |

A counter-signature signs another signature's value, not the document (RFC
5652 §11.4), so it carries no contentType. Levels B and T are available for
added signatures; LT and LTA are not yet. A detached `.p7s` needs its document
to be co-signed: `--content atto.pdf`.

`verify` checks each signature of the tree on its own — digest, signature,
timestamp, chain — and reports counter-signatures under the signature they
counter-sign. Envelopes co-signed by other tools (for example
`openssl cms -resign`) are read the same way.

---

## Signature policies (EPES)

Some recipients require a signature to name the rules it was made under: the
Spanish General State Administration (AGE) and FacturaE electronic invoices
do. The signature then carries the policy's identifier and the digest of its
document, and a validator compares that digest with the policy it knows.

| Policy | Flag | Formats | Identifier |
|---|---|---|---|
| AGE 1.9 | `--policy age` | CAdES, XAdES | OID 2.16.724.1.3.1.1.2.1.9 |
| AGE 1.8 | `--policy age18` | CAdES, XAdES | OID 2.16.724.1.3.1.1.2.1.8 (a different digest for each format) |
| FacturaE 3.1 | `--policy facturae` | XAdES enveloped, FacturaE invoices | the policy's URL |
| FacturaE 3.0 | `--policy facturae30` | XAdES enveloped, FacturaE invoices | the policy's URL |
| Any other | `--policy-id`, `--policy-hash`, `--policy-hash-alg`, `--policy-qualifier` | CAdES, XAdES (a URL only in XAdES) | as given |

The digests are AutoFirma 1.9's. The AGE 1.9 digest equals the SHA-1 of the
document at its address today (checked on 2026-11-09). The FacturaE 3.1
digest is the one validators expect: the PDF at that address was re-issued
later and hashes differently, so recomputing it would produce signatures
validators reject. trebaruna never downloads a policy.

A FacturaE policy signs only an XML whose root is `Facturae` and that carries
no signature yet, always enveloped, and claims the role `emisor` unless
`--role` names another of the policy's roles (`receptor`, `tercero`).

```bash
trebaruna sign factura.xml --policy facturae --p12 k.p12
trebaruna sign factura.xml --policy facturae --role receptor --p12 k.p12
trebaruna sign solicitud.txt --format cades --policy age --p12 k.p12
```

PAdES refuses a policy for now: the PDF library writes the signed attributes
itself and cannot add this one. FacturaE signatures have been checked with
openssl and signxml, not yet with the Spanish administration's own validator.

---

## Chained signatures

Signing an already-signed PDF adds an **incremental update**: the earlier bytes
are untouched, so the earlier signatures stay valid.

```bash
trebaruna sign atto.pdf       --p12 k1.p12 --pass a    # → atto_signed.pdf
trebaruna sign atto_signed.pdf --p12 k2.p12 --pass b   # → atto_signed_signed.pdf
```

Verified with up to five chained signatures. Each is reported separately by
`verify`, in order, with its own verdict.

This is the same model public administrations use when an office countersigns
after the citizen signs.

An XML works the same way: signing `acta_signed.xml` adds a second
`ds:Signature` beside the first. Each signature leaves every signature out
of what it signs (the XPath filter `not(ancestor-or-self::ds:Signature)`,
as AutoFirma writes it), so adding one never breaks another; `verify`
reports each. FacturaE invoices take a single signature. XML signed by
trebaruna before 0.30.4 lacks the filter, and a second signature breaks it.

---

## Reasons and locations

```bash
--reason "Contratto di fornitura"
--location "Roma"
```

Both are stored in the signature dictionary and shown by PDF viewers. They are
**claims by the signer**, not verified facts, and `verify` treats them as such.

---

## What ends up inside the file

Useful to know when something goes wrong.

### PAdES-B

An incremental update containing a `/Sig` dictionary with a CMS container:
signer certificate, signed attributes, and the signature value. The original PDF
bytes are preserved exactly, which is what keeps earlier signatures valid.

### PAdES-B-LT

The same, plus a `/DSS` dictionary reachable from the document catalog: the
certificates and OCSP responses needed to check the signature later. It is written
as a **second incremental update**, after the signature, so the signature bytes are
never rewritten.

### PAdES-B-LTA

A `/Type /DocTimeStamp` signature with `/SubFilter /ETSI.RFC3161` covering the
whole file, `/DSS` included. This is what protects the validation material from
becoming worthless as its own certificates expire.

### XAdES enveloped

The signature goes inside the document's root element; everything else
stays as it was, the processing instructions and comments outside the root
included (a FatturaPA's `<?xml-stylesheet?>`, so viewers still render it).
The document reference (`URI=""`) covers the whole document node: the
instructions outside the root are signed, comments are not (XML-Signature
and C14N 1.0). xmlsec1 and Java's XML-Signature (used by EU DSS and
AutoFirma) read it that way. signxml, a Python library, canonicalises only
the root element and reports a document with such an instruction as
modified; that is signxml's reading, not a broken signature.

### XAdES-A

The signature element plus `xades:SignatureTimeStamp` and
`xades141:ArchiveTimeStamp`, in that order. The archive token covers the
signed document and every object of the signature (EN 319 132-1, 5.5.2.2),
which is why it must be written last.

### CAdES

A CMS `SignedData` with the content embedded and the CAdES-required signed
attributes. `.p7m` is the conventional name.

- **CAdES-T** adds a `signature-time-stamp` unsigned attribute.
- **CAdES-LT** adds `revocationValues` (`1.2.840.113549.1.9.16.2.24`) carrying the
  OCSP responses, so the signature stays checkable after the responder is gone.
- **CAdES-LTA** adds `archiveTimestampV3` over the container as it stands,
  revocation material included.

The revocation attribute's OID is worth stating: `.24` is `revocationValues`, and
the neighbouring `.23` is `certificateValues`. Using the wrong one produces a
container that parses and labels OCSP responses as certificates — it looks
correct, which is why the tests assert the OID through OpenSSL rather than
trusting our own encoder.

---

## Practical recipes

### A contract, signed once, with a visible seal

```bash
trebaruna sign contratto.pdf --p12 k.p12 --pass x \
    --reason "Accettazione" --box 60,60,300,170
```

### An invoice to an Italian public administration

```bash
trebaruna sign fattura.xml --pem k.pem --level t --tsa https://freetsa.org/tsr
```

### A document that must stay verifiable for 20 years

```bash
trebaruna sign mutuo.pdf --p12 k.p12 --pass x \
    --level lta --tsa https://freetsa.org/tsr --online-revocation \
    --tsa-user me --tsa-pass secret
```

### Sign in bulk

Name several documents: each is signed with the same settings and in its own
format (signed PDF, signed XML, `.p7m` for the rest) unless `--format` forces
one. One failure does not stop the others; the exit code is 1 when any failed.

```bash
trebaruna sign *.pdf fattura.xml --p12 k.p12 --json   # {"signed":…, "failed":…, "results":[…]}
trebaruna sign *.docx --format cades --detached --p12 k.p12
```

`--out` names one file, so it is refused with several documents. In the desktop
app, drop several files on the window, or use **File → Sign a folder…**.

### Sign and check in one go

```bash
trebaruna sign doc.pdf --p12 k.p12 --pass x >/dev/null &&
trebaruna verify doc_signed.pdf
```

Verifying your own output is worth doing once per key: it is how you find out that
your certificate's issuer is not in any public list, before a counterparty does.

---

## Next

- [Verification](verification.md) — what the report says about what you produced
- [Certificates](certificates.md) — which keys are accepted
- [Timestamps](timestamps.md) — choosing and using a TSA