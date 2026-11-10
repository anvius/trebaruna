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
signing failed: page 1: certificate identity needs 7.4 pt of height but the seal offers 6.0 pt; enlarge the box instead of truncating the identity
```

Enlarge the box, or sign with `--invisible` for a signature without a seal
(omitting `--box` gives the default seal in the corner, not an invisible
signature).

A truncated name on a signature is worse than no seal at all: it looks like a
different person.

### With a handwritten signature

`--rubric firma.png` draws the image of a handwritten signature in every seal,
to the left of the certificate data, never alone (ADR-0012):

```
┌──────────────────────────────────────┐
│  ╭~~~~~~~~~╮  ▌MARIA LOPEZ GARCIA     │
│  ╰~~~~~~~~~╯   00000000X · 02/11/2026 │
│                14:05:09 +01:00        │
└──────────────────────────────────────┘
```

A PNG (its transparency is kept) or a JPEG, up to 4 MiB and 4096 pixels a
side. It takes at most half the seal, with its proportions; the data keep the
size they have without it, so a box too narrow for both is refused rather
than printed smaller. The default seal widens to 160x48 pt for it.

### Without `--box`

Omitting `--box` places a default seal, 64x48 pt (160x48 with `--rubric`), 18
pt from the bottom and right edges of the page given by `--page`, measured on
the page's real visible box (CropBox, else MediaBox, inherited from the page
tree when needed): a Letter or landscape page gets the seal in its own corner.

### Invisible signature

`--invisible` signs without any mark on the page: the signature is complete and
every reader lists it in its signature panel, but its widget is empty
(`/Rect [0 0 0 0]`). It excludes `--box`.

### Signing in a form's field

A form prepared for its signers has an empty signature field for each:
`--field <name>` signs in that one, by its fully qualified name (the partial
names of the field and its parents joined by dots, `form.Firma1`), and draws
the seal in the field's box. With `--invisible` the field is signed without a
seal. A name the form lacks is refused with the empty fields it has;
`trebaruna fields <pdf>` lists them, and the window offers them beside the page.

```bash
trebaruna sign solicitud.pdf --field Firma1
trebaruna sign solicitud-signed.pdf --field form.Firma2 --level t --tsa https://…
```

The PDF library always adds a field of its own, so this signature is written by
trebaruna: an incremental update that leaves every earlier byte, and every
earlier signature, intact. It holds the signature dictionary (PAdES baseline,
`ETSI.CAdES.detached`, the time in `/M`), the field with its value and
appearance, the appearance's objects, and `/SigFlags 3` on the form when it
lacked them; its cross-references are a table or a stream, as the file's are.
The CMS envelope is trebaruna's own (signing-certificate-v2, no signing-time
attribute), timestamped for level T; levels LT and LTA are added after it as
for any PDF signature. A field too small for a legible seal (type under 3 pt) is
refused, with `--invisible` offered. `--field` excludes `--box`. A document
its author certified against any change (DocMDP permissions 1) is refused
however it would be signed, in a field, with a seal or invisibly: any
signature would break the certification.

### PDF/A documents

A PDF/A document stays PDF/A when it is signed. trebaruna reads the part its
metadata claims (`pdfaid:part`) and, for a PDF/A document, sets the seal in
the Go fonts (BSD licence, part of the program), embedded whole as TrueType
with the widths read from the font program, instead of the standard Helvetica
a reader supplies; in PDF/A-1, which forbids soft masks, a rubric with
transparency is painted onto white. Other documents keep the lighter seal.
Invisible signatures change nothing a PDF/A validator looks at. The type is
a little wider than Helvetica, so a long identifier may take one more line;
nothing is cut. Checked with Ghostscript's PDF/A-1b and PDF/A-2b files and
veraPDF 1.30: seal and rubric pass, and pdfsig verifies the signatures.

### Encrypted PDFs

```bash
read -rs TREBARUNA_PDF_PASSWORD && export TREBARUNA_PDF_PASSWORD
trebaruna sign protegido.pdf --p12 k.p12              # invisible, or with a seal
TREBARUNA_PDF_PASSWORD=… trebaruna verify protegido_signed.pdf
```

A PDF encrypted with a password (RC4, AES-128 or AES-256, the standard
security handler) is opened with its user or owner password, read only from
`TREBARUNA_PDF_PASSWORD`, never a flag; one that only restricts permissions
(an empty user password) needs none. The signature is an incremental update
encrypted as the document is: every new string and stream with its object's
key, except the signature's `/Contents` (ISO 32000-1, 7.6.1 and 7.6.2), under
the document's own `/Encrypt`. The author's permissions are honoured: a
document that allows neither filling in forms nor changing annotations is not
signed. Levels B and T; LT and LTA are refused on an encrypted PDF (their
update is not encrypted), so sign at T or decrypt it first. afirma:// pages
give the password as `ownerPassword` or `userPassword`; the window asks for it
under the document when the PDF opens only with one. Checked with qpdf
(AES-256 R6, AES-128 R4, RC4-128), invisible and with a seal: pdfsig verifies
each with the password, `qpdf --check` finds the file sound, and after `qpdf
--decrypt` the signature's strings read as written.

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

## Word, Excel and PowerPoint files

`sign offerta.docx` signs inside the file, as Microsoft Office does: a
signature part in `_xmlsignatures`, whose Manifest covers every part of the
package but the document properties applications rewrite when they save.
`offerta_signed.docx` opens in Word and in LibreOffice with the signature
shown. `.xlsx`, `.pptx`, macro-enabled files and templates are signed the
same way (`--format ooxml`); every level works.

Signing a signed file adds a signature beside the earlier ones, Office's
and LibreOffice's included. A file that has no signature yet gets its
relationships parts written compactly first, as Office writes them, so
that Office and LibreOffice agree on the digest (ADR-0015 tells why).

`verify` reads them, names any part changed or added after the
signature, and says when a signature digests the package's relationships
the way LibreOffice does rather than as the standard says.

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

### Authorising in the browser (OAuth2)

Providers that sign people in, or have each signature authorised, through
their OAuth2 server give trebaruna a client id. With it, the person signs
in or agrees in their own browser, and no password reaches trebaruna:

```bash
trebaruna sign contratto.pdf --csc https://provider.example/csc/v2 --csc-client <client id>
```

- trebaruna asks the service where its OAuth2 server is (`info`), opens
  the authorisation page in the browser (`$BROWSER`, or the system's
  opener; the address is also printed on standard error) and waits, up to
  five minutes, for the browser to come back to `http://127.0.0.1:<port>/callback`.
  The code it brings is exchanged with PKCE (S256), and only if the state
  is this request's.
- Without a token or a user, the person signs in this way (scope
  `service`). A credential whose mode is `oauth2code` has each signature
  authorised for its one hash (scope `credential`), and the token the
  provider then gives signs it.
- A provider that registered a fixed address for trebaruna gets it with
  `--csc-redirect http://127.0.0.1:8765/callback`; it must be on this
  computer. A confidential client's secret goes in
  `TREBARUNA_CSC_CLIENT_SECRET`.
- The token and the secret are never printed. The browser's own
  connections are the browser's; trebaruna's (`info`, the code exchange)
  are listed as `remote-signing`.

---

## ASiC containers

`--asic s` packs the document and its detached signature into one file, an
ASiC-S container (ETSI EN 319 162-1): `<document>.asics`, a ZIP whose first
entry is its media type (stored, with its CRC and sizes in its own header
and no extra field, so the type stands at byte 38 and Java's
`ZipInputStream` reads the container), the document at the root, and the
signature under `META-INF`. CAdES writes `signature.p7s`; XAdES and XMLDSig write
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
Each document's media type, in the manifest and in a XAdES
`DataObjectFormat`, comes from its name's extension when that is a known one
(an office document is no plain ZIP), else from its bytes (an XML document
without its declaration is still XML).

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
5652 §11.4), so it carries no contentType. Added signatures take every level:
at T each carries its timestamp; at LT its chain's revocation values, in its own
SignerInfo (a counter-signature's nested inside the signature it signs); at LTA
an archive-time-stamp-v3 seals the parallel signature added, or each signature
that took counter-signatures, which seals them with it. A detached `.p7s` needs
its document to be co-signed, or counter-signed at LTA: `--content atto.pdf`.

An ASiC container takes a parallel signature too, of the kind it holds: `sign
expediente.asice --cosign` (or `.asics`). An ASiC-S's CAdES `signature.p7s` is
co-signed in place; its XAdES `signatures.xml` takes one more signature, and
every signature that verified must still verify (a file whose root declares
other namespaces would change the new signature's canonical form, and is
refused); an ASiC-E takes a new signature file over all its documents, a CAdES
`signatureNNN.p7s` over a new `ASiCManifestNNN.xml` or a XAdES
`signaturesNNN.xml`. The result is `expediente_cosigned.asice`, and the
report (`--json`'s `format`) names the kind added, whatever `--format` said.

Its signatures are counter-signed where they are: `sign expediente.asice
--countersign leaves` (or `all`) adds CMS counter-signatures to each
`signature*.p7s` and XAdES ones inside each `*signatures*.xml`, as for an
envelope or a signed XML document, and writes `expediente_countersigned.asice`.
At LTA the archive timestamp that seals a CAdES counter-signature covers
what that signature signs: the ASiC-S's document, or the `ASiCManifest` that
names it in an ASiC-E. XAdES counter-signatures take levels B and T.

A signed XML document is counter-signed in place too: `sign acta_signed.xml
--countersign leaves` (or `all`; a detached `.xsig` the same way, its
document beside it) adds a XAdES signature over each chosen
signature's `SignatureValue` (a reference of type
`http://uri.etsi.org/01903#CountersignedSignature`), inside that signature's
`UnsignedSignatureProperties` as `xades:CounterSignature`. trebaruna gives
every `SignatureValue` an `Id` when it signs, so the counter-signature names
it without touching it; a signature from elsewhere without one gets one when
nothing seals its value, and is refused when a timestamp does (the `Id` would
change what the timestamp sealed). Levels B and T; plain XMLDSig
signatures, which have no properties to hold one, are left alone. Every
signature that verified before must verify after, or nothing is written: a
signature whose enveloped transform removes only itself covers the others and
would break. A parallel XML signature is the signed file signed again.

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

A PAdES signature with a policy (PAdES-EPES) is written by trebaruna, since the
PDF library writes the signed attributes itself and cannot add this one: in a
new field with a seal at each placement, or none, or in a form's field with
`--field`, as an incremental update with trebaruna's CMS envelope (see
"Signing in a form's field"). FacturaE signatures have been checked with
openssl and signxml, not yet with the Spanish administration's own validator.

---

## Chained signatures

Signing an already-signed PDF adds an **incremental update**: the earlier bytes
are untouched, so the earlier signatures stay valid.

```bash
read -rs TREBARUNA_PASSPHRASE && export TREBARUNA_PASSPHRASE   # the passphrase, never on the command line
trebaruna sign atto.pdf       --p12 k1.p12    # → atto_signed.pdf (k1's passphrase in $TREBARUNA_PASSPHRASE)
trebaruna sign atto_signed.pdf --p12 k2.p12   # → atto_signed_signed.pdf (then k2's)
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
- **CAdES-LTA** adds an `archive-time-stamp-v3` (`0.4.0.1733.2.4`, EN 319 122-1
  5.5.3): a token over the signed content's type and digest, the SignerInfo
  (version to signature value) and an `ats-hash-index-v3` (`0.4.0.19122.1.5`,
  5.5.2) listing the digest of every certificate, revocation value and unsigned
  attribute value the envelope holds, revocation material included. The index
  travels in the token's own unsigned attributes, and `verify` recomputes all of
  it. Before 0.50.1 the token covered the container's DER under the v2 OID
  (`1.2.840.113549.1.9.16.2.48`): no validator could check it.

The revocation attribute's OID is worth stating: `.24` is `revocationValues`, and
the neighbouring `.23` is `certificateValues`. Using the wrong one produces a
container that parses and labels OCSP responses as certificates — it looks
correct, which is why the tests assert the OID through OpenSSL rather than
trusting our own encoder.

---

## Practical recipes

### A contract, signed once, with a visible seal

```bash
trebaruna sign contratto.pdf --p12 k.p12 \
    --reason "Accettazione" --box 60,60,300,170
```

### An invoice to an Italian public administration

```bash
trebaruna sign fattura.xml --pem k.pem --level t --tsa https://freetsa.org/tsr
```

### A document that must stay verifiable for 20 years

```bash
trebaruna sign mutuo.pdf --p12 k.p12 \
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
trebaruna sign doc.pdf --p12 k.p12 >/dev/null &&
trebaruna verify doc_signed.pdf
```

Verifying your own output is worth doing once per key: it is how you find out that
your certificate's issuer is not in any public list, before a counterparty does.

---

## Next

- [Verification](verification.md) — what the report says about what you produced
- [Certificates](certificates.md) — which keys are accepted
- [Timestamps](timestamps.md) — choosing and using a TSA