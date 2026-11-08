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

`pignus` infers this from the suffix. `sign fattura.xml` produces XAdES
without being told. Override with `--format` when the suffix lies — a PDF named
`.bin`, for instance.

Asking for a format that cannot hold the document is refused:

```
$ pignus sign doc.xml --format pades
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

### Invisible signature

Omit `--box`. The signature is still a full signature; only the visible mark is
missing. Common for machine-to-machine documents.

---

## Chained signatures

Signing an already-signed PDF adds an **incremental update**: the earlier bytes
are untouched, so the earlier signatures stay valid.

```bash
pignus sign atto.pdf       --p12 k1.p12 --pass a    # → atto_signed.pdf
pignus sign atto_signed.pdf --p12 k2.p12 --pass b   # → atto_signed_signed.pdf
```

Verified with up to five chained signatures. Each is reported separately by
`verify`, in order, with its own verdict.

This is the same model public administrations use when an office countersigns
after the citizen signs.

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

### XAdES-A

The signature element plus `xades:SignatureTimeStamp` and
`xades141:ArchiveTimeStamp`, in that order. The archive token covers every object
of the signature, which is why it must be written last.

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
pignus sign contratto.pdf --p12 k.p12 --pass x \
    --reason "Accettazione" --box 60,60,300,170
```

### An invoice to an Italian public administration

```bash
pignus sign fattura.xml --pem k.pem --level t --tsa https://freetsa.org/tsr
```

### A document that must stay verifiable for 20 years

```bash
pignus sign mutuo.pdf --p12 k.p12 --pass x \
    --level lta --tsa https://freetsa.org/tsr --online-revocation \
    --tsa-user me --tsa-pass secret
```

### Sign in bulk

```bash
for f in *.pdf; do
    pignus sign "$f" --p12 k.p12 --pass x --json || echo "FAILED: $f" >&2
done
```

Each run is independent, so one failure does not stop the rest.

### Sign and check in one go

```bash
pignus sign doc.pdf --p12 k.p12 --pass x >/dev/null &&
pignus verify doc_signed.pdf
```

Verifying your own output is worth doing once per key: it is how you find out that
your certificate's issuer is not in any public list, before a counterparty does.

---

## Next

- [Verification](verification.md) — what the report says about what you produced
- [Certificates](certificates.md) — which keys are accepted
- [Timestamps](timestamps.md) — choosing and using a TSA