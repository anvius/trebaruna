# Verification

What the report says, what each verdict means, and what is actually checked.

- [The six verdicts](#the-six-verdicts)
- [The three questions](#the-three-questions)
- [Finding codes](#finding-codes)
- [Reading the JSON](#reading-the-json)
- [What is really checked, and what is not](#what-is-really-checked-and-what-is-not)
- [Revocation](#revocation)
- [The qualified verdict](#the-qualified-verdict)
- [Common scenarios](#common-scenarios)

---

## The six verdicts

`verify` reports one verdict per signature, from best to worst:

| Verdict | Meaning | Exit code |
|---|---|---|
| `qualified` | A QES: qualified certificate, qualified device, granted qualified issuer, all verified | 0 |
| `advanced` | A valid advanced signature from a recognised authority. Not qualified. | 0 |
| `untrusted` | The cryptography holds, but no trusted list vouches for the issuer | 3 |
| `unknown` | Could not decide: no trust list, unreadable file, unsupported format | 3 |
| `broken` | The document or the signature was altered, the certificate was revoked before signing, or it had already expired when it signed | 1 |

A **self-signed** certificate that is still valid produces `untrusted` (exit 3),
not `broken`: nothing is wrong with the signature, only with who vouches for it.
One that is *also expired* produces `broken`, because expired-at-signing is fatal
regardless of who issued it.

`advanced` is the normal verdict for a signature made with a certificate from a
recognised authority. `qualified` is narrower than most people assume — see
[the qualified verdict](#the-qualified-verdict).

---

## The three questions

Every finding belongs to one of three questions, and mixing them is the source of
most confusion about electronic signatures.

### 1. Integrity — did the bytes change?

`signature.intact`, `signature.modified`, `signature.unverifiable`,
`content.missing`, `certificate.missing`.

An XML signature is checked completely: every reference in `SignedInfo` —
the document, the signed properties (signing time, signing certificate,
policy, role), any other object — is dereferenced, transformed and digested,
then the signature value over `SignedInfo`. A change to any of them is
`signature.modified`. A signature that uses an algorithm or a transform
trebaruna does not implement (an XPath expression other than the
`not(ancestor-or-self::ds:Signature)` filter, XPointer, XSLT) is
`signature.unverifiable`: unknown, not broken. SHA-1 signatures, still found
in older files, are checked; so are RSA-PSS (`…-rsa-MGF1`, RFC 6931, with a
key published as id-RSASSA-PSS or as plain RSA) and SHA-3 digests and
signatures (RFC 9231). A document with several signatures (co-signed,
or counter-signed inside) gets one report per signature.

CMS and PDF signatures made with RSASSA-PSS (RFC 4055, with its parameters:
digest, MGF1 over the same digest, salt length) are checked by trebaruna
itself, since the CMS and PDF libraries it builds on lack them; a PDF
signature is a detached CMS over its byte ranges, so it gets the CAdES
checks, though the revocation data of the document's `/DSS` is not read for
it. An authority whose key is published as id-RSASSA-PSS — German
qualified ones such as D-TRUST CA 3-1 2016 and the HBA authorities —
anchors chains like any other. An algorithm neither trebaruna nor the
libraries implement is `signature.unverifiable`, never `signature.modified`.

An ASiC container (`.asics`, `.asice`, ETSI EN 319 162-1) is unpacked into a
private directory, refusing entries whose names leave it or that exceed
512 MiB, and each signature under `META-INF` is judged against the files it
covers:
- a CAdES `signature*.p7s` against the one document of an ASiC-S, or against
  the `ASiCManifest` that names it, whose digests must match the files;
- a XAdES `signatures*.xml`, its references resolved from the container's
  root.

Files no signature covers are reported as `container.unsigned_files`: a
document added to a signed container is not signed.

If integrity is bad, nothing else matters. A tampered document with an otherwise
perfect certificate is worthless.

### 2. Trust — is the issuer recognised?

`certificate.trusted`, `certificate.untrusted_issuer`,
`certificate.self_signed`.

This is about **who issued the certificate**, not about the person. It answers
"does a supervisory authority list this CA as operating in the EU", which is a
different question from "is this Maria".

### 3. Validity — was the certificate usable when it signed?

`certificate.expired_at_signing`, `certificate.expired_now`,
`certificate.revoked_before_signing`, `certificate.revoked_after_signing`.

The distinction that matters:

| Situation | Finding | Effect |
|---|---|---|
| Valid when signed, expired today | `certificate.expired_now` | Warning only |
| Already expired when signed | `certificate.expired_at_signing` | **Fatal** |
| Revoked after signing | `certificate.revoked_after_signing` | Warning only |
| Revoked before signing | `certificate.revoked_before_signing` | **Fatal** |

A signature made in 2020 with a certificate that expired in 2022 is still a good
signature. One made in 2022 with a certificate that expired in 2020 is not.

---

## A report to keep or send

`--report verifica.pdf` (or `.html`, `.md`) writes the verification as a
document: the file and its SHA-256, the verdict, every signature with its
findings in the chosen language, the connections made, and the trebaruna
version. It describes the check; the signed file remains the evidence, and
anyone can verify it again.

---

## Finding codes

### Integrity

| Code | Status | Meaning |
|---|---|---|
| `signature.intact` | good | The signature matches the document |
| `signature.modified` | bad | The document changed after signing |
| `signature.unverifiable` | unknown | The signature uses an algorithm or transform trebaruna does not check |
| `content.missing` | unknown | A detached signature without the document it signs |
| `container.covers` | good | The files of an ASiC container a signature covers |
| `container.unsigned_files` | warn | Files of the container no signature covers: they are not signed, whatever else the container says |
| `content.partly_signed` | warn | An XML signature covers only some elements of the document around it (references by Id, none to the whole document): the parts named are not signed, whatever they say |
| `signature.not_qualified` | warn | A valid advanced signature that is not a QES |
| `signature.qualified` | good | The QES conditions all held |

### Certificate

| Code | Status | Meaning |
|---|---|---|
| `certificate.trusted` | good | The issuer is granted in an authenticated trust list |
| `certificate.untrusted_issuer` | unknown | No list vouches for this issuer |
| `certificate.self_signed` | warn | Valid cryptography, no third-party trust |
| `certificate.missing` | unknown | The signature does not embed the signing certificate |
| `certificate.expired_now` | warn | Expired since; the signature itself is unaffected |
| `certificate.expired_at_signing` | bad | Expired when it signed |
| `certificate.validity_unproven` | warn | No trusted signing time, so the validity window cannot be judged |
| `certificate.not_yet_valid_at_signing` | bad | Signed before the certificate was issued |
| `signing_certificate.bound` | good | The certificate shown is the one the signature names in its signed attributes (CAdES and PAdES signing-certificate-v2 or v1, XAdES SigningCertificate or V2) |
| `signing_certificate.mismatch` | bad | The signature names another certificate: one with the same key and another identity was put in its place. The signature counts as broken |
| `signing_certificate.missing` | warn | The signature names no certificate (older PKCS#7, plain XAdES properties): the identity shown is not bound to it |

### Revocation

| Code | Status | Meaning |
|---|---|---|
| `certificate.not_revoked` | good | A responder answered "not revoked" |
| `certificate.revoked_before_signing` | bad | Revoked before the signature |
| `certificate.revoked_after_signing` | warn | Revoked since; the signature stands |
| `certificate.revocation_unchecked` | warn | No answer could be obtained |

### Timestamp

| Code | Status | Meaning |
|---|---|---|
| `timestamp.bound` | good | The token covers this signature |
| `timestamp.accredited` | good | The authority is a qualified service of an authenticated list |
| `timestamp.untrusted_authority` | warn | The token is bound, its authority is not proven |
| `timestamp.not_timestamping_certificate` | warn | The token certificate lacks the time-stamping key usage |
| `timestamp.invalid` | bad | The token does not parse, verify, or cover this signature |
| `timestamp.archival` | good | An archive timestamp covers the signature (XAdES-A, or CAdES-A's archive-time-stamp-v3) |
| `timestamp.archive_unbound` | warn | The archive timestamp does not seal this signature as EN 319 132-1 5.5.2 (XAdES: its references, value, KeyInfo and the properties before it) or EN 319 122-1 5.5.3 (CAdES: the content, the SignerInfo and the hash index of its certificates, revocation values and unsigned attributes, all still present) read: it proves nothing about it |
| `timestamp.legacy_form` | warn | A trebaruna XAdES-T made before 0.38.2: the token seals the signature value as written, not its canonical form, and other validators refuse it |

### Environment

| Code | Status | Meaning |
|---|---|---|
| `trustlist.unavailable` | warn | No list cached for this territory |
| `trustlist.stale` | warn | The cached list is past its next-update date |
| `format.unsupported` | unknown | The container could not be parsed |
| `verification.warning` | warn | A library warning that has no better code |

---

## Reading the JSON

```bash
trebaruna verify atto.pdf --json
```

```json
{
  "verdict": "advanced",
  "format": "pdf",
  "signed": true,
  "signers": [
    {
      "field": "signature-1",
      "signer": "MARIA LOPEZ GARCIA",
      "identifier": "IDCES-00000000X",
      "issuer": "Example TSP",
      "integrity": "good",
      "trust": "advanced",
      "qualified": false,
      "timestamped": true,
      "signed_at": "2026-11-02T12:52:30+01:00",
      "qualification": {
        "certificate_qualified": true,
        "device_qualified": false,
        "service_listed": true,
        "missing": ["the private key is not proven to live in a qualified device"]
      },
      "timestamp": {
        "bound": true,
        "accredited": true,
        "service": "Qualified TSA",
        "provider": "Example TSP"
      },
      "revocation": {
        "status": "good",
        "checked": true,
        "source": "ocsp"
      },
      "policy": { "identifier": "2.16.724.1.3.1.1.2.1.9", "name": "AGE 1.9" },
      "claimed_roles": ["Apoderado"],
      "production_place": "Madrid",
      "findings": [ ... ]
    }
  ]
}
```

The `missing` array is what makes the verdict auditable: it names the condition
that failed, so a user can go and fix it rather than guess.

`policy`, `claimed_roles` and `production_place` are what the signature declares
of itself, covered by it: the signature policy (CAdES and PAdES
signature-policy-identifier, XAdES SignaturePolicyIdentifier; AGE 1.9 and 1.8 and
FacturaE 3.1 and 3.0 named), the roles its signer claims (XAdES SignerRole or
SignerRoleV2) and where it says it was made (XAdES SignatureProductionPlace or V2,
a PDF signature's /Location). They are statements, not facts trebaruna checked:
the policy's rules are not evaluated. The text output, the reports and the
window's Check tab show them too.

---

## What is really checked, and what is not

Stated plainly, because a verification tool that overstates its own coverage is
worse than none.

### Checked

- The cryptographic signature against the document bytes.
- The signer certificate against the trust lists the tool downloaded **and
  authenticated** against the EU root.
- The certificate chain, including when the document carries only the leaf. Most
  Spanish and Italian signing tools embed just the signer certificate, so the
  issuer is resolved from the trust list itself.
- That the certificate shown is the one the signer signed for: the digest in
  the signed signing-certificate attribute (CAdES, PAdES) or property
  (XAdES), against the certificate carried. Without it, a certificate with
  the same key and another name could stand in for the real one.
- The certificate validity window, against the proven signing time when a trusted
  timestamp exists.
- Revocation, when `--offline=false`, with the answer recorded as checked or not.
- The timestamp token: its signature, its imprint against this signature, its
  key usage, and its authority against the lists. A XAdES archive timestamp's
  imprint is recomputed from what it must seal.
- The document structure, for PDF: `pdfsig` and `qpdf` are used as judges in the
  test suite.

### Not checked

- **The signer's identity.** A qualified signature means the CA verified a
  document; it does not mean the person who pressed the button was that person.

### A note on the key-usage check

Document-signing certificates carry no single purpose: European qualified CAs issue
e-mail protection, Spanish notarial and corporate certificates carry client
authentication, and private PKI often omits the extension. The underlying PDF
library chains with Go's default of *server authentication*, which no signing
certificate carries, so chains that should verify were rejected as
"incompatible key usage". The verifier now re-checks the chain with the purposes a
document certificate actually has. Measured on a real Spanish notarial signature.
- **That the document is the one the parties agreed.** That is an editorial
  question, not a cryptographic one.
- **Anything inside the document.** Page rendering, embedded macros, JavaScript.
  This tool signs bytes; it does not sanitise them.
- **The legal effect.** Whether an office accepts the artefact is their rule.

---

## Revocation

Revocation is **opt-in**:

```bash
trebaruna verify atto.pdf --offline=false
```

The default is offline for a reason: a verification that silently contacts a third
party tells that party which documents you open, and fails on a machine without
network access.

The status is one of four explicit values, never a boolean:

| Status | Meaning |
|---|---|
| `good` | A responder said "not revoked" |
| `revoked` | A responder said "revoked" |
| `unknown` | Could not obtain an answer: offline, unreachable, stale response |
| `unsupported` | The certificate publishes no responder at all |

`good` and `unknown` are **not** the same. The JSON carries `checked` so you can
tell "we asked and the answer was no" from "we never asked".

A stale or future-dated response is rejected: an answer about a moment that has
passed is not evidence about now.

---

## The qualified verdict

`qualified` requires **three independent conditions**, and each is verified
separately:

| Condition | Where it comes from |
|---|---|
| **Qualified certificate** | `qcStatements` in the certificate itself |
| **Qualified device** | The certificate states where the private key lives |
| **Granted qualified issuer** | A `CA/QC` service, status `granted`, in an **authenticated** trust list, granted no later than the signing time |

None implies the others. A qualified certificate on a software key is not a QES.
A qualified certificate from a CA whose grant was withdrawn is not a QES.

The report lists what is missing:

```json
"missing": ["the private key is not proven to live in a qualified device"]
```

---

## Common scenarios

### "Valid, but untrusted"

```
Veredicto: emisor no reconocido
```

The cryptography is fine; the CA is not in the lists. Usually one of:

1. The trust lists are not downloaded yet: `trebaruna trust sync`.
2. The certificate is from a private CA, common in enterprise deployments.
3. The certificate is self-signed, which is fine for testing and means nothing
   for third parties.

### "Expired at signing"

Check the signing time. If it really was signed after expiry, the signature is
bad. If a **trusted timestamp** proves it was signed earlier, re-verify with the
timestamp present: the report then judges the certificate at the proven time.

### "Could not verify" with exit code 3

Not a bad signature. Something prevented a decision: no list, unreadable file,
unsupported format. Look at the findings — the first `unknown` explains it.

### A file with several signatures

Each is reported separately, with its own verdict. One bad signature does not
invalidate the others in the report, but it does make the overall verdict
`broken`, which is correct: somebody added something after signing.

---

## Next

- [Trust lists](trust-lists.md) — where "trusted" comes from
- [Certificates](certificates.md) — inspecting what you are signing with
- [Troubleshooting](troubleshooting.md) — the errors you will actually hit