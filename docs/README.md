# firma-it documentation

Everything about using this tool, in the order you are likely to need it.

| Document | What it answers |
|---|---|
| [Installation](installation.md) | How to get it running on Linux, macOS or Windows; what each build contains |
| [Command line](command-line.md) | Every command and flag, with the exit codes scripts depend on |
| [Signing](signing.md) | Choosing a format and level for your document, seals, chained signatures |
| [Verification](verification.md) | Reading a report, what each verdict means, what is actually checked |
| [Certificates](certificates.md) | Which certificates and keys are accepted, and how to inspect one |
| [Timestamps](timestamps.md) | RFC 3161 tokens: obtaining, using and verifying them |
| [Trust lists](trust-lists.md) | Where "trusted issuer" comes from, and why a downloaded list is not enough |
| [Desktop app](desktop.md) | The window: signing, verifying, pending requests |
| [Web pages](web-pages.md) | Making a browser ask `firma-it` to sign, safely |
| [Local API](local-api.md) | The HTTP surface for agents and scripts |
| [Smartcards](smartcards.md) | PKCS#11 tokens: setup, PINs, what is tested |
| [Troubleshooting](troubleshooting.md) | The errors you will actually hit, and what each one means |
| [Becoming a CA](becoming-a-ca.md) | What it takes to issue qualified certificates in Spain |

New here? Read [Installation](installation.md), then
[Signing](signing.md).

---

## In one page

`firma-it` produces and checks **AdES** electronic signatures: the European
standard family that Italian and Spanish administrations, and most of the EU,
accept.

| Format | Produces | Used for |
|---|---|---|
| **PAdES** | `document_signed.pdf` | PDF files |
| **XAdES** | `document_signed.xml` | XML invoices, forms, anything signed as XML |
| **CAdES** | `document.pdf.p7m` | Any file, wrapped in a CMS container |

Three things distinguish it from the signing tools that come with a bank or a
public administration:

1. **It tells you what it found.** Integrity, certificate validity, revocation
   and qualified status are four separate answers, not one "valid" badge.
2. **It refuses to overstate.** A self-signed certificate is not "advanced"
   trust. A signature made with a qualified certificate on a non-qualified device
   is not a QES. The report says which condition failed.
3. **It is verifiable without it.** Output is checked in the test suite by
   `openssl`, `pdfsig`, `qpdf` and `signxml` — tools written by other people.

## The three questions a verification answers

Almost every misunderstanding about electronic signatures comes from merging
these:

| Question | If the answer is bad |
|---|---|
| **Did the document change after signing?** | The signature is broken. Nothing else matters. |
| **Is the issuer recognised?** | The signature is mathematically sound but means nothing about identity. |
| **Was the certificate usable when it signed?** | Expired *at signing* is fatal; expired *since* is not. |

A file can be intact and worthless, or altered and still carry a valid
certificate. Reporting one flag hides both.

## Conventions used throughout

- **Exit codes.** `0` success, `1` invalid or tampered, `2` usage error, `3`
  could not verify. Scripts can branch on them.
- **`--json`** on every command that reports something, with stable shapes.
- **`--offline` is the default.** Nothing contacts a network unless you say so.
  `--offline=false` enables OCSP and CRL queries.
- **Nothing is interactive** once every parameter is supplied, which is what
  makes the tool usable from a script or an agent.

## What this documentation does not cover

National requirements that are not part of the AdES standards — a specific
administration's filing procedure, a registry's own validation portal, or the
legal effect of a signature in a given jurisdiction. This tool produces and
verifies the artefact; what an office accepts is their rule, not ours.

Where a statement here is a limitation rather than a feature, it is written as a
limitation. If you find one that is inaccurate, that is a bug.