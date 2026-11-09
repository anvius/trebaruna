# Specification

What trebaruna does, as business rules. Implementation choices live in
[`adrs/`](adrs/README.md); usage lives in the other documents. Items marked
*(planned)* are specified here before they are built.

## Purpose

Replace AutoFirma completely with one light, transparent, free program: sign
and check documents with the ETSI AdES profiles that Italian and Spanish
administrations require, from a file, a card, a system store or a
remote provider, offline unless a step needs the network, and never without the
user seeing what is signed and where anything goes.

## Principles (constraints on every feature)

1. **Light**: one binary per platform; the static CLI under 15 MB, the desktop
   under 40 MB; no JVM, no Electron, no runtime downloads.
2. **Free**: only free dependencies; no mandatory external program; free card
   drivers (OpenSC) by default, a vendor module only when the user picks it.
3. **Transparent**: every connection is explicit and recorded (ADR-0010); the
   document fingerprint is shown before signing; web requests are shown and
   approved by a person (ADR-0004); secrets never appear on a command line
   (ADR-0006); builds are reproducible.
4. **Honest verdicts**: an intact document is never reported as altered
   (ADR-0005); trust comes only from authenticated trusted lists (ADR-0003).

## Capabilities

### Sign

| Rule | Status |
|---|---|
| Formats: CAdES `.p7m` (content embedded), PAdES, XAdES enveloped and enveloping | built |
| Levels B, T, LT, LTA for every format; T and above need a timestamp authority; LT and LTA fetch revocation evidence only when allowed (`--online-revocation`) | built |
| Output next to the document: `<name>.<ext>.p7m`, `<name>_signed.pdf`, `<name>_signed.xml` | built |
| Signer name: the certificate holder unless one is given | built |
| PAdES visible seal: certificate data only (ADR-0007), placed by the user, repeatable across pages; chained signatures by incremental update | built |
| PAdES invisible signature; seal in an existing empty field; default seal sized to the real page | planned (B1) |
| CAdES detached (`.p7s`), verified with the document beside it | planned (B2) |
| Parallel signatures (co-signing) and counter-signatures on CAdES and XAdES | planned (B4, B5) |
| Several documents in one run, same settings, one result per document | planned (B6) |
| Signature policies (EPES): AGE, FacturaE; FacturaE invoices | planned (E1) |
| XAdES detached and plain XMLDSig | planned (E2) |
| ASiC-S / ASiC-E signed in one step | planned (E3) |
| Handwritten-signature image next to the certificate data (ADR-0012) | planned (G3) |
| ODF and OOXML signatures (ADR-0015) | planned (G1, G2) |

### Keys

| Rule | Status |
|---|---|
| PKCS#12 in DER and BER (ADR-0009), PEM bundles | built |
| PKCS#11 cards and tokens from the CLI; certificate listing without PIN | built |
| Pick a certificate on a card; OpenSC found automatically on each system | planned (C1) |
| Cards and tokens in the desktop window, with PIN attempts and locked cards stated | planned (C2) |
| Firefox / NSS store used in place, without exporting | planned (C3) |
| Change PIN, unlock with PUK | planned (C4) |
| Windows and macOS system stores | planned (C5) |
| Remote signing through the CSC API v2 only (ADR-0014) | planned (F5) |

### Timestamps

| Rule | Status |
|---|---|
| RFC 3161 tokens (`.tsr`) and their verification; authorities with an account | built |
| Time-stamped data `.tsd` (RFC 5544): create, verify, extract | planned (E4) |
| Choose a qualified authority from the trusted list | planned (F1) |

### Verify

| Rule | Status |
|---|---|
| PAdES, CAdES, XAdES; chain at the proven signing time; qualification from three independent conditions; offline by default, OCSP when allowed | built |
| Verdicts: qualified, advanced, untrusted, invalid, broken, unknown — words and exit codes stable | built |
| Detached signatures with their document; signature trees (co- and counter-signatures) | planned (B2, B4) |
| Extract the signed document from `.p7m` (nested) and ASiC | planned (B3) |
| Exportable report | planned (F2) |

### Encrypt

| Rule | Status |
|---|---|
| `.p7e` envelopes for recipients' certificates and their decryption (ADR-0011) | planned (F4) |

### Web entry points

| Rule | Status |
|---|---|
| Local HTTP API and `trebaruna://` handler under ADR-0004 | built |
| AutoFirma `afirma://` protocol: single operations, batches (JSON/XML, one- and three-phase), intermediate server, WebSocket without an installed root (ADR-0013) | planned (D1–D7) |

### Transparency

| Rule | Status |
|---|---|
| Connection record in every JSON result and in the window (ADR-0010) | built |
| Document fingerprint in the receipt and before signing | built |
| Dependencies and licences embedded and printable | built |
| Reproducible release with SBOM and checksums (ADR-0017) | planned (A5) |

## Use cases (application layer)

| Slice | Use case | One public method |
|---|---|---|
| signing | `SignDocument` | `Execute(ctx, Request) (Artefact, error)` |
| verification | `VerifyDocument` | `Execute` |
| trust | `VerifyList` | `Execute` |
| desktop | `SignFromDesktop`, `PreviewPage`, `InspectCertificate` | `Execute` |

New capabilities add use cases here as they are built.
