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
| Formats: CAdES `.p7m` (content embedded), PAdES, XAdES enveloped, enveloping (any file: XML as XML, other files in Base64) and detached | built |
| Levels B, T, LT, LTA for every format; T and above need a timestamp authority; LT and LTA fetch revocation evidence only when allowed (`--online-revocation`) | built |
| Output next to the document: `<name>.<ext>.p7m`, `<name>_signed.pdf`, `<name>_signed.xml` | built |
| Signer name: the certificate holder unless one is given | built |
| PAdES visible seal: certificate data only (ADR-0007), placed by the user, repeatable across pages; chained signatures by incremental update | built |
| PAdES invisible signature; default seal placed on the real page size | built |
| PAdES seal in an existing empty form field: `sign --field <name>`, the seal in its box or none with `--invisible`; trebaruna's own incremental update (pdffield) and CMS envelope, cross-references of the file's kind | built (command line, `trebaruna fields`, the window's field choice, afirma:// `signatureField`) |
| CAdES detached (`.p7s`), verified with the document beside it | built |
| Parallel signatures (co-signing) and counter-signatures on CAdES, levels B, T, LT (revocation values in the added SignerInfo) and LTA (archive-time-stamp-v3 on the signature added, or on each that took counter-signatures) | built |
| Parallel signatures on XAdES enveloped: signing a signed XML adds a signature beside the others; each excludes every signature (AutoFirma's XPath filter), so none breaks another | built |
| Counter-signatures on XAdES | planned (B5) |
| Several documents in one run, same settings, one result per document | built |
| Signature policies (EPES) in CAdES and XAdES: AGE 1.9 and 1.8, FacturaE 3.1 and 3.0 by name, with AutoFirma 1.9's digests; any other by identifier, digest and qualifier, never downloaded; a policy named by a URL only in XAdES | built |
| Claimed roles in XAdES (`SignerRoleV2`) | built |
| FacturaE invoices: unsigned `Facturae` documents, XAdES enveloped, FacturaE's policy, role `emisor` by default and only the policy's roles | built (not yet checked with the administration's own validator) |
| Signature policies in PAdES (EPES), from the command line and afirma:// `expPolicy`: trebaruna's own incremental update and CMS envelope, in a new field with a seal per placement or none, or in a form's field | built |
| XAdES detached: `<document>.xsig` beside the untouched document, which the signature names; verify finds it there or takes `--content` | built |
| AutoFirma's "XAdES Detached" (an `AFIRMA` root holding `CONTENT` and the signature) for afirma:// pages | built |
| Plain XMLDSig (`--format xmldsig`, afirma:// `XMLDSig…`): the same layouts without signed properties, level B only, no policy; verify names it XMLDSig | built |
| ASiC-S signed in one step (`sign --asic s`, afirma:// `CAdES-ASiC-S`, `XAdES-ASiC-S`): the document and its detached CAdES or XAdES signature, the XML one inside `asic:XAdESSignatures` | built |
| ASiC-E signed in one step (`sign a b c --asic e`): one XML signature referencing every document, or a CAdES signature over an `ASiCManifest` of their digests | built |
| Handwritten-signature image next to the certificate data (ADR-0012): `sign --rubric firma.png`, afirma:// `signatureRubricImage`, the desktop's rubric row; PNG or JPEG, left of the data at most half the width, proportions kept; the data keep their size and a box too narrow for both is refused; the default seal widens to 160x48 pt | built |
| ODF signatures (ADR-0015): `sign file.odt` signs inside the package as LibreOffice does, XAdES over every stream (mimetype and manifest included); added signatures keep the earlier ones; LibreOffice 26.2 reports them valid; verify reads ODF, LibreOffice's included | built |
| OOXML signatures (ADR-0015): `sign file.docx` (`.xlsx`, `.pptx`, macro-enabled files and templates) signs inside the package as Microsoft Office does, a signature part whose Manifest covers every part but the document properties, the relationships through the RelationshipTransform; added signatures keep the earlier ones; LibreOffice 26.2 reports them valid, LibreOffice's and Office's earlier ones included; verify reads OOXML, Office's and LibreOffice's signatures included, and names parts added later | built |

### Keys

| Rule | Status |
|---|---|
| PKCS#12 in DER and BER (ADR-0009), PEM bundles | built |
| PKCS#11 cards and tokens from the CLI; certificate listing without PIN | built |
| Pick a certificate on a card by serial or fingerprint; without one, the only certificate or the only non-repudiation one signs, never a guess; the card holding it is found without a label and without trying the PIN; OpenSC found automatically on each system | built |
| PIN attempts are never spent needlessly: state read before login, no empty PIN, a refused PIN stops the run (a batch included), the state after a refusal stated | built |
| Cards and tokens in the desktop window: every certificate listed in full, the signing one chosen, PIN state and locked cards stated before typing, a refused PIN cleared and the card read again | built |
| Firefox / NSS store used in place, without exporting: read-only, primary password as PIN, CLI (`--firefox`, `--nss-db`) and window | built |
| Change PIN, unlock with PUK: state and length checked before any attempt, secrets only in the environment, CLI (`pin`) and window (Card menu) | built |
| Windows and macOS system stores | planned (C5) |
| Remote signing through the CSC API v2 only (ADR-0014): `--csc` and `--credential`; token or user/password; PIN and OTP per signature for explicit credentials; the receipt names the provider; every connection recorded | built (no OAuth2 browser flow; desktop: CLI only for now) |

### Timestamps

| Rule | Status |
|---|---|
| RFC 3161 tokens (`.tsr`) and their verification; authorities with an account | built |
| Time-stamped data `.tsd` (RFC 5544): create, verify (renewals included, DER or BER), extract (nested `.p7m.tsd`) | built |
| Qualified timestamping services named from the trusted list (`trust tsa`); every timestamp says whether its authority is qualified, offline. The lists (IT, ES, AT, BE) publish no service addresses, so the address comes from the provider | built |

### Verify

| Rule | Status |
|---|---|
| PAdES, CAdES, XAdES; chain at the proven signing time; qualification from three independent conditions; offline by default, OCSP when allowed | built |
| Verdicts: qualified, advanced, untrusted, invalid, broken, unknown — words and exit codes stable | built |
| Detached signatures with their document; CAdES signature trees checked node by node | built |
| Extract the signed document from `.p7m` (nested, DER/BER/PEM/Base64); ASiC through `asic --extract` | built |
| XML signatures checked completely: every reference (document, signed properties, objects), every signature of a document; what cannot be checked is unknown, not broken | built |
| ASiC-S and ASiC-E containers: each CAdES (over the document, or over its signed `ASiCManifest` whose digests must match) or XAdES signature against the files it covers; files no signature covers are reported | built |
| Exportable report (`verify --report x.md|.html|.pdf`): file and SHA-256, verdict, every signature and finding in the chosen language, connections, version; home directory as `~` | built (CLI; the Check tab saves a PDF) |
| Check tab: counter-signatures indented under what they sign; the files each container signature covers and those none covers; extraction from `.p7m`, `.tsd` and ASiC containers | built |

### Encrypt

| Rule | Status |
|---|---|
| `.p7e` envelopes for recipients' certificates and their decryption with a file, a card or a store (ADR-0011): CLI | built |
| `.p7e` encryption and decryption in the window | planned |

### Web entry points

| Rule | Status |
|---|---|
| Local HTTP API and `trebaruna://` handler under ADR-0004 | built |
| AutoFirma `afirma://` protocol, specified from the free source in [afirma-protocol.md](afirma-protocol.md) | specified (D1) |
| `afirma://` requests read and answered as AutoFirma 1.9 does (dispatch, parameters, SAF errors, certificate filters) for sign, cosign, countersign, signandsave, selectcert and save, each approved by a person first; CAdES (implicit/explicit, co-, counter-), PAdES (invisible unless placed), XAdES enveloped/enveloping | built (D2) |
| `afirma://` through the intermediate server: answers posted ciphered (DES, AES for autoscript 1.10), `#WAIT` while the person decides, uploaded requests fetched; `trebaruna afirma` | built (D3) |
| `afirma://` batches: JSON and XML through the site's pre- and post-signers (three-phase), and local batches; every document shown before approval | built (D4) |
| `afirma://` single signatures through the site's server (`…tri` formats) | planned |
| `afirma://` approval window: the request in full, the certificate chosen (card, Firefox, file) and held to the page's filters, decision through a pipe to `trebaruna afirma --interactive` | built (D6) |
| `afirma://` handler registered next to AutoFirma (desktop entry, macOS bundle); the person chooses the default (`make afirma-default`); no browser preference installed | built (D7) |
| `afirma://` WebSocket and socket channels: TLS on 127.0.0.1 needs a locally trusted certificate, which ADR-0013 forbids installing as a root; not offered unless the owner chooses a leaf-only peer trust | blocked (D5, owner decision) |

### Transparency

| Rule | Status |
|---|---|
| Connection record in every JSON result and in the window (ADR-0010) | built |
| Document fingerprint in the receipt and before signing | built |
| Dependencies and licences embedded and printable | built |
| Reproducible release with SBOM and checksums (ADR-0017) | built |

### Packages

| Capability | Status |
|---|---|
| `.deb` with the window, the card CLI, the launcher and its URL handlers, icons, AppStream, dependencies from the binaries (`make package-deb`); checked with dpkg-deb, apt and the extracted binaries | built |
| AppImage (`make package-appimage`): the window, or the command line through a link named `trebaruna`; AppDir checked, packing needs appimagetool | built (packed in CI) |
| Flatpak manifest (`make package-flatpak`), without cards for now | in CI, not yet run |
| Windows installer (WiX v4, per user, `afirma://` optional and off by default) | in CI, not yet run |
| CI on Windows (tests, window, zip, MSI) and macOS (tests, `.app`); Linux `.deb` installed and removed, AppImage, Flatpak | written, not yet run (needs publishing) |

### Page preview

| Capability | Status |
|---|---|
| Page preview without poppler: trebaruna draws the page itself (text in place in Go's typeface, shapes, JPEG/Flate pictures with transparency, forms, annotation appearances, OCR text left out), poppler preferred when installed, the window saying which | built |

### Accessibility

| Capability | Status |
|---|---|
| WCAG 2.2 AA review of the window (docs/accessibility.md): text 4.5:1 and control edges 3:1 on every surface, every action on the keyboard (seal moved with arrows, resized with + and −), names for icon buttons and the page | built |
| Screen readers through Fyne's accessibility tag on Windows and macOS | built, untried with NVDA/VoiceOver |
| Screen readers on Linux; light or high-contrast theme | pending (Fyne; owner choice) |

### Languages

| Capability | Status |
|---|---|
| Window, approval windows and verification report in Spanish, Catalan, Galician, Basque, Italian and English (`TREBARUNA_LANG`, `$LANG`, `verify --lang`); tests fail on a missing string, a string left in Spanish or a lost formatting verb | built |

## Use cases (application layer)

| Slice | Use case | One public method |
|---|---|---|
| signing | `SignDocument` | `Execute(ctx, Request) (Artefact, error)` |
| signing | `ChangeCardPIN`, `UnlockCard` | `Execute(ctx, Card, secret, newPIN) error` |
| verification | `VerifyDocument` | `Execute` |
| trust | `VerifyList` | `Execute` |
| encryption | `EncryptDocument`, `DecryptDocument` | `Execute` |
| afirma | `AnswerPage` | `Execute(ctx, Invocation) (Answer, error)` |
| desktop | `SignFromDesktop`, `PreviewPage`, `InspectCertificate`, `ListCards`, `ChangeCardPIN`, `ReviewPageRequest` | `Execute` |

New capabilities add use cases here as they are built.
