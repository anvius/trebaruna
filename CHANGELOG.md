# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Seal position is repeatable: `--box` may appear several times, optionally as
  `PAGE:x1,y1,x2,y2`, and every mark shares a single cryptographic signature.
  `seal_count` is reported in the JSON output.
- Chained signatures verified: signing an already-signed PDF adds a valid
  incremental signature. Checked with up to five chained signatures.
- Free-space detection: the renderer rasterises the page with poppler, measures
  ink through a summed-area table, and proposes the emptiest conventional gap.
- Draggable seal overlay in the desktop app, clamped to the page.
- Welcome cover with the application icon, in three languages.
- Localised window theme; Italian Fyne strings supplied by hand.

### Changed

- The seal now prints the certificate identity and the signing instant, never
  user-typed text. `--caption` and `--image` are gone, and the GUI has no caption
  field: a signature mark whose text the signer writes is decoration, not proof.
- Default seal is 64x48 pt instead of 200x70 pt, and it grows the text into
  several lines rather than abbreviating the name.
- The certificate identity prefers givenName and surname over the common name.
- One clock: the instant is captured once and used for both the stamp and the
  report, so they cannot disagree by a second.
- Free-space search keeps a safety margin from the paper edge, because printers
  clip a few millimetres.

### Fixed

- XAdES was emitting invalid XML in three separate ways, all caught only by an
  independent verifier: a duplicated `<?xml?>` declaration, `KeyInfo` before
  `SignatureValue` (schema-invalid order), and missing `enveloped-signature`
  transforms so verifiers hashed the document with the signature inside.
  Digests were also taken over hand-written strings instead of canonical form.
- The signing skeleton is re-parsed before measuring, so the tree that is
  hashed is byte-for-byte the tree that is written.
- `isSelfSigned` used `CheckSignatureFrom`, which requires KeyUsageCertSign and
  therefore reported every self-signed signing certificate as CA-issued.
- The preview pane collapsed to zero width; the form pane clipped its buttons.
- The seal was drawn at the page origin instead of the requested box.

## [0.1.0-unstable] - 2026-11-02

First slice: CLI signing CAdES, PAdES and XAdES.

## [0.3.0-unstable] - 2026-11-02

First working slice. Not a stable release: major version 0 by policy.

### Added

- `sign` subcommand for CAdES (`.p7m`), PAdES (`_signed.pdf`) and XAdES
  (`_signed.xml`) with levels BES, T, LT and LTA declared.
- Hand-written CMS encoder (`src/signing/infrastructure/cms`) producing
  `signingCertificateV2` (RFC 5035) and accepting an RFC 3161 token as an
  unsigned attribute, which is what makes CAdES-T possible.
- Visible seal with explicit box (`--box x1,y1,x2,y2`), page, caption and image.
- PKCS#12, PEM and PKCS#11 key sources behind a single `crypto.Signer` contract.
- Self-signed certificates are accepted and flagged instead of rejected.
- `--json` output and stable exit codes (0 signed, 1 signing failure, 2 usage)
  for script and AI callers.
- File naming convention follows the practice of established signing tools.

- Native desktop app (`-tags gui`) built on Fyne: one form, file pickers,
  explicit seal box, off-UI-thread signing, opens the result on request.
- Localisation es / it / en, with a compile-checked catalogue per language and a
  Fyne bundle for Italian, which Fyne does not ship.

### Verified

- CAdES-BES and CAdES-T accepted by `openssl cms -verify -cades`.
- CAdES-T timestamp validated by pyHanko as `intact` and `trusted`.
- PAdES-B accepted by `pdfsig` with `Signature is Valid`.
- Seal lands inside the requested box (782 inked pixels in a 200x100 pt gap).
- Fyne window renders at 868x712 with 39 threads and zero translation failures
  in all three languages.
- Binary is 8.1 MB (8.4 MB on Windows) and static; cross-compiles to 5 targets
  with `CGO_ENABLED=0`.

### Known gaps

- PAdES B-LT and B-LTA: the PDF library rejects them. `--level lt` fails with
  an explanation rather than emitting a wrong profile.
- XAdES-T: `xades:SignatureTimeStamp` not implemented.
- XAdES output not yet validated against `xmlsec1`.
- PKCS#11 requires cgo, so the token build is a separate binary.
- Messages are English only; localisation pending.

## [0.3.0-unstable] - 2026-11-08

### Changed

- The project is now called **pignus** (Latin: pledge, security, guarantee). Module
  path, binaries, environment variables (`PIGNUS_*`), URI scheme, cache directory
  and documentation all follow.

### Fixed

- Spain was rejected as "publishes only a PDF" and every Spanish qualified
  signature read as untrusted. The EU list carries two pointers for Spain and the
  first match — the PDF — won. Now the XML pointer is preferred. ES: 442 services,
  131 qualified.
- A document carrying only its leaf certificate never chained. Most Spanish and
  Italian signing tools embed just the signer, so the issuer now resolves from the
  trust list itself.
- Every chain failed with "certificate specifies an incompatible key usage" — Go's
  default is ServerAuth and no document certificate carries it. The chain is now
  re-checked with the purposes documents actually have.
- `trust show`, which the manual documented and the binary did not have.
- CAdES-LT wrote its revocation material under the certificateValues OID (`.23`)
  instead of `revocationValues` (`.24`). A container that parsed and verified
  while meaning something else.

### Added

- CAdES-LT, CAdES-LTA and XAdES-LT are implemented. All twelve
  format/level combinations now exist.
- `pignus://` handler with mandatory human approval, signing and delivery.
- Full English manual in `docs/`, twelve documents.
