# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `make install-desktop` failed on every machine: it installed
  `packaging/trebaruna.desktop`, but the file was still `firma-it.desktop`.
- `make package-desktop` called a script that lived in the ignored `bin/`
  directory and still produced `pignus` archives; it is now the tracked
  `packaging/package-desktop.sh` and builds `trebaruna` archives with the
  version injected. CI runs both targets.
- The macOS bundle injected the version into `cli.Version`, a variable that
  does not exist, so the bundled CLI never reported the release version.
- The desktop app ID and the macOS bundle identifier are now the same,
  `org.codeberg.simplicer.trebaruna`, instead of the old `it.firma.desktop`.

### Security

- The desktop app no longer passes the certificate passphrase as `--pass`,
  where every local user could read it in the process list. The CLI accepts
  `TREBARUNA_PASSPHRASE`, `TREBARUNA_PIN` and `TREBARUNA_TSA_PASS` when the
  matching flag is absent (`sign`, `certificate`, `timestamp`, `token`,
  `handler`); an explicit flag still wins.

### Changed

- Desktop: the command-line adapter moved out of the application and domain
  layers. `SignFromDesktop` now depends on a `Signer` port and returns a typed
  `Receipt` read from `sign --json`, instead of predicting the output name and
  echoing raw JSON. A receipt whose file is missing is reported as a
  translatable problem rather than a Spanish sentence built in the use case.
- Desktop: the application layer is covered by unit tests (100 %), and the
  adapter by tests that run a stand-in command.

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

## [0.2.0-unstable] - 2026-11-02

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

## [0.3.1-unstable] - 2026-11-08

### Fixed

- A binary installed with `go install` reported `0.1.0-unstable`, because the
  version was only set by the Makefile's linker flags and a user's own build
  applies none. The version now falls back to the one the toolchain records in
  the build information, which is the version the user asked for. Binaries
  built by this repository's Makefile are unaffected.
- The mirror workflow carried the branch but not the tags, so a mirror user
  asking for a version was told it did not exist.

## [0.3.0-unstable] - 2026-11-08

### Changed

- The project is now called **trebaruna** (Latin: pledge, security, guarantee). Module
  path, binaries, environment variables (`TREBARUNA_*`), URI scheme, cache directory
  and documentation all follow.

### Fixed

- `verify` reported "altered" for a signature made with a certificate that had
  expired or was revoked before signing, in the same report that said the
  integrity was correct. The document was intact; the signer simply was not
  entitled to sign. That is now the `invalid` verdict, with its own exit code 4,
  distinct from the exit code 1 that means the bytes changed.
- An XAdES document could never chain to an authority. The verifier read only the
  first certificate in `KeyInfo`, so the intermediate that signed the leaf was
  ignored and the path to the anchor could not be built. Every foreign XML
  signature read as untrusted. The whole chain is now read, and the embedded
  intermediates build the path.
- `trebaruna token` returned no certificates on a card that held one: the object
  search template carried an identifier with no value, which the driver reads as
  "the identifier is empty" and matches nothing. Only the class is now searched.
- The token diagnostic opened a session read-write before logging in, which a
  driver is free to refuse, and reported `CKR_CRYPTOKI_ALREADY_INITIALIZED` as a
  failure. Both are driver behaviour a diagnostic has to survive, because the
  situation it exists for is a program that already talks to the card.
- The macOS bundle script copied the license in *after* the signature, which
  invalidates it: `codesign --verify` then fails for a reason that has nothing to
  do with the binary. The resource is signed first, then the bundle, which is the
  order macOS verifies in.
- The XML and CMS verifiers compared against a pool of roots only, and a pool
  cannot be enumerated. A trust list publishes the authority that issues
  qualified certificates, and that authority is normally an intermediate, so
  neither could reach it. Both now take the raw certificates of the list and
  treat them as anchors, which is what the PDF adapter already did.
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
- `trebaruna://` handler with mandatory human approval, signing and delivery.
- Full English manual in `docs/`, twelve documents.
