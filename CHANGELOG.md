# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Qualified timestamping from the trusted list: `trebaruna trust tsa
  [territory]` lists the granted TSA/QTST services (and their addresses when a
  list publishes them, which IT, ES, AT and BE do not), and `trebaruna
  timestamp` reports whether the authority used is qualified by the cached
  list (`status`; `qualified`, `qualified_by` in JSON), offline. The TSL parser
  reads ServiceSupplyPoint; TrustList.QualifiedTimestampService is shared with
  verification.

- Encrypted envelopes (`.p7e`, ADR-0011): `trebaruna encrypt <file> --to
  <cert> [--to …] [--oaep]` and `trebaruna decrypt <file.p7e>` with the key
  flags of `sign` (file, card, Firefox store). CMS EnvelopedData written in
  this repository: AES-256-CBC content, RSA PKCS#1 v1.5 (default) or
  RSA-OAEP/SHA-256 key transport; OpenSSL envelopes (PKCS#1 v1.5, OAEP SHA-1
  or SHA-256) open, and ours open in OpenSSL. Recipients are checked first
  (RSA key, keyEncipherment when usages are declared, not expired); on a card
  the certificate the envelope names is found without the PIN and only the
  content key is decrypted there. New slice `encryption` with the use cases
  `EncryptDocument` and `DecryptDocument`; `sign` and `decrypt` share their
  key flags.

- Time-stamped data (RFC 5544): `timestamp --tsd` writes `<file>.tsd` with the
  document, its name and media type, and the token; `verify-tsr <file.tsd>`
  checks every token (the first against the document, renewals against the
  previous token) and reads DER or BER; `extract` opens `.tsd`, nested ones
  included (`name.pdf.p7m.tsd`).

- Card PIN management: `trebaruna pin change` (current PIN → new) and
  `trebaruna pin unlock` (PUK → new PIN, for a locked or forgotten PIN), with
  the secrets only in `TREBARUNA_PIN`, `TREBARUNA_PUK` and `TREBARUNA_NEW_PIN`.
  The card is read first: a locked card or PUK, or a new PIN outside the
  lengths the card declares, is refused without an attempt; refusals are named
  with the last-attempt warning. The window gains a **Card** menu with both
  operations in a dialog that checks the repeated PIN. Use cases
  `ChangeCardPIN` and `UnlockCard` (signing) and `ChangeCardPIN` (desktop).

- Firefox / NSS stores used in place: `sign --firefox` (the profile Firefox
  starts with, found in profiles.ini under the usual, Snap and Flatpak roots)
  and `sign --nss-db <dir>` (any NSS store, e.g. Chromium's `~/.pki/nssdb`)
  open the store through NSS's softokn3, read-only; the primary password is the
  PIN, with the same PIN rules as a card. `token --firefox/--nss-db` lists it;
  `token --firefox --json` prints an empty listing when there is no profile.
  The window's step 2 gains a **Firefox** source. A certificate authority's
  certificate is never chosen to sign.

- Desktop card source: step 2 offers **File** or **Card**. The card's
  certificates are listed in full from `token --json` (no PIN), the signing one
  chosen, with the card and reader named; the PIN state (attempts failed, last
  attempt, locked, to be changed, keypad) is shown before typing; a locked card
  or an empty PIN stops before the signer runs; a refused PIN is cleared and the
  cards read again; a batch stops at the first refusal. The PIN travels in
  `TREBARUNA_PIN`; the chosen certificate's fingerprint is remembered, never
  the PIN. New use case `ListCards`; `ErrLastAttempt` names a refusal that
  leaves one attempt.

- Card PIN safety: the card's PIN state is read before any login (locked, to
  be changed, not set: refused without an attempt); an empty PIN is never sent
  except to a keypad reader; a refused PIN (`ErrWrongPIN`, `ErrCardLocked`,
  `ErrPINExpired`, `ErrPINMissing`) stops a batch, whose remaining documents
  are reported as not tried; after a refusal the message says when the next
  mistake locks the card. `sign --card` signs with the card in the reader, and
  `--module` alone now means a card too. `token` prints the PIN state (`pin:`;
  `pin`, `pinpad` in `--json`) and, in `--json`, each certificate's holder,
  identifier, issuer name, locality and trusted-list standing (`--territory`).
  Two cards with the same label are told apart by the certificate.

- Card certificate choice: `sign --certificate <serial|fingerprint>` picks the
  certificate of a card and finds the reader that holds it without `--token`.
  Without it, the only certificate or the only one declaring non-repudiation
  signs (the DNIe signature certificate, not the authentication one); any doubt
  stops the signature and lists the certificates. `trebaruna token` prints the
  SHA-256 fingerprint and which certificate signs by default (`fingerprint`,
  `signs_by_default` in `--json`). The OpenSC module is found where each system
  installs it (Debian multiarch, Fedora, Arch, macOS, Windows), so `--module`
  is only needed for a vendor driver.

- Batch signing: `sign` takes several documents, signs each with the same
  settings in its own format (or a forced one), reports one result per
  document (`{"signed", "failed", "results", "network"}`) and exits 1 on a
  partial batch. The desktop signs batches from several dropped files or a
  folder (File → Sign a folder…).

- CAdES parallel signatures and counter-signatures: `sign --cosign` adds a
  SignerInfo over the same content, `sign --countersign leaves|all` nests
  counter-signatures (no contentType, RFC 5652 §11.4), at levels B and T; a
  detached `.p7s` is co-signed with `--content`. `verify` checks envelopes with
  several signatures node by node and reports each counter-signature under the
  signature it counter-signs; envelopes co-signed by OpenSSL are read too. The
  desktop offers co-sign, counter-sign and wrap when the document is an envelope.

- `trebaruna extract`: the document inside a `.p7m`, through nested envelopes,
  from DER, BER, PEM or Base64, never overwriting; the desktop Check tab offers
  it for `.p7m` files. `verify` now also reads PEM and Base64 `.p7m` files.

- CAdES detached signatures: `sign --format cades --detached` writes
  `<document>.p7s`; `verify` checks it against `--content`, or the document of
  the same name beside it, and reports unknown integrity, not tampering, when
  the document is missing. The desktop offers it as a fourth format.

- PAdES `--invisible`: a complete signature with an empty widget
  (`/Rect [0 0 0 0]`); the desktop offers it under More options for signed PDFs.

- Release: `make release-artifacts` builds the CLI for five platforms with a
  CycloneDX SBOM (`trebaruna about --sbom`, written by the binary itself) and
  SHA256SUMS; `make reproducible` proves two builds of a commit are identical
  (CI runs it); a tag workflow publishes the artefacts and the Linux desktop
  package, with minisign signing ready for when a key exists.

- `trebaruna about [--json]`: version, platform, source revision, card support
  and every linked module with its licence; the desktop About dialog shows the
  same. A test regenerates the licence table from the modules' licence files and
  fails on any unknown or non-free licence (today: 42 modules, all MIT, BSD,
  Apache-2.0 or ISC).

- Transparency: the receipt carries `document_sha256` and `signed_sha256`; the
  window shows the document's fingerprint before signing and warns if the
  signer reports a different one (the file changed after it was chosen).

- Transparency: every connection is recorded (ADR-0010). A new `transparency`
  slice hands out the only HTTP clients; it also wraps the default transport,
  so connections libraries open with their own client (pdfsign's timestamp and
  revocation requests) are recorded too, marked `via: library`. `sign`,
  `verify` and `timestamp` report `network` in JSON and list connections in
  human output; the window summarises them after signing and lists the session
  under Tools → Network activity. An architecture test fails if any code builds
  its own HTTP client.

- Desktop: user and password for timestamp authorities that require an
  account, such as Aruba's and InfoCert's. The user is remembered; the password
  is passed as `TREBARUNA_TSA_PASS`, never on the command line, and not stored.

- Desktop: a main menu (File, Signature, Tools, Help) with every action and
  shortcuts for the frequent ones; dropping a file on the window routes it
  (certificate, file to check, or document to sign); an About dialog with the
  version and licence.
- Desktop: the Check tab states the verdict as a word, a sentence and a
  colour, with one readable block per signature and an OCSP checkbox.
  "Signer not entitled to sign" is now red instead of grey; "no trusted list"
  is amber instead of red.

- Desktop: the signing form is three steps — document, certificate,
  signature — with one button that stays in reach. Files are shown as name
  and folder, wrapping, never cut. The certificate is read as soon as its
  passphrase is typed: holder, identifier, issuer, expiry and a plain verdict
  (qualified, trusted, no trusted list, expired, expiring soon). The format is
  offered from the document type with human labels; the level, reason and
  place live under "More options", the place prefilled from the certificate.
  The certificate path, level and TSA are remembered; the passphrase is not.
  After signing: Open, Folder and Check (which verifies the new file).
- CLI: `certificate --json` reports `issuer_name` and `locality`, and a wrong
  passphrase is reported as such instead of "not a certificate".
- Desktop: LT and LTA are offered and pass `--online-revocation`, which those
  levels require.

- Desktop: the seal is placed with the mouse. A click on the page centres it
  under the pointer, dragging moves it, the corner handle enlarges it, and the
  arrow keys nudge it. The page and the pointer share one `DisplayFit`, which
  fixes the old overlay drifting away from the cursor (it was drawn at a fixed
  scale of 1.0 over a page scaled to fit).
- Desktop: the seal preview is drawn as the signer prints it (name, identifier,
  date, time, accent rule), with the same line breaks. Its frame turns amber
  when it covers text.
- Desktop: page navigation shows "Page N of M" above the page; the seal goes on
  the page shown. "Find free space" cycles through the empty areas.
- Desktop: screenshot harness (`TREBARUNA_SCREENSHOTS=dir go test -tags gui`)
  and interaction tests for the page canvas, run in CI.

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

- Card signatures go through an own PKCS#11 session over `miekg/pkcs11`
  instead of `crypto11` (ADR-0018): module parameters for software stores,
  no PIN sent to keypad readers, issuers held by the token added to the chain;
  three dependencies fewer. The licence table generator formats its output.

- Desktop packages (`install-desktop`, `package-desktop`, the macOS bundle)
  ship the CLI built with cgo, so the window can sign with cards (ADR-0016);
  CI checks that the installed CLI reports PKCS#11 support.
- Trust: the list downloaders moved from the application layer to
  `trust/infrastructure` (`WebLOTL`, `WebList`).
- Desktop: the command-line adapter moved out of the application and domain
  layers. `SignFromDesktop` now depends on a `Signer` port and returns a typed
  `Receipt` read from `sign --json`, instead of predicting the output name and
  echoing raw JSON. A receipt whose file is missing is reported as a
  translatable problem rather than a Spanish sentence built in the use case.
- Desktop: the application layer is covered by unit tests (100 %), and the
  adapter by tests that run a stand-in command.

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

### Removed

- Desktop: the Requests tab; web-page requests open from Tools in their own
  window. The editable monospaced report box in the Check tab.
- Desktop: the raw JSON "Result" box, the free-text certificate and document
  path fields, and the `pades`/`bes` technical values in the selectors.
- Desktop: the page number and `x1,y1,x2,y2` box fields, and the "Show page"
  button. The page renders as soon as a PDF is chosen.

### Fixed

- The card session is closed after each signature. A process that signs more
  than once, such as the local API, kept every session open and went on seeing
  the readers as they were at its first signature.

- The default seal assumed A4: on a Letter page it sat away from the corner,
  and on a landscape page off the visible area. It is now placed on the page's
  real CropBox/MediaBox, inherited from the page tree when needed.
- XAdES with ECDSA keys: the signer wrote the SignatureValue as an ASN.1
  SEQUENCE and the verifier (goxmldsig, through `x509.CheckSignature`) read only
  that form. XML-DSig requires r||s (RFC 6931). Our signatures were refused by
  other verifiers, and a correct ECDSA signature from another producer was
  reported as **tampered**. The signer now writes r||s; the verifier accepts
  r||s and still accepts the old form, so files already issued keep verifying.
  RSA signatures were not affected.
- XAdES signatures lacked `xades:DataObjectFormat`, which the XAdES baseline
  (EN 319 132-1, B-B) asks for. It now declares `text/xml` for enveloped
  signatures and `application/octet-stream` with base64 encoding for
  enveloping ones, bound to the document reference. Checked with signxml.
- PDF signatures carried `/Name (signer)` — or `handler`, or `api`, depending on
  the entry point — and the JSON receipt reported the same placeholder. A signer
  nobody named now takes the holder printed on the certificate, as other signing
  tools do; `--name` still overrides it.
- PKCS#12 files exported by Firefox or Thunderbird (NSS) were refused as "not a
  certificate" even with the right passphrase: they are BER with indefinite
  lengths and Go's PKCS#12 library reads DER only. A new `keybundle` package
  falls back to its own reader for BER files: PBES2 (AES, PBKDF2-HMAC-SHA1/256/
  384/512), legacy 3DES with the PKCS#12 KDF, and the integrity MAC checked on
  the bytes as written. Every earlier version failed on these files too, only
  later, at signing time.
- The PDF seal never carried its design: every line printed pure black and the
  blue accent rule was missing. With pdfsign v1.0.0, `Position()` commits a text
  element, so the colour set after it was dropped; and `DrawRect()` registers a
  type its renderer does not draw. Colours are now set before the position and
  the rule is drawn as a thick line. Checked by rendering a signed PDF with
  poppler; `pdfsig` still reports the signature valid.
- The PDF seal printed the identifier and the date on top of the second line
  of a name that wrapped (any long name: "MARIA DEL CARMEN LOPEZ GARCIA
  MARTINEZ" overprinted "MARTINEZ"). The details now start below the last name
  line; a layout test checks that no line overprints another.
- The verification tab showed an empty heading, hint and button in every
  language: four catalogue entries had never been written. The catalogue test
  now walks every string field by reflection instead of a hand-kept list, which
  is how the gap was found.
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

### Security

- A wrong card PIN could sign while another signature of the same process
  held a logged-in session (the local API serving two requests, for
  instance): PKCS#11 logins belong to the whole process, the second login
  answered "already logged in" and that answer was taken as success. Card
  sessions now run one at a time per process, and a leftover login is logged
  out so the card checks every PIN.

- The desktop app no longer passes the certificate passphrase as `--pass`,
  where every local user could read it in the process list. The CLI accepts
  `TREBARUNA_PASSPHRASE`, `TREBARUNA_PIN` and `TREBARUNA_TSA_PASS` when the
  matching flag is absent (`sign`, `certificate`, `timestamp`, `token`,
  `handler`); an explicit flag still wins.

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

## [0.1.0-unstable] - 2026-11-02

First slice: CLI signing CAdES, PAdES and XAdES.
