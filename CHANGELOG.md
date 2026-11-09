# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Remote signing through the Cloud Signature Consortium API v2
  (ADR-0014): `sign --csc https://…/csc/v2 [--credential id]`.
  - The access token (`TREBARUNA_CSC_TOKEN`), or user and password for
    `auth/login`, and the PIN and OTP come from the environment.
  - An explicit credential is authorised for each hash before it is signed;
    an implicit one is not.
  - The combined signature OID is used unless the credential lists only the
    key's algorithm; ECDSA `r||s` answers become DER.
  - Every format and level signs through it.
  - The receipt says the key is remote and names the provider
    (`key_source`, `remote_service` in JSON); the connections are recorded
    as `remote-signing`, and no secret is printed.
  - Tested against a CSC service in tests/support/csc (RSA under a CA with a
    PIN and v2 descriptions; ECDSA implicit with v1 descriptions and raw
    signatures). Its CAdES verifies in OpenSSL against the CA, its PAdES in
    pdfsig. A wrong or missing PIN, a wrong token, an ambiguous credential,
    a missing token and plain HTTP to another host each fail with their
    reason.

- Check tab:
  - signatures as a tree: each counter-signature indented under the
    signature it signs (SignatureTree in the desktop domain: report order
    kept, a missing parent or a loop at the top);
  - a container signature lists the files it covers, and the files no
    signature covers are named;
  - extraction from time-stamped data (`.tsd`), and from ASiC containers
    into a folder beside them;
  - **Save report…** writes the verification as a PDF in the window's
    language and opens it.
  - New strings in Spanish, Italian and English; a screenshot of a
    counter-signed container checked by eye.

- `verify --report <file>.md|.html|.pdf` writes the verification as a
  document to keep or send.
  - It holds the file and its SHA-256, the verdict, every signature
    (signer, issuer, certificate validity, signing time, format, integrity,
    trust, each finding in the `--lang` language), the connections made and
    the version. The three formats are built from one content model.
  - The PDF is written by trebaruna: Helvetica with WinAnsi encoding, A4,
    page footers. The HTML is one well-formed page, with no scripts and no
    external resources.
  - Certificate text is escaped in each format; the home directory reads
    as `~`.
  - Judged with qpdf --check, pdfinfo, pdftotext (accents, parentheses and
    the footer across pages) and an XML parser for the HTML.

- ASiC-E signed in one step: `sign a b c --asic e [--out x.asice]` puts
  every document under one signature.
  - XAdES and XMLDSig: one detached signature with a reference and a
    DataObjectFormat per document, inside `asic:XAdESSignatures`.
  - CAdES: a detached signature over `META-INF/ASiCManifest.xml`, which
    names the signature and lists each document with its media type and
    SHA-256 digest.
  - Documents are stored by name; two with the same name are refused.
  - Checked with OpenSSL (the signature over the manifest, the manifest's
    digests recomputed), xmlsec1 1.3.9 and Java 25 (the three references,
    a name with spaces included), and trebaruna's ASiC verifier, which
    catches a changed document inside.

- ASiC-S signed in one step.
  - `sign --asic s` writes `<document>.asics`: the document and its
    detached signature, `META-INF/signature.p7s` (CAdES) or
    `META-INF/signatures.xml` (XAdES, XMLDSig).
  - The XML signature is written inside `asic:XAdESSignatures`, whose
    namespace is part of what it signs, so it cannot be added afterwards.
  - afirma:// `CAdES-ASiC-S` and `XAdES-ASiC-S` answer with the container,
    the data named `asicsFilename` or `dataobject.<extension>` (sniffed),
    as AutoFirma does.
  - The parts were checked with OpenSSL, xmlsec1 1.3.9 and Java 25, and the
    containers with trebaruna's ASiC verifier.

### Changed

- `asic` packs an ASiC-S as ETSI EN 319 162-1 lays it out: the signature
  under `META-INF` (it went to the root), `.asics` by default (it was
  `.asice`). A `.p7m`, an XML signature or ASiC-E are refused, with the
  `sign --asic` command that makes them.

- `verify` reads ASiC containers (`.asics`, `.asice`, `.scs`, `.sce`; ETSI
  EN 319 162-1).
  - The container is unpacked into a private directory. Entries whose
    names leave it, entries over 512 MiB, and ZIPs whose mimetype is not
    ASiC are refused.
  - Each signature under `META-INF` gets a report:
    - CAdES `signature*.p7s` over the one document of an ASiC-S, or over the
      `ASiCManifest` that names it, whose digests must match the files;
    - XAdES `signatures*.xml` with its references resolved from the
      container's root.
  - New findings: `container.covers` lists the files a signature covers;
    `container.unsigned_files` (warn) names the files no signature covers.
  - Judged against containers built with zip, OpenSSL and xmlsec1
    (tests/verification/asic/testdata/PROVENANCE.md). A changed or missing
    file, an added file, a missing manifest, an entry outside the
    container, an OpenDocument ZIP and a container without signatures are
    each told apart.
  - `signature.unverifiable` gets its Spanish and Italian text, missing
    since it was added.

- Plain XMLDSig.
  - `sign --format xmldsig`, and afirma:// `XMLDSig`, `XMLDSig Enveloped`,
    `XMLDSig Enveloping`, `XMLDSig Detached` (enveloping by default, as
    AutoFirma; Detached is the AFIRMA layout).
  - The XAdES layouts without signed properties: one reference, no
    QualifyingProperties. Level B only; a policy is refused (SAF_23 on a
    page), roles are left out on pages as AutoFirma does.
  - `verify` reports such a signature as XMLDSig.
  - Checked with xmlsec1 1.3.9 and Java 25.

- XAdES detached: `sign --format xades --detached` writes
  `<document>.xsig` beside the untouched document.
  - The reference names the file (escaped) and digests its bytes.
  - `verify` reads the file of that name in the signature's directory, a
    plain name only, never fetched. `--content` names another, and reports
    `content.detached`, or `content.missing` (unknown) without it.
  - Every level works; the archive timestamp covers the external document.
- XAdES enveloping of any file: XML travels as XML in the `ds:Object`, other
  files in Base64 with the Base64 transform and their sniffed media type, as
  AutoFirma does.
- afirma:// "XAdES Detached" is AutoFirma's layout: a new document whose
  `AFIRMA` root holds `CONTENT` (XML as XML, other data in Base64) and the
  signature. `expPolicy=FirmaAGE` with XAdES, detached as AutoFirma forces
  it, now signs.
- Judged with xmlsec1 1.3.9 and Java 25's XML-Signature on all four
  layouts, a detached file whose name has spaces included.

### Changed

- afirma:// `format=XAdES` with no variant is enveloping, AutoFirma's
  default (`XAdESSigner`); it was enveloped.
- An enveloping XAdES of XML carries it as XML (`MimeType="text/xml"`, C14N
  reference) instead of Base64.

### Fixed

- The XAdES-A archive timestamp covers the signed document. Its input
  skipped the enveloped document reference (`URI=""`), so the token covered
  the signature's objects but not the document, and no other validator could
  reproduce its imprint. Every SignedInfo reference is now processed as
  XML-Signature processes it (EN 319 132-1, 5.5.2.2), by the code that
  computes the digests. A test rebuilds the input from the file, step by
  step, and compares it with the token's imprint.

- A second XAdES on a signed XML no longer breaks the first.
  - The enveloped reference only excluded its own signature, so the next
    signature added to the root changed what the first one signed.
  - Each enveloped signature now leaves every signature out, with the
    XPath filter `not(ancestor-or-self::ds:Signature)` as AutoFirma writes
    it. FacturaE keeps AutoFirma's transforms, without the filter.
  - Checked with xmlsec1 1.3.9 and Java 25 on both signatures of a
    twice-signed FatturaPA.

- XML verification reads AutoFirma's enveloped signatures and every
  signature of a document.
  - AutoFirma writes the XPath filter after C14N, on the canonical octets.
    That read as unverifiable; the octets are now read back into nodes and
    filtered, as XML-Signature does.
  - A co-signed XML reported its first signature only, vouching for the
    others unseen. Each signature gets its own report now.
  - Judged against xmlsec1 1.3.9 fixtures: AutoFirma's order, and a document
    signed twice (RSA, then ECDSA) where both signatures hold.

- XAdES enveloped keeps what surrounds the root. The signed file was
  rebuilt from the root element alone, so the processing instructions and
  comments outside it were dropped: a FatturaPA lost its
  `<?xml-stylesheet?>`. They stay now.
  - The document reference digests the document node, those instructions
    included, as C14N requires. The signer computes every DigestValue with
    the verifier's own dereferencing code (`xmldsig.ReferenceData`).
  - A document that starts with `<?xml-stylesheet` still gets an XML
    declaration (it was mistaken for one).
  - Each signature names its elements with Ids of its own
    (`trebaruna-signature-<random>`…). With the fixed Ids, signing a signed
    XML again made the new SignedProperties reference digest the old
    signature's properties.
  - Verified with xmlsec1 1.3.9 and Java 25's XML-Signature. signxml
    canonicalises only the root and calls such a file modified
    (docs/signing.md).

- XML signatures are verified completely. The verifier, built on goxmldsig,
  checked only the reference to the document element. As a result:
  - a change inside the signed properties (signing time, policy, role,
    signing certificate) went unnoticed;
  - enveloping signatures, trebaruna's own among them, read as broken;
  - the XPath filter AutoFirma writes (`not(ancestor-or-self::ds:Signature)`)
    made a correct signature read as broken.

  Every reference is now dereferenced (`""`, `#id`, a file), transformed
  (enveloped signature, that XPath filter, Base64, C14N 1.0, 1.1 and
  exclusive) and digested, and the value over `SignedInfo` is checked with
  RSA (SHA-1 to SHA-512) or ECDSA (r‖s or ASN.1). `URI=""` digests the
  document node, the processing instructions outside the root included, as
  xmlsec1 does. Two elements carrying the signed Id are refused.

  What trebaruna cannot evaluate is reported as `signature.unverifiable`
  (unknown), and a detached reference without its document as
  `content.missing`, not as broken.

  Judged against signatures made by signxml 5.2.0 and xmlsec1 1.3.9, each
  verified with xmlsec1 first (tests/signing/xmldsig/testdata).

### Added

- Signature policies (EPES): `sign --policy age|age18|facturae|facturae30`
  declares AutoFirma 1.9's AGE and FacturaE policies with its digests, and
  `--policy-id`, `--policy-hash`, `--policy-hash-alg`, `--policy-qualifier`
  any other (the digest's length must match its algorithm; nothing is
  downloaded). CAdES carries the `sigPolicyId` signed attribute, in new and
  added signatures; XAdES carries `SignaturePolicyIdentifier` after
  `SigningCertificateV2`, an OID as `urn:oid:` qualified `OIDAsURN`, a URL as
  it is. PAdES refuses a policy until its signed attributes can be written.
  `--role` claims a role in XAdES (`SignerRoleV2`). FacturaE invoices: a
  FacturaE policy signs only unsigned `Facturae` documents, XAdES enveloped,
  with role `emisor` by default and only the policy's roles. afirma:// pages
  get the same: `expPolicy` (FirmaAGE, FirmaAGE18) expanded as AutoFirma
  does, `policyIdentifier` with its digest (`SAF_23` without one),
  `format=FacturaE` and `auto` on an invoice (a signed one is refused with
  `SAF_38`, not signed again as plain XAdES), `signerClaimedRoles` (several
  separated by `|`). Verified with openssl (`cms -verify -cades`,
  `cms -print`) and signxml's XAdES verifier, which checks the policy digest.

- afirma:// handler registration: the desktop entry declares
  `x-scheme-handler/afirma` and the macOS bundle the `afirma` scheme, so
  trebaruna is offered for AutoFirma's links without taking them over;
  `make afirma-default` / `make afirma-autofirma` switch this user's default.
  docs/web-pages.md explains the Firefox preference AutoFirma's package sets,
  which bypasses the system choice. No browser preference is installed.

- afirma:// approval window: `trebaruna-desktop afirma://…` opens a window
  with the request in full (operation, site, the page's own name, data or its
  address, batch documents, filters, translated warnings), the certificate
  chosen as in the Sign tab (card by default, Firefox, file), and Sign and
  send / Decline (closing declines). It drives `trebaruna afirma
  --interactive`: JSON proposal lines out, the decision with its secrets in
  through stdin, `retry` when the page refuses the certificate. The chosen
  certificate must pass the page's filters (up to three choices, then
  SAF_19), for every approver. `cli.RunIO` takes the standard input.

- afirma:// batches: JSON and XML batch definitions signed through the site's
  pre- and post-signers (`json=`/`xml=` with `certs=`, the client signing each
  `PRE` into `PK1` and keeping `PRE` only when `NEED_PRE`, `tridata=` to the
  post-signer; documents the pre-signer reports as failed reach post-sign as
  results), answered `result[|cert]`; HTTP 400/4xx/5xx from the services map
  to SAF_03/26/27. Local batches (`localBatchProcess`) are signed item by item
  with `stoponerror`. The person sees every document of the batch first.

- afirma:// through the intermediate server: answers posted to the site's
  StorageService (`op=put&v=1_0`), ciphered element by element with the page's
  key — single DES-ECB with zero padding and `N.base64url` (the protocol's
  vector reproduced) or AES-256-CBC for autoscript 1.10's `cipher` — failures
  URL-encoded; `#WAIT` every 10 s while the person decides, never after the
  result; requests uploaded by the page fetched from the RetrieveService
  (`op=get`) and read from their XML (or JSON). `trebaruna afirma '<uri>'`
  shows the request and answers it, signing only with `--approve` and a key.

- AutoFirma protocol engine (new slice `afirma`, docs/afirma-protocol.md):
  afirma:// URIs read as AutoFirma 1.9 reads them (literal dispatch, query
  rules, tolerant Base64, the AutoFirma test for `dat`, Java properties),
  validated (session id, servlet URLs, versions, `mcv`, algorithms, formats)
  and answered (`cert|signature`, `CANCEL`, `SAF_NN` with AutoFirma's
  texts). Certificate filters (RFC 2254 on subject/issuer, `dnie:`, key usage,
  thumbprint, policy, SSCD…) with unknown conditions matching nothing. Use
  case `AnswerPage`: nothing is signed, downloaded or sent before a person
  approves, and the DES weakness is stated. Page signatures: CAdES implicit or
  explicit, co- and counter-signatures, PAdES invisible unless placed, XAdES
  enveloped/enveloping; policies, XAdES Detached, FacturaE, ASiC and
  precalculated digests are refused by name. The local WebSocket/socket
  channels are not offered (ADR-0013).

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

- A seal word wider than its line (a long identifier) was cut by bytes, so a
  word with accents could be split inside a character and print garbage. It is
  now cut between characters. The Helvetica metrics moved to a shared package
  (`signing/infrastructure/helvetica`) for the verification report.

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
