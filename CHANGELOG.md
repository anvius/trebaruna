# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `trebaruna recipients find <who> --ldap ldap://host/<base>` looks a
  person's certificate up in an LDAP directory, by e-mail address or name,
  says of each whether it can receive envelopes, and keeps the fit ones in
  the address book with `--save`, to encrypt for them with `--to saved:`.
  `ldaps://` checks the server against the system's roots. trebaruna's own
  LDAPv3 client binds anonymously and asks only for the certificate
  attributes; the connection is listed with the purpose `directory`, which
  connections other than HTTP can now be recorded under.

- `trebaruna update` and Help → Check for updates say whether a newer
  release is published, comparing this build with the release tags of the
  repository trebaruna is published in by Semantic Versioning's
  precedence, and where to get it. It runs only when asked, its connection
  is listed as `update-check`, and it downloads nothing; a build that does
  not know its version asks nothing.

- A text, spreadsheet or presentation (OpenDocument, Office Open XML, the
  older Office formats, RTF, plain text, CSV) can be signed as the PDF
  LibreOffice prints of it: `sign x.docx --to-pdf` writes
  `x_signed.pdf` in PAdES beside the document and nothing else, and the
  window offers "As a PDF, converted with LibreOffice". `trebaruna convert`
  writes the PDF alone, to read it before signing. LibreOffice runs headless
  with a profile created for the conversion and thrown away after, and is
  stopped after three minutes; without it the command says so.

- Signing with a Brainpool key on a card (brainpoolP256r1, P384r1 and
  P512r1, the curves of German health professionals' cards): the card's
  certificates are read with trebaruna's own parser, the chain the card
  holds is walked with each issuer's signature checked, a self-signed card
  is recognised, and the card signs ECDSA through PKCS#11. CAdES, PAdES
  (through trebaruna's own CMS, as the PDF library's does not know the
  curves), XAdES and its counter-signatures, and the Office and
  OpenDocument signatures write the value as each format asks; the
  safeguard that refuses a counter-signature which would break another
  signature now sees Brainpool signatures too. `trebaruna token` lists such
  certificates. Checked against SoftHSM with openssl, lxml and Python's
  cryptography, and trebaruna's verifier. A Brainpool key in a PKCS#12
  file or a PEM bundle is refused saying that such keys sign on a card,
  rather than with Go's "unsupported elliptic curve".

- A PDF signature field's seed values (`/SV`, ISO 32000-1 tables 234 and
  235) are honoured: the encoding is the first of the field's that
  trebaruna writes (`adbe.pkcs7.detached` when the form asks for it), and
  what the field requires (a reason from its list, a timestamp from its
  authority, SHA-256 among its digests, the signer's certificate, issuer,
  policy, holder's name or key usage) is met or the signature refused,
  saying what the form asks; certification signatures, other handlers,
  legal attestations and embedded revocation information are refused.

- A PDF signature field's lock (`/Lock`, ISO 32000-1 12.7.4.5) is recorded
  when the field is signed, as a FieldMDP reference over the catalogue
  with the lock's action, fields and PDF 2.0 permissions; earlier
  signatures' locks are respected: a field one of them locked is refused,
  and nothing is signed after one that allows no change (`/P 1`), in a
  field, with a seal or invisibly.

- ASiC containers are counter-signed: `sign expediente.asice --countersign
  leaves` (or `all`) adds CMS counter-signatures to each CAdES signature
  file and XAdES ones inside each signatures file, where they are, and
  writes `expediente_countersigned.asice`; at LTA a CAdES counter-signature's
  archive timestamp covers what its signature signs (the ASiC-S's document,
  or the `ASiCManifest` naming it in an ASiC-E). afirma:// `countersign`
  with `CAdES-ASiC-S` and `XAdES-ASiC-S` does the same (`target=tree` for
  all) instead of answering "not yet", and the window offers a
  counter-signature for a container and for a detached `.xsig`.

- Trusted lists read the authorities they publish with brainpool keys (the
  German list's health professionals' authorities) and use them as
  anchors; Go's parser dropped them. The lists' and the list of lists'
  signer certificates are read the same way.

- XML signatures (XAdES, XMLDSig) made with brainpool keys are read and
  checked: their certificates through trebaruna's own reading, the value
  (XML-Signature's r and s) with its brainpool ECDSA, the chain walked to
  an anchor. openssl signs the canonical SignedInfo with the brainpool key
  on the three curves (this system's xmlsec1 cannot load such a key): the
  signature verifies, a changed prescription is caught, the chain reaches
  the anchored authority and not an impostor.

- PAdES signatures made with brainpool keys are read and checked: the PDF
  library cannot read them and reported them as changed (a false
  "altered", which ADR-0005 forbids); trebaruna now checks them itself, as
  the detached CMS over the byte ranges they are. A PDF signed with
  openssl's brainpool envelopes on the three curves verifies, its chain
  reaches an anchored authority, and a changed page is caught.

- CAdES signatures made with brainpool keys (brainpoolP256r1, P384r1,
  P512r1; German health professionals' cards) are read and checked. Go has
  no such curves: trebaruna reads their certificates itself (Go reads the
  rest while the key is set aside, then the certificate gets its own bytes
  and key back), verifies ECDSA on them (RFC 5639 curves, FIPS 186-4
  verification, s and r below the order), and walks the chain to an
  anchor, checking each issuer's signature and that it may issue, as Go
  does. openssl makes keys, certificates and envelopes on the three
  curves: their signatures verify, an altered prescription or signature is
  caught, an impostor authority anchors nothing.

- PDF/A documents stay PDF/A when signed with a seal: the part their
  metadata claims is read, and the seal is set in the Go fonts, embedded
  whole as TrueType with the widths read from the font program (ISO
  19005-1, 6.3.4 and 6.3.6), instead of Helvetica; in PDF/A-1 a rubric's
  transparency is painted onto white (no soft mask, 6.4). Other documents
  keep the lighter seal. veraPDF 1.30 passes Ghostscript's PDF/A-1b and
  PDF/A-2b files signed with a seal and a rubric; before, both failed on
  the fonts and PDF/A-1 on the mask.

- Window: a PDF that opens only with a password asks for it under the
  document (detected by opening it, so one that only restricts
  permissions asks nothing); it travels to the signer in its environment
  and is forgotten with the document. The page is not previewed, since
  that would put the password on pdftoppm's command line.

- Signing encrypted PDFs (RC4, AES-128, AES-256): the password, user or
  owner, comes from TREBARUNA_PDF_PASSWORD (never a flag) or afirma://
  `ownerPassword`/`userPassword`; a document that only restricts
  permissions needs none. Invisible signatures go through the PDF
  library's encrypted writer; trebaruna's own writer (seals, fields,
  policies) now encrypts every new string and stream with its object's
  key, leaves the signature's /Contents clear and keeps the document's
  /Encrypt. The author's permissions are honoured (neither form filling
  nor annotations: refused); LT and LTA are refused on encrypted files.
  `verify` opens them with the same variable. Judges: qpdf makes AES-256
  R6, AES-128 R4 and RC4-128 files; pdfsig verifies each signature with
  the password, qpdf --check finds the files sound, the /ByteRange gap is
  exactly /Contents, and after qpdf --decrypt the signature's strings
  read as written.

- A recipients' address book for `.p7e` envelopes: `trebaruna recipients
  list|add|remove` and `encrypt --to saved:<fingerprint start | holder>`.
  Certificates are kept as `<SHA-256>.pem` in a private directory (0700,
  files 0600), only those that can receive envelopes now; a name two
  certificates share is refused. The envelopes window lists the saved
  recipients with the date each serves until (an expired one marked),
  adds one with a click, forgets one, and keeps the recipients of an
  envelope just made when its box stays ticked. openssl opens an envelope
  made for a saved recipient. The encryption use cases are now fully
  covered by tests.

- Changing a card's PUK: `trebaruna-token pin change-puk` ($TREBARUNA_PUK,
  $TREBARUNA_NEW_PUK) and the window's Card → Change the PUK…. A security
  officer login with the current PUK, then C_SetPIN; a locked PUK, or a
  new one outside the card's limits, is refused without an attempt, and a
  wrong one is named with what the card says of the next try. Checked
  against SoftHSM (whose security officer PIN plays the PUK): the new PUK
  unlocks, the old one is refused; the token suite (now 44 tests) runs
  against an extracted SoftHSM.

- Window: ASiC containers, FacturaE invoices and declared policies. Any
  document can go in an ASiC-S container (`.asics`, with a CAdES
  signature); a batch can go in one ASiC-E container under one XAdES
  signature, in one command. A FacturaE invoice is recognised by its root
  and offered as an invoice first: signed inside with FacturaE's policy
  (3.1 or 3.0) and the role the person chooses (issuer, recipient, third
  party). More options offers the policy a signature declares (AGE 1.9 for
  PDF; AGE 1.9 or 1.8 for CMS and XML). Six languages; a policy that does
  not fit the format, or an invoice without its policy or role, is said
  before anything runs.

- afirma:// `visibleSignature=want|optional`: when a page asks for a
  visible seal without fixing its place, the approval window shows the PDF
  with the main window's seal canvas (drag, draw, find free space, turn
  pages) and the box becomes AutoFirma's position parameters; an optional
  seal can be unticked. The window works on a private copy of the PDF
  (0600, in a 0700 directory), removed once it has decided; a PDF the
  person picks is shown instead when the page sends none; one fetched only
  after approval is signed invisibly, and the approval says so.

- afirma:// XAdES Externally Detached and `useManifest`: an XML signature
  over documents that stay on the site, named by address and digest (`uri`
  with the data as its digest, or `uri1`/`md1`/`mimeType1`… for a
  manifest), the references in SignedInfo or, with `useManifest`, in a
  `ds:Manifest` the signature references once, as AutoFirma writes them.
  The digests' algorithm follows AutoFirma (precalculatedHashAlgorithm,
  else referencesDigestMethod, else SHA-512); each length is checked and
  SHA-1 refused; the approval lists every address and digest, in the
  window's six languages. xmlsec1 verifies both kinds with the documents
  mapped to their addresses, and catches a changed document. XAdES
  signatures in general can now reference documents by a digest given,
  with SHA-256, SHA-384 or SHA-512.

- afirma:// `sticky` and `resetsticky`: within one process, a WebSocket
  session, the key approved for a sticky request is kept in memory (with
  its PIN or passphrase) and the window offers it, ticked, at the page's
  next sticky request: the person need not choose it again, but still
  approves every request, and the page's filters still apply.
  `resetsticky`, or the session ending, forgets it. The holder's name
  wraps in the window.

- afirma:// `CAdES-ASiC-S-tri` and `XAdES-ASiC-S-tri`: the ASiC-S
  container made through the site's server, which receives the format as
  AutoFirma's ASiC triphase signers send it (`CAdES-ASiC-S`,
  `XAdES-ASiC-S`); co- and counter-signatures are refused, as AutoFirma
  refuses them.

- afirma:// `precalculatedHashAlgorithm`: a page that sends the document's
  digest instead of the document gets a detached CAdES signature over it,
  as AutoFirma makes it. The digest's length is checked, its algorithm must
  be the signature algorithm's (SHA-256, SHA-384 or SHA-512; SHA-1 is
  refused), and the approval shows the digest in hex so the person can
  compare it with the document's. CMS signatures can now use SHA-384 and
  SHA-512 throughout, not only SHA-256.

- afirma:// bare signatures, `NONE` and `NONEtri` (AutoFirma's
  AOPkcs1Signer): the page's bytes signed as they are, PKCS#1 v1.5 for RSA
  and ASN.1 for ECDSA, checked against the certificate before the page
  gets them. The approval says, in the window's six languages, that a bare
  signature records nothing of what it signs. `NONEtri` goes through the
  site's server, whose pre-signature for this format is the document
  itself: trebaruna signs only when it is exactly the document shown, and
  refuses before signing otherwise.

- afirma:// certificate filters `ssl:<serial>` and `qualified:<serial>`,
  as AutoFirma's SSLFilter and QualifiedCertificatesFilter: the page names
  a certificate, usually the identity card's authentication certificate
  the person logged in with, and the card's signing certificate is the one
  accepted (same holder serial number and expiry date; for `qualified:`
  also the same issuer). They look at the other certificates of the chosen
  key's store; until now they matched nothing.

- afirma:// pages that use AutoFirma's WebSocket channel work (D5;
  ADR-0019, proposed, opt-in): `afirma://websocket?ports=…&v=…&idsession=…`
  starts a WebSocket server, trebaruna's own RFC 6455 implementation, on
  the first free port of the page's list, on 127.0.0.1 alone, over TLS with
  the local channel's certificate. Protocols 3, 4 (session id checked on
  every message, SAF_46) and 4.1 (`#wait`, `getresult`); each operation runs
  as from the intermediate server, approved by the person, its answer sent
  back on the socket; the channel ends when the page's connection does (a
  connection that sends nothing for the session holds nothing). The
  approval window shows where it waits, each request in turn, and offers
  to install the certificate when it is missing; Tools → Local channel
  for sites installs or removes it. Checked with headless Chromium
  trusting only the installed root: the echo and a CAdES signature come
  back and openssl verifies it; without the root the connection fails.

- `trebaruna afirma local-tls install|status|remove`: the certificate the
  afirma:// WebSocket channel will serve on 127.0.0.1 (ADR-0019, proposed).
  Its root is made per user, signs that certificate once and its key is
  destroyed, never written; its critical name constraints permit only
  127.0.0.1 and localhost. Installing it in the user's NSS stores (Firefox
  profiles, ~/.pki/nssdb) is explicit and `remove` undoes it; the system's
  stores are never touched.

- Approving a three-phase afirma:// signature ("…tri") names the site's
  server that prepares and assembles it, and says that what is signed is
  what that server computes, which trebaruna cannot show: the person
  approved an id without knowing where it went.

- afirma:// pages co-sign ASiC-S containers: a `cosign` with
  `CAdES-ASiC-S` or `XAdES-ASiC-S` takes the container and answers it with
  one more signature of the kind it holds, as AutoFirma does. The
  container co-signature is now a use case of its own, CosignContainer,
  shared by signing a file and answering a page. A counter-signature of a
  container is refused as not supported yet.

- The window signs with a remote service: *Remote service* in step 2 takes
  the service's address and a user and password, or the client id of an
  OAuth2 sign-in in the browser, and an optional one-time code; *Find
  credentials* lists the account's credentials as a card's certificates
  (holder, issuer's standing, which provider keeps it) and the PIN is typed
  when the credential asks. Address, user and client id are remembered;
  secrets travel in the command's environment. `trebaruna token --csc`
  lists a service's credentials, each with its `credential` id, in the
  cards' JSON. The four key sources are listed one under another: side by
  side they widened the form at the page's expense. A credential whose
  service address is cleared says so.

- Remote signing through a provider's OAuth2 server (CSC's
  authorization-code flow): `sign --csc … --csc-client <id>` signs the
  person in, or has each signature of an `oauth2code` credential
  authorised, in their own browser. trebaruna asks `info` for the server,
  opens the page (`$BROWSER` or the system's opener, the address also on
  standard error), waits up to five minutes for the browser to come back
  to a loopback address, checks the state and exchanges the code with
  PKCE (S256); a credential-scoped token stands in for the activation data
  in signatures/signHash. `--csc-redirect` takes the address a provider
  registered (on this computer only); `TREBARUNA_CSC_CLIENT_SECRET` a
  confidential client's secret. oauth2code credentials were refused.

- The window encrypts and opens `.p7e` envelopes, in a window of its own
  from the File menu (*Encrypt for others…*, *Open an encrypted
  envelope…*). Encrypting lists each recipient by the holder's name read
  from the certificate added, refuses a file that is no certificate, and
  writes `<document>.p7e`; opening uses the key chosen in step 2 of the
  Sign tab (file, card or Firefox store), which the window names and
  follows, and offers to choose one when there is none; a card's refusal
  is explained as when signing. A `.p7e` dropped on the window or opened
  from a file manager goes there; the launcher offers trebaruna for
  `application/pkcs7-mime`. It drives `trebaruna encrypt` and
  `trebaruna decrypt`, passphrase and PIN in the environment.

- The Flatpak signs with smart cards. The runtime has no PC/SC, so it
  carries OpenSC 0.27.1 and the PC/SC client library of pcsc-lite 2.5.3
  (the tarball's signature by its maintainer checked), and reaches the
  system's pcscd through `--socket=pcsc`; trebaruna looks for OpenSC in
  /app/lib after the system's places. The runtime moves to freedesktop
  26.08 (24.08 is past its support), in the CI image too. The build script
  uses Flathub's flatpak-builder when the system has none, without
  rofiles-fuse, and clears a failed build's directory before vendoring.

- The window follows the desktop's light or dark preference: a light
  palette (pale desk, white fields, the teal and the signal colours
  darkened) with the same WCAG 2.2 AA contrast as the dark one, checked by
  the same test; `FYNE_THEME` overrides it. The page preview lies on a desk
  colour of its own, darker than the paper in both. Chosen when the window
  opens; colours the theme leaves to Fyne come in the palette's variant.

- ASiC containers are co-signed (`sign x.asics|x.asice --cosign`), with
  the kind of signature they hold: an ASiC-S's CAdES signature in place,
  one more XAdES signature in its signatures file (every signature that
  verified must still verify, or nothing is written), and in an ASiC-E a
  new signature file over all its documents (a CAdES one over a new
  ASiCManifest, or a XAdES one). The container is read (asic.Read, with
  the same name and size limits as verification) and written again; the
  result is `<name>_cosigned.<ext>`.

- ASiC time-stamp tokens (ETSI EN 319 162-1): `timestamp <file> --asic`
  writes `<file>.asics` with the document and `META-INF/timestamp.tst` (the
  TimeStampToken); verify judges each `timestamp*.tst` of a container,
  against the one document of an ASiC-S or the ASiCManifest that names it
  (whose digests must still match the files), reporting the timestamp
  authority (format RFC 3161) with its certificate checked like a signer's.
  Containers holding only timestamps were refused.

- XAdES signatures declare where they were made: SignatureProductionPlaceV2
  (city, province, postal code, country) between the policy and the roles,
  from `--location` (the city) and from afirma:// pages
  (`signatureProductionCity`, `…Province`, `…PostalCode`, `…Country`), in
  new signatures and in counter-signatures. The afirma:// approval, in the
  terminal and in the window, shows the policy, the roles and the place the
  page asks the signature to declare, before anything is signed; messages
  in six languages.

- verify shows what a signature declares of itself: its signature policy
  (CAdES and PAdES signature-policy-identifier, XAdES
  SignaturePolicyIdentifier; AGE 1.9, AGE 1.8, FacturaE 3.1 and 3.0 by
  name), the roles its signer claims (XAdES SignerRole/V2) and its
  production place (XAdES SignatureProductionPlace/V2, a PDF's /Location):
  `policy`, `claimed_roles` and `production_place` in the JSON, rows in the
  text output, the reports and the window's Check tab, in the six
  languages. They are statements, not checked facts.

- afirma:// single signatures through the site's server: the `CAdEStri`,
  `XAdEStri`, `PAdEStri` and `FacturaEtri` formats (E.8) were refused.
  After the person approves, trebaruna posts `op=pre` to `serverUrl` (the
  document id, the chain, the algorithm, the properties but serverUrl and
  documentId), signs each pre-signature with the key, posts `op=post` with
  the session, and hands the page the signer's certificate and the id of
  the signature the server keeps. `ERR-…` answers are SAF_26 with the
  server's text.

- XAdES counter-signatures inside the document: `sign doc_signed.xml
  --countersign leaves|all` adds, in each chosen signature's
  UnsignedSignatureProperties, an xades:CounterSignature: a XAdES signature
  whose reference (type CountersignedSignature) is that signature's
  SignatureValue, given an Id when it had none. Levels B and T; plain
  XMLDSig signatures are skipped. The signatures that verified before must
  verify after, or nothing is written. afirma:// pages co-sign a signed XML
  (signed again, enveloped) and counter-sign it (`target` tree → all), where
  both were refused; `auto` recognises a signed XML. verify names each XML
  signature (XMLSignature #n when several), says what a counter-signature
  counter-signs, and no longer reads it as a partial signature.

- Signatures added to a CAdES envelope (co-signature, counter-signatures)
  take levels LT and LTA, refused until now. At LT the added SignerInfo
  carries its chain's revocation values (asked before signing, so a
  counter-signature's go in its own nested SignerInfo); at LTA an
  archive-time-stamp-v3 seals the parallel signature added, or each
  signature that took counter-signatures. A detached envelope's document
  (`--content`) now also reaches a counter-signature, whose archive
  timestamp seals it.

- A form's signature field from the window and from web pages. `trebaruna
  fields <pdf> [--json]` lists a PDF form's empty signature fields (name,
  page, box). The window reads it: a PDF with fields offers them under the
  formats, after "None: place the seal on the page"; a field chosen shows
  its page with the seal locked in its box (no handle, no keys, no page
  turning, no free-space search) and signs with `--field`; batches never
  offer fields. Messages in Spanish, Italian, English, Catalan, Galician
  and Basque. afirma:// pages name the field with AutoFirma's
  `signatureField` (the position keys then do not apply).

- PAdES signatures carry a signature policy (PAdES-EPES): `sign --policy`
  on a PDF, and afirma:// `expPolicy` (FirmaAGE) or `policyIdentifier` on
  a PAdES page, were refused. The PDF library cannot add the attribute, so
  trebaruna writes these signatures itself (pdffield.SignNew): a new field
  "Signature n" with one widget per seal, a widget kid each when several
  (or one empty widget when invisible), added to each page's /Annots (the
  page or its annotations array written again) and to the form's /Fields
  (a form created when the PDF has none), /SigFlags 3; its CMS envelope
  with signature-policy-identifier and no signing-time. With `--field` it
  goes in the form's field.

- `sign --field <name>` signs a PDF form in its empty signature field (by
  its fully qualified name), the seal drawn in the field's box, or none
  with `--invisible`; an unknown name is refused with the empty fields the
  form has. The PDF library always adds a field of its own, so trebaruna
  writes this signature itself (pdffield): an incremental update with the
  signature dictionary, the field's /V and /AP, the appearance (the seal
  as a form XObject: Helvetica in WinAnsi, the rubric as an image with its
  soft mask), /SigFlags 3, and cross-references of the file's kind (table
  or stream); its own CMS envelope (PAdES baseline, timestamped for T;
  LT/LTA added after). A field too small for a legible seal, encrypted
  documents and documents certified against any change are refused.

- CMS (CAdES) and PDF (PAdES) signatures made with RSASSA-PSS (RFC 4055,
  with its parameters) are verified: the CMS and PDF libraries do not
  implement it, and a valid PSS signature was reported as altered. A PDF
  signature the PDF library cannot check goes through the CAdES checks over
  its byte ranges (without the `/DSS` revocation data). Authorities whose
  key is published as id-RSASSA-PSS (D-TRUST CA 3-1 2016 and the German
  HBA authorities among the qualified ones) anchor chains: their keys are
  read where trust lists, envelopes and anchors are (`publickey.Complete`).
  An algorithm trebaruna does not implement is `signature.unverifiable`, no
  longer `signature.modified`, in CMS and PDF as in XML.

- XML signatures made with RSA-PSS (`sha1/224/256/384/512-rsa-MGF1` and
  `sha3-*-rsa-MGF1`, RFC 6931: MGF1 over the same digest, a salt as long as
  the digest) and with SHA-3 (digests `sha3-224/256/384/512`, ECDSA
  `ecdsa-sha3-*`, RFC 9231) are verified, in documents and in trusted
  lists, the algorithms xmlsec1 implements. An RSA key a certificate
  publishes as id-RSASSA-PSS (RFC 4055), which crypto/x509 leaves unread,
  is read (`publickey.Of`). The German trusted list, signed that way and
  refused until now, authenticates: 979 services, 93 qualified.

- Accessibility (plan G8), after a WCAG 2.2 AA review of the window
  (docs/accessibility.md):
  - + and − resize the seal from the keyboard, as the corner handle does
    with the mouse; the hint says so in every language.
  - The page arrows and the page have names for screen readers; the Windows
    and macOS windows are built with Fyne's accessibility tag (UI Automation,
    VoiceOver). Linux waits for Fyne.
  - The accent teal and the error red are slightly lighter, and field edges
    have their own colour, so text reaches 4.5:1 and control edges 3:1 on
    every surface, dialogs and buttons included.
  - Tests pin the contrasts, Tab reaching the page and the sign button, the
    keyboard resizing and the accessible names.

- Page preview without poppler (plan G7): when `pdftoppm` is not installed
  the window draws the page itself, in plain Go, instead of falling back to
  the default corner.
  - Text where the PDF puts it (simple fonts by their widths and encodings,
    composite fonts through their ToUnicode maps), in Go's typeface; lines,
    rectangles and fills in their colours; JPEG and Flate pictures (grey,
    RGB, CMYK, ICC, indexed) with their soft masks, others as grey boxes;
    forms; the appearances of form fields and earlier signatures. The
    invisible OCR layer of a scan is left out.
  - poppler stays first when installed; the line under the page says when
    the preview is trebaruna's sketch, in every language.
  - Compared by eye with pdftoppm on real documents (a cover with pictures,
    a dense page of a contract, a signed page with a rubric): the same
    layout, another typeface.

- CI (plan G6): the test suite on Windows and macOS; on Windows the window,
  the card CLI, the zip and the MSI (WiX 5); on Linux the .deb installed
  and removed for real, the AppImage (appimagetool 1.9.1 pinned by digest)
  run as the command line, and the Flatpak in Flathub's builder image. The
  release attaches the .deb and lists it in SHA256SUMS. Not run yet:
  nothing has been published since.

- Packages (plan G5):
  - `make package-deb`: a `.deb` with the window, the CLI that reads cards,
    the launcher and its URL handlers, the icons, an AppStream description
    and the licence; its dependencies are those dpkg-shlibdeps reads from
    the binaries plus the X11 and Wayland libraries GLFW opens at run time.
  - `make package-appimage`: an AppDir, packed into an AppImage when
    appimagetool is installed; run through a link named `trebaruna` it is
    the command line.
  - `make package-flatpak`: a Flatpak manifest under the window's id, with
    the Go toolchain as a checked archive and vendored modules; no cards in
    the sandbox yet.
  - A WiX installer for Windows, built by `package-desktop.sh windows` when
    wix is installed: per user, trebaruna:// links, AutoFirma's afirma://
    links only on request.
  - The .deb was built and checked here (dpkg-deb, apt, the extracted
    binaries, desktop-file-validate, appstreamcli); the Flatpak and the
    installer need tools this machine lacks.

- Catalan, Galician and Basque (plan G4): the window, the approval windows
  and the verification report (`verify --lang ca|gl|eu`, `TREBARUNA_LANG`,
  `$LANG`), Fyne's own widget strings, and the launcher's name and comment.
  - Tests fail on a missing string, a catalogue that repeats the Spanish,
    or a translation that loses or reorders a formatting verb, for every
    language.
  - The HTML report's `lang` names the language its text is in: an unknown
    locale gave Spanish text under `lang="en"`.

- A handwritten signature in the seal (ADR-0012): `sign --rubric firma.png`,
  afirma:// `signatureRubricImage`, and a rubric row in the desktop, which
  remembers it and previews it in the seal.
  - PNG (transparency kept) or JPEG, up to 4 MiB and 4096 pixels a side;
    anything else is refused when given.
  - Drawn left of the certificate data, at most half the width, its
    proportions kept; the data keep their size, and a box too narrow for
    both is refused. The default seal widens to 160x48 pt.
  - Greyscale and CMYK JPEGs are re-encoded as PNG: pdfsign would embed
    them as RGB and garble them.
  - Checked with pdfsig and pages rendered by pdftoppm.

- Office Open XML signatures (ADR-0015): `sign offerta.docx` (and `.xlsx`,
  `.pptx`, macro-enabled files, templates; `--format ooxml`) signs inside
  the file as Microsoft Office does.
  - One signature part under `_xmlsignatures`, Office's objects and XAdES
    properties; its Manifest covers every part but the document
    properties, the relationships through the RelationshipTransform.
  - A file with no signature yet gets its relationships written compactly,
    so Office and LibreOffice (whose libxmlsec reads the text between
    relationships) agree on the digest. A signed file keeps its bytes, and
    a new signature follows the form the earlier ones used.
  - `verify` reads OOXML files, Office's and LibreOffice's signatures
    included: every changed part is named, parts added later too, and
    LibreOffice's form of the relationships is told. An unsigned file reads
    as having no signatures.
  - afirma:// `OOXML` and `OOXML (Office Open XML)`. The desktop offers it
    first for Word, Excel and PowerPoint files, and the Check tab accepts
    them.
  - Judged with LibreOffice 26.2.6.3 through UNO: ours, two of ours, ours
    added to LibreOffice's and to Office 2010's are all valid; a changed
    part is not. xmlsec1 validates the XML signature; the transform matches
    seven files Office signed (Apache POI's test data).

- OpenDocument signatures (ADR-0015): `sign acta.odt` (and `.ods`, `.odp`,
  `.odg`, templates; `--format odf`) signs inside the file as LibreOffice
  does.
  - One XAdES signature in `META-INF/documentsignatures.xml` references every
    stream, `mimetype` and the manifest included; the XML ones are
    canonicalised by the manifest's rule.
  - The package is otherwise copied byte for byte. Signing a signed file adds
    a signature beside the earlier ones.
  - `verify` reads ODF files, LibreOffice's signatures included, and names
    streams added afterwards. An unsigned one reads as having no signatures.
  - afirma:// `ODF` and `ODF (Open Document Format)`. The desktop offers it
    first for OpenDocument files, and the Check tab accepts them.
  - Judged with LibreOffice 26.2.6.3 through UNO: our signature, two of
    ours, and ours added to one LibreOffice made are all valid; a changed
    content.xml is not. xmlsec1 1.3.9 and Java 25 agree.

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

- Versions are numbered as the commit history gives them: 0.103.0-unstable
  instead of the hand-kept 0.86.0-unstable, 17 minor versions apart since
  the first weeks. The AppStream releases and the versions the documents,
  ADRs and the `timestamp.legacy_form` finding mention moved by the same 17
  (0.38.2 is 0.55.2, 0.50.1 is 0.67.1). A packaging test derives the
  version from the history and fails when `VERSION` says otherwise. The
  releases below are renumbered the same way: 0.3.1 is 0.20.5 and 0.3.0 is
  0.20.3, their tags renamed to match; 0.1.0 and 0.2.0, both in the first
  commit, are its 0.0.0.

- The seal is laid out as marks (the rubric, the accent rule, the lines of
  text) apart from the PDF library that draws them, so trebaruna can draw
  the same seal in a signature field the library does not create. The
  appearance the library receives is unchanged.

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

- afirma:// `format=XAdES` with no variant is enveloping, AutoFirma's
  default (`XAdESSigner`); it was enveloped.

- An enveloping XAdES of XML carries it as XML (`MimeType="text/xml"`, C14N
  reference) instead of Base64.

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

- The Quit item Fyne adds at the end of the File menu is in the window's
  language: it read "Quit" in Italian, Catalan, Galician and Basque.

- The visible seal and the PDF report print the letters of Central and
  Eastern European names (Polish ł ż ś, Czech ř ě ů, Hungarian ő ű, Romanian
  ș ț, Baltic ā ė ū…), which came out as "?": WinAnsi lacks them, and
  trebaruna now puts them in the codes WinAnsi leaves free, named by their
  Adobe glyph names in the fonts' /Differences array (up to 36 per seal or
  report). The report's title travels as UTF-16 text. The PDF/A seal, in its
  embedded fonts, still prints "?" for them.

- A CAdES co-signature or counter-signature at LT carries the validation
  material of the authority behind the timestamp it brought (its chain and
  OCSP answers, in SignedData), as a new signature does since 0.104.3. Only
  the timestamps the added signature brings are looked into: the earlier
  signatures' authorities are not asked about, so one revoked since does
  not refuse the new signature.

- The long-term levels carry what EU DSS needs to rate them LT and LTA,
  which it did not before (it rated trebaruna's LT and LTA signatures at T):
  - the timestamp authority behind the signature timestamp now has its
    chain and an OCSP answer for each of its certificates carried with the
    signer's, in all three formats; a revoked authority certificate refuses
    the signature, one without a responder adds what it can;
  - XAdES-LT carries xades:CertificateValues with the certificates
    ds:KeyInfo leaves out, without which a validator not given the signer's
    authority found no chain;
  - CAdES-LT keeps its validation data where the baseline profile wants
    it: certificates in SignedData.certificates, OCSP answers in
    SignedData.crls as RFC 5940 OtherRevocationInfoFormat (SignedData
    version 5), instead of the revocation-values attribute, which DSS reads
    as the extended X-L form. Co-signatures and counter-signatures at LT put
    their signer's material there too.

- CAdES-LT revocation values follow RFC 5126: `ocspVals [1]` is a sequence
  of the responders' BasicOCSPResponses, each as the responder signed it.
  trebaruna wrapped every OCSP answer, whole, in an OCTET STRING; EU DSS
  (BouncyCastle) could not parse the attribute and found no revocation in
  the signature, so a CAdES-LT read as T and its chain as not conclusive.

- CAdES-LTA archive timestamps are accepted by EU DSS: the
  ats-hash-index-v3 now names its hash algorithm even when it is SHA-256.
  DSS takes that field as required in the v2 and v3 indexes and rebuilds the
  index with it before hashing, so every archive timestamp trebaruna wrote,
  which left SHA-256 out as the ASN.1 DEFAULT, read to DSS as sealing
  something else. Archive timestamps written that way still pass `verify`.

- Signing a PDF field whose lock covers other fields (`/Lock`) marks
  those fields read-only in the update, keeping the flags each had or
  inherited, so a reader no longer lets anyone fill them in after the
  signature; the lock was recorded but the fields stayed editable. A name
  in a lock now covers the fields under it too, for the read-only marks
  and for refusing to sign a field an earlier signature locked. A field
  written inside another object (ISO 32000-1 asks for a reference) was
  rewritten as that object, which would have overwritten the form: a
  locked one is left as it is and a signature field written so is refused.

- A PDF whose author certified it against any change (DocMDP permissions
  1) was refused only when signed in a field: an invisible signature, which
  the PDF library writes, went ahead and broke the certification. Every
  PAdES signature now refuses it, the encrypted documents' permissions
  checked at the same place.

- Counter-signing a timestamped XAdES signature broke its timestamp: the
  counter-signature names the signature's value by its `Id`, which
  trebaruna did not write, so one was added after the timestamp had sealed
  the value. Every XML signature trebaruna makes now carries
  `SignatureValue Id` from the start; a timestamped signature from
  elsewhere without one is refused instead of broken. xmlsec1 verifies the
  signatures, LibreOffice the ODF ones.

- `verify` read only the first archive timestamp of a XAdES signature: a
  renewed XAdES-A's later ones went unchecked, a false one included. Each
  is now checked. A XAdES signature was also searched into the
  counter-signatures nested in it: one without a timestamp, counter-signed
  at level T, was reported "timestamp invalid" with its counter-signature's
  token. A signature's signing time, timestamps and properties are now its
  own, and an archive timestamp's token is never taken for a signature
  timestamp.

- A detached XML signature (`.xsig`) could not be counter-signed: without
  `--format` it was read as a CMS envelope ("ber: truncated encoding"),
  with `--format xades` refused (".xsig cannot hold a xades signature").
  `.xsig` is XML: XAdES is inferred and accepted, and `sign acta.xsig
  --countersign leaves` writes `acta_countersigned.xsig`.

- `certificate` printed Spanish labels and an English trust note ("confianza
  self-signed — the certificate is its own issuer"). Its output now comes
  whole from the report's catalogue, in the language of `--lang` (new) or
  `LANG`, as `verify`'s; the trust verdict carries a stable code
  (`verdict_code` in the JSON, beside the English `verdict_note`) that the
  six languages translate. The guide's example of the output is the real one.

- ASiC containers wrote their `mimetype` entry with a data descriptor, its
  header's CRC and sizes zero: Java's `ZipInputStream`, as Java signing
  tools read a container, refused it ("only DEFLATED entries can have EXT
  descriptor"). The entry now carries its CRC and sizes, no descriptor and
  no extra field (EN 319 162-1, A.1). Every entry of a container, and the
  parts a signature adds to an ODF or OOXML package, was dated
  1980-00-00 (an MS-DOS date of zero); they carry the time written.

- Co-signing an ASiC reported `"format": "cades"` even when the container
  took a XAdES signature: the report now names the kind added. The media
  type of a document, in an ASiC-E manifest and in a XAdES
  `DataObjectFormat`, was sniffed from its bytes alone: an XML document
  without its declaration read as `text/plain`, an office document as
  `application/zip`. Its name's extension now decides when known, and XML
  is recognised without the declaration.

- `verify` named an XML counter-signature "XMLSignature #2", like a second
  signature of the document; it is now named after the one it signs
  ("XMLSignature › countersignature 1"), as CMS counter-signatures were.
  Inside an ASiC every signature of an entry took the entry's name alone,
  so the two of a co-signed `signatures.xml` read the same: each now keeps
  its own after the entry, and `countersigns` follows.

- A detached signature verified without its document (a `.p7s` or an
  `.xsig` alone) said "untrusted", the word for cryptography that holds
  under an unknown issuer, although no byte was compared. Its trust and
  the verdict are now "unknown" (exit 3 as before); the certificate
  findings still show. `content.detached` joins the list of finding codes
  in the verification guide.

- `verify`, for PDFs, named each signature after its signer in `field`;
  it now carries the form field's name ("Signature 1"), two signatures by
  one person keeping their own fields. The human output printed "! aviso
  del verificador" with no words: the PDF library's warning that repeats
  "the signing time is declared by the signer" is dropped, and any other
  shows its text. The reason a PDF signature gives is shown, and a signer
  that cannot be read says "unknown" instead of a blank. Times were local
  for PDFs and UTC for CMS and XML: the JSON is UTC everywhere, the human
  output and the reports the reader's local time.

- `sign` replaced an existing file at its output without a word, the
  previous signed file included, while `extract` and `decrypt` refused.
  It now refuses (exit 1, naming the file and `--force`), `--force`
  replaces it, and nothing replaces the document being signed. `extract`
  refusing to overwrite now exits 1, as an operation that failed, not 2
  (a usage error). The window names the output before signing, says when
  it replaces a file, and passes `--force`.

- With `--json`, a failure left nothing on stdout, only text on stderr:
  any command that fails without writing its own result now prints
  `{"error", "exit_code"}` on stdout, the reason it gives on stderr,
  without the usage text a wrong flag prints for a person.

- A signature with a seal, made by trebaruna's own PDF writer, wrote the
  signer's name, the reason and the place as UTF-8 bytes in PDF text
  strings, which readers take as PDFDocEncoding: "José García Núñez" read
  as "JosÃ© GarcÃ­a NÃºÃ±ez" (qpdf saw them as binary). They are now
  ASCII when they can be, UTF-16BE behind its byte order mark otherwise
  (ISO 32000-1, 7.9.2.2). Invisible signatures were already right. Found
  while testing brainpool PDF signatures.

- afirma:// pages asking for `FacturaEtri` or `Adobe PDF TriPhase` were
  answered SAF_06 (unknown format), though signing through the site's
  server was built for both families; and NONE's other names, `PKCS1` and
  `PKCS#1`, were unknown too. Every signature format name in AutoFirma's
  AOSignConstants is now read, except SOAP and the Externally Detached
  variants.

- Usage and key errors said what the person can act on: `verify`,
  `extract` and `certificate` without a document said "sign needs a
  document path"; a PKCS#12 file that did not open named a placeholder
  ("certificate holder") and not the cause. It now says whether no
  passphrase was given (and that it goes in $TREBARUNA_PASSPHRASE) or the
  one given does not open it. The help and the documentation no longer
  show passphrases on the command line in their examples.

- A PAdES-T whose timestamp authority is on no trusted list was reported
  as not timestamped, the claimed signing time shown instead: the PDF
  library drops a token whose authority it cannot chain to its roots.
  A token on a valid PDF signature is bound (the library checks its
  imprint before the signature), so it is now recorded as CAdES and XAdES
  record theirs: the time it proves, its authority, timestamp.bound and
  the evidence the trust list is weighed against (timestamp.accredited or
  timestamp.untrusted_authority). PDF timestamps were never weighed
  against the trust lists before.

- The default visible seal was drawn by the PDF library, which gives the
  standard fonts every glyph 500 units wide and writes UTF-8 into WinAnsi
  strings: "MARI O  ROSSI", "TINIT-… Â· 09/11/2026". Every signature with
  a seal is now written by trebaruna, whose appearance sets the text in
  Helvetica, WinAnsi encoded, with the fonts' own metrics, as signatures
  with a policy or in a form's field already were.

- A PDF changed under a document timestamp whose authority signed with
  RSA-PSS was reported unaltered. The PDF library cannot read such a token
  and stops before comparing its imprint with the document; trebaruna's
  own check then verified the token's signature over its TSTInfo and took
  that for the document. A document timestamp (its content a TSTInfo) is
  now checked as one: the token's signature, then its imprint against the
  bytes its /ByteRange covers, with the same code as ASiC timestamps.

- A PDF envelope carrying content of its own (adbe.pkcs7.sha1, or another
  document's envelope put in /Contents) is left to the PDF library's
  verdict: trebaruna's RSA-PSS fallback judged envelopes against their
  content, which for these is not the PDF.

- A PDF signature whose signature timestamp an authority signed with
  RSA-PSS was "unverifiable": the library stops at the token before
  checking the signature. Such a signature now gets the CAdES checks,
  timestamp included.

- A remote signature asked the CSC service for the credential twice
  (credentials/info, and the sign-in before it): once to show the signer,
  once to sign. A credential read is remembered for as long as one call
  may last (a minute), per service, credential and secrets, so a
  signature asks once; another credential is read again.

- Timestamp tokens an authority signed with RSA-PSS are read: the
  timestamp library's CMS code does not implement it, so a valid token was
  reported invalid (CAdES and XAdES signature timestamps, archive
  timestamps, ASiC timestamps). The token's SignerInfo is checked over its
  TSTInfo with trebaruna's CMS check, then the TSTInfo is read. Brainpool
  keys, which Go's certificate parser refuses, and PSS tokens inside PDF
  signatures the PDF library checks remain out of reach (docs/verification.md).

- CAdES-LTA's archive timestamp is an archive-time-stamp-v3 as ETSI EN
  319 122-1 defines it: the token covers the signed content's type and
  digest, the SignerInfo and an ats-hash-index-v3 of the certificates,
  revocation values and unsigned attribute values (5.5.2, 5.5.3), the index
  carried in the token, under id-aa-ets-archiveTimestampV3
  (0.4.0.1733.2.4). It covered the container's DER under the v2 OID
  (1.2.840.113549.1.9.16.2.48), which no validator could check, and nothing
  checked it: verify now recomputes it (timestamp.archival, or
  timestamp.archive_unbound when what it sealed changed or is gone). The
  signer and the verifier share cms.ArchiveTimeStampV3Input; the archive
  timestamp is added to one SignerInfo, not to every one.

- A PAdES B-LT signature added to a PDF signed before keys its /DSS /VRI
  entry to its own signature value: the first signature field's was taken,
  someone else's in a co-signed PDF or a form, so validators could not
  match the revocation data to the new signature. The latest signature is
  the one whose /ByteRange reaches furthest, nested fields included.

- Every HTTP request names the program (User-Agent `trebaruna`, no
  version): the Estonian trusted list answered Go's default one with 403,
  so Estonia was never synced. trust sync downloads the EU list of the
  lists once per run instead of once per territory (31 times, half a
  megabyte each); a failed download is tried again for the next territory.
  On 9 November 2026 a full sync authenticated all 31 lists.

- verify recomputes what a XAdES archive timestamp seals (EN 319 132-1
  5.5.2: the references, SignedInfo, SignatureValue, KeyInfo, the unsigned
  properties before it, the other objects, with its declared C14N) and
  compares the token's imprint: it was reported as present, never checked.
  One that seals something else is `timestamp.archive_unbound`. The signer
  and the verifier share the computation (`xmldsig.ArchiveTimeStampInput`).

- The visible seal keeps every line inside its right margin. Lines were
  wrapped to the box minus both paddings but drawn after the accent rule,
  3.2 pt further right, so a line that filled its width ran past the edge
  and the end of a name could be clipped.

- The local API (`trebaruna serve` and the `trebaruna://` handler) signs and
  verifies every format the command line does: it was wired with PAdES,
  CAdES and XAdES only, so ASiC containers, OpenDocument and Office Open
  XML files were refused or unreadable through it. The command line, the
  API and their tests now share one wiring (`cli.Signing`,
  `cli.Verification`).

- XAdES signature timestamps cover the canonical `ds:SignatureValue`.
  - EN 319 132-1 (5.4.1.3) has the token seal the element canonicalised
    where it stands, its inherited namespaces included. The signer sealed
    the element as written, and the verifier checked it the same way, so
    trebaruna's XAdES-T was refused by other validators and theirs read as
    a timestamp over "a different signature value".
  - Both now canonicalise in place, with the C14N the SignatureTimeStamp
    declares; the verifier finds SignatureValue under any prefix.
  - Files written before 0.55.2 still read as timestamped, with
    `timestamp.legacy_form` (warn) saying others will refuse them.
  - `openssl ts -verify` checks the token against the canonical bytes.

- XML is canonicalised with trebaruna's own C14N.
  - goxmldsig's canonicaliser sorted prefixed attributes by local name
    instead of namespace URI. LibreOffice's content.xml, or any element with
    `xml:lang` and `xsi:` attributes, came out in a different order from
    every other implementation: a signature over such XML did not verify
    elsewhere, and trebaruna misjudged other producers' signatures over it.
  - The new canonicaliser (C14N 1.0 and 1.1, exclusive with
    InclusiveNamespaces, with and without comments) handles the document
    node, subsets with their inherited namespaces and xml: attributes,
    `xmlns=""`, superfluous declarations, and attribute and text escaping.
  - It is used everywhere the signer and verifier canonicalise.
  - It matches libxml2 (xmllint --c14n, --c14n11, --exc-c14n) byte for byte
    on LibreOffice's XML and a corpus of namespace and escaping cases.

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

- An XML signature over part of a document left out of its unsigned
  parts anything inside an element that merely looked like another
  signature (`ds:Signature`), so content could hide there unreported.
  Another signature is left out only when it holds; a look-alike is named
  among the unsigned parts (content.partly_signed).

- A CMS signature over data that merely parses as a TSTInfo was read as a
  timestamp token: the timestamp library does not check the declared
  content type, nor did trebaruna's RSA-PSS fallback. A token must now
  declare id-ct-TSTInfo (RFC 3161, 2.4.2) wherever it is read: CAdES and
  XAdES signature timestamps, archive timestamps, ASiC and PDF timestamps.

- The EU list of the lists, the root every national list is
  authenticated against, was trusted on TLS alone, and `--lotl` accepted
  plain http. It is now used only when its own signature, over all of
  it, was made with a certificate the Official Journal announced (the
  six of notice C/2026/1944, embedded with their provenance), or with one
  a chain of pivot lists announced after that notice; a list that no
  longer names the notice is refused until trebaruna carries the newer
  one. `--lotl` takes https, or http on this computer only. Checked live:
  the Commission's list authenticates and Spain's syncs.

- A territory code from the EU list, or given to `verify`, named a file in
  the cache unchecked: a hostile list could write `../` paths outside it.
  Only two capital letters are a territory now; the cache file is named by
  the code the authenticated list publishes.

- trust sync accepts a national list only when its own signature (a child
  of the list's root, ETSI TS 119 612 5.7) signs the whole list: one over
  a part, with the authorities left unsigned, or nested elsewhere is
  refused. The signature is checked with the XML-Signature verifier signed
  documents use, instead of a second, partial one (it refused inclusive
  C14N and read a missing SignatureMethod as SHA-512); among the
  certificates KeyInfo shows, the one the EU list publishes is used.
  goxmldsig is no longer a dependency. Of the lists the EU list pointed at
  on 9 November 2026, the 30 that could be fetched authenticate but
  Germany's, signed with RSA-PSS and refused as before.

- verify names the parts of an XML document its signature does not cover:
  a signature whose references point at one element by Id, none at the
  whole document, leaves the rest unsigned and readable as if signed (the
  ground of signature wrapping). `content.partly_signed`, with the paths
  of the unsigned elements; detached and enveloping signatures, and
  references to the whole document, are not concerned.

- verify checks that the certificate a signature carries is the one it
  names in its signed attributes: signing-certificate-v2 or v1 in CAdES and
  PAdES (read from each PDF signature field's envelope, which the PDF
  library does not hand back), SigningCertificate or SigningCertificateV2 in
  XAdES (only when SignedInfo covers the signed properties). A certificate
  with the same key and another identity put in its place left the
  signature value valid and the wrong name on the report; it is now
  `signing_certificate.mismatch` and the signature counts as broken. A
  signature that names no certificate gets a warning. Among CMS
  certificates answering to the same identifier, the named one is chosen.

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

## [0.20.5-unstable] - 2026-11-08

Published as 0.3.1-unstable, tagged `v0.20.5-unstable` since.

### Fixed

- A binary installed with `go install` reported `0.1.0-unstable`, because the
  version was only set by the Makefile's linker flags and a user's own build
  applies none. The version now falls back to the one the toolchain records in
  the build information, which is the version the user asked for. Binaries
  built by this repository's Makefile are unaffected.
- The mirror workflow carried the branch but not the tags, so a mirror user
  asking for a version was told it did not exist.

## [0.20.3-unstable] - 2026-11-08

Published as 0.3.0-unstable, tagged `v0.20.3-unstable` since.

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

## [0.0.0-unstable] - 2026-11-02

The first commit, which gathers the work numbered 0.1.0 (CLI signing
CAdES, PAdES and XAdES) and 0.2.0 before this repository kept its history.
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
