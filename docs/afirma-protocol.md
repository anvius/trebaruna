# The AutoFirma `afirma://` protocol

A clean-room description of how Spanish public-administration web pages talk to
AutoFirma, written so that `trebaruna` can answer those pages exactly as
AutoFirma 1.9 does. Behaviour, names, constants and byte layouts are described in
our own words; no source code is reproduced.

- [Sources and conventions](#sources-and-conventions)
- [Overview](#overview)
- [A. URI grammar](#a-uri-grammar)
- [B. Responses and error codes](#b-responses-and-error-codes)
- [C. Intermediate server mode](#c-intermediate-server-mode)
- [D. Local channels: WebSocket and the legacy socket](#d-local-channels-websocket-and-the-legacy-socket)
- [E. Batch signing and the triphase protocol](#e-batch-signing-and-the-triphase-protocol)
- [F. Signature policies](#f-signature-policies)
- [G. Version history and what sites send](#g-version-history-and-what-sites-send)
- [Open questions](#open-questions)

---

## Sources and conventions

| Source | Identifier | Use |
|---|---|---|
| `ctt-gob-es/clienteafirma`, tag `v1.9` | commit `1f29aa7a2a` (2025-05-21) | **Primary**: matches the installed AutoFirma 1.9.0 |
| same repo, tag `v1.9.1` and `master` | `master` = `bd9254be70` (2026-10-19) | Later behaviour (protocol 4.1, AES) |
| same repo, tag `v1.9.2` | 2026-05-12 | macOS maintenance branch built on 1.9.0; has **no** 4.1 features |
| Debian package `~/Downloads/autofirma_1_9` | `Version: 1.9.0`, jar built 2025-05-28 | Constants confirmed with `strings` on `.class` files |
| `~/.afirma/AUTOFIRMA.afirma.log.xml.{1,2}` | two invocations, 2026-10-16 | Field evidence (redacted) |

File references use these prefixes (all under the repository root, tag `v1.9`
unless stated):

| Prefix | Path |
|---|---|
| `core:` | `afirma-core/src/main/java/es/gob/afirma/core/` |
| `proto:` | `afirma-core/src/main/java/es/gob/afirma/core/misc/protocol/` |
| `simple:` | `afirma-simple/src/main/java/es/gob/afirma/standalone/` |
| `launch:` | `afirma-simple/src/main/java/es/gob/afirma/standalone/protocol/` |
| `bclient:` | `afirma-crypto-batch-client/src/main/java/es/gob/afirma/signers/batch/client/` |
| `bserver:` | `afirma-server-triphase-signer/src/main/java/es/gob/afirma/signers/batch/` |
| `storage:` | `afirma-signature-storage/src/main/java/es/gob/afirma/signfolder/server/proxy/` |
| `retriever:` | `afirma-signature-retriever/src/main/java/es/gob/afirma/signfolder/server/proxy/` |
| `autoscript` | `afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js` (the page-side library, version 1.9.0 at tag `v1.9`) |

**UNCERTAIN** marks a claim not fully established from the sources. Every such
item is repeated in [Open questions](#open-questions).

Terminology: the *page* is the web page running `autoscript`; the *client* is
AutoFirma (or `trebaruna`); *intermediate server* is the pair of servlets
`StorageService` / `RetrieveService` that the page's site hosts. In `autoscript`,
"WS mode" (`setForceWSMode`) means **Web Service** (intermediate server), not
WebSocket.

---

## Overview

A page starts the client by navigating to an `afirma://` URI (the OS hands it to
the registered handler). The result travels back over one of three channels:

```
                 ┌──────────── afirma://<op>?...  (OS URL handler) ───────────┐
page (autoscript)                                                             client
   │ 1. WebSocket (wss://127.0.0.1:port)   afirma://websocket?ports=..&v=4    │
   │      page sends the operation URI as a WS text message, gets the result  │
   │ 2. Legacy socket (https://127.0.0.1:port/afirma)  afirma://service?...   │
   │      HTTP-over-TLS mini protocol with fragments                          │
   │ 3. Intermediate server: client POSTs the result to the site's            │
   │      StorageService; page polls RetrieveService                          │
```

Which channel a page uses is decided by `autoscript` (`cargarAppAfirma`):
intermediate server if the site forced it (`setForceWSMode(true)`) or on
Android/iOS; otherwise WebSocket on any browser with WebSocket support except
Internet Explorer and Firefox ≤ 60; otherwise the legacy socket; otherwise the
intermediate server (`autoscript`, function `cargarAppAfirma`).

Protocol version numbers (two parameters, see [A.10](#a10-version-parameters)):

| Number | Where | Meaning |
|---|---|---|
| `v` | on `afirma://websocket` and `afirma://service` | channel protocol version |
| `ver` | on each operation URI | minimum protocol version the operation needs |
| `jvc` | on every URI | `autoscript` version code (1.8 → 2, 1.9 → 3, 1.10 → 4) |

AutoFirma 1.9.0 accepts operation versions up to **4**
(`launch:ProtocolInvocationLauncher`, constant for the maximum supported version),
WebSocket channel versions **3 and 4** (`launch:AfirmaWebSocketServerManager`),
and legacy-socket versions **1, 2, 3** (`launch:ServiceInvocationManager`).

---

## A. URI grammar

### A.1 Scheme, registration and dispatch

- Scheme is exactly `afirma`. On Linux the package registers
  `MimeType=x-scheme-handler/afirma` with `Exec=/usr/bin/autofirma %u`
  (`usr/share/applications/afirma.desktop` in the `.deb`) and sets Firefox prefs
  `network.protocol-handler.app.afirma`, `...warn-external.afirma=false`,
  `...external.afirma=true` (`etc/firefox/pref/Autofirma.js` in the `.deb`).
- Entry point: the first command-line argument is treated as a protocol call if,
  lower-cased, it starts with `afirma://` (`simple:SimpleAfirma#main`). The
  launcher itself then requires the literal, **case-sensitive** prefix
  `afirma://`; otherwise it answers `SAF_02` (`launch:ProtocolInvocationLauncher#launch`).
- Dispatch is by **literal prefix match** on the whole string, each operation in
  two spellings, `afirma://<op>?` and `afirma://<op>/?`
  (`launch:ProtocolInvocationLauncher#launch`, confirmed in the 1.9 jar):

| Prefix (`?` or `/?`) | Operation | Parameter class |
|---|---|---|
| `afirma://websocket` | open WebSocket channel | — |
| `afirma://service` | open legacy socket channel | — |
| `afirma://batch` | batch sign | `proto:UrlParametersForBatch` |
| `afirma://selectcert` | select certificate | `proto:UrlParametersToSelectCert` |
| `afirma://save` | save data to a file | `proto:UrlParametersToSave` |
| `afirma://signandsave` | sign then save to file | `proto:UrlParametersToSignAndSave` |
| `afirma://sign`, `afirma://cosign`, `afirma://countersign` | sign / co-sign / counter-sign | `proto:UrlParametersToSign` |
| `afirma://load` | load local file(s) | `proto:UrlParametersToLoad` |
| anything else (including `afirma://log` of autoscript 1.8, `afirma://?op=sign`, upper case) | — | `SAF_04` |

  Consequences: the operation must be the URI *host*; a query parameter `op` does
  **not** select the operation (`autoscript` still sends one; it is ignored for
  dispatch). There is no "path" form other than the optional single `/`.
- Android Chrome form (`intent://<op>?...#Intent;scheme=afirma;package=es.gob.afirma;end`)
  is produced by `autoscript` only on Android (`autoscript`, `buildUrl`); not
  relevant on desktop.

### A.2 Query parsing

Two near-identical parsers exist (`launch:ProtocolInvocationLauncher#extractParams`
and `proto:ProtocolInvocationUriParser#parserUri`):

1. Take everything after the **first** `?` (if there is no `?`, the whole string
   is used — harmless because dispatch already required `?`).
2. Split on `&`. For each piece find the **first** `=`; pieces with no `=` or with
   `=` at position 0 are ignored.
3. The value is URL-decoded as UTF-8 with HTML-form rules (`+` becomes a space,
   `%XX` decoded). An empty value is stored as empty string.
4. Keys are case-sensitive. Duplicate keys: the last one wins (hash map).
5. `proto:ProtocolInvocationUriParser#parserUri` then overwrites key `op` with the
   URI host (text between `://` and `?`, trailing `/` removed, cut at the first
   `/`).

AutoFirma logs the **whole** URI, including `key`, `dat` and `properties`
(`simple:SimpleAfirma#main`; the parser additionally logs the first 300
characters). `trebaruna` should not log those values (see field evidence in
[G.2](#g2-what-sites-send-field-evidence)).

### A.3 Value encodings

**Base64 everywhere is tolerant of both alphabets.** Before decoding, AutoFirma
replaces `_`→`/` and `-`→`+` (`core:misc/http/DataDownloader#downloadData`,
`core:misc/AOUtil#base642Properties`, `simple:crypto/CypherDataManager`). Its
decoder (`core:misc/Base64`) skips whitespace (space, tab, CR, LF) and stops at the
first `=` that completes a quartet.

**`dat` resolution** (`core:misc/http/DataDownloader#downloadData`, called from
`proto:UrlParameters#setCommonParameters`), in this order:

1. If the value starts with `file:/` → rejected (`SAF_03`), checked before
   download (`proto:UrlParameters#setCommonParameters`).
2. If `gzip=true` and the value "looks like Base64" → Base64-decode (alphabet
   normalised) then gunzip.
3. If it starts with `http://` or `https://` → **AutoFirma downloads it** with
   HTTP GET and uses the body as data. `ftp://` is also downloaded.
4. If it "looks like Base64" → decode.
5. Otherwise the raw characters of the string (platform charset) are the data.

"Looks like Base64" (`core:misc/Base64#isBase64`): every character is in
`A–Z a–z 0–9 + / - _ = ~ TAB CR LF`, `=` appears only in the last two positions,
and the count of characters other than CR/LF is a multiple of 4. **Unpadded
Base64 therefore fails the test and is used as literal text.** A space is not in
the set, so standard Base64 whose `+` was not percent-encoded (and became a space
in step A.2.3) is silently treated as text. `autoscript` avoids this by sending
URL-safe Base64 (`normalizeBase64Data` in the WebSocket client; `signOperation` in
the intermediate client also strips CR/LF).

Recommendation for `trebaruna`: accept both alphabets, accept spaces as `+` in
Base64-typed parameters, accept missing padding; never download `dat` URLs
without showing the URL to the user (AutoFirma does it silently).

### A.4 Operations

| `op` (host) | Purpose | Result on success |
|---|---|---|
| `sign` | new signature over `dat` (or a file the user picks if `dat` is absent) | `cert|signature[|extra]` |
| `cosign` | parallel signature over an existing signature in `dat` | same |
| `countersign` | counter-signature of signers in `dat` | same |
| `signandsave` | sign/cosign/countersign (chosen by `cop`), then show a save dialog | same as sign |
| `selectcert` | let the user pick a certificate | `cert` |
| `save` | show a save dialog for `dat` | `OK` |
| `load` | open dialog, return file name(s) and content | `name:b64[|name:b64...]` |
| `batch` | sign a batch (server triphase or local) | `batchResult[|cert]` |
| `websocket` | start WebSocket server ([D.1](#d1-websocket-channel)) | — |
| `service` | start legacy TLS socket ([D.2](#d2-legacy-socket-channel-service)) | — |

Exact payload layouts and encodings are in [B.1](#b1-success-payloads).

### A.5 Parameters common to all operations

From `proto:UrlParameters` (field names as constants, method `setCommonParameters`).

| Name | Type / encoding | Required | Meaning and limits |
|---|---|---|---|
| `key` | 8 characters | no | DES key for the intermediate server. Empty value = no cipher. Length ≠ 8 → `SAF_03`. Used as the bytes of the string in the platform charset (`autoscript` sends 8 decimal digits) — [C.5](#c5-des-cipher-exact-layout) |
| `dat` | see [A.3](#a3-value-encodings) | depends on op | Data, signature, batch definition, or a URL to fetch |
| `gzip` | `true`/other | no | `dat` is Base64 of gzip |
| `fileid` | text | no | Id of the request stored on the intermediate server. Only read when `dat` is absent |
| `rtservlet` | URL | if `fileid` | Retrieve servlet. Validated as below |
| `stservlet` | URL | intermediate mode with `id` | Storage servlet. Validated as below |
| `aw` | `true`/other | no | Active waiting: send `#WAIT` every 10 s ([C.6](#c6-active-waiting)) |
| `mcv` | dotted version, e.g. `1.9` | no | Minimum client version; if greater than AutoFirma's own version → `SAF_41` ([A.10](#a10-version-parameters)) |
| `ksb64` | Base64 of `NAME[:path]` | no | Preferred keystore ([A.8](#a8-keystores)) |
| `keystore` | `NAME[:path]` (plain) | no | Same, legacy (kept for AutoFirma 1.4 pages); wins over `ksb64` |
| `appname` | text | no | Name of the calling site/app (only stored by sign/batch in 1.9) |

**Servlet URL validation** (`proto:UrlParameters#validateURL`), applied to
`rtservlet`, `stservlet`, `batchpresignerurl`, `batchpostsignerurl`: the value is
URL-decoded once more, must parse as a URL, scheme `http` or `https`, host not
literally `localhost` or `127.0.0.1` (→ `SAF_13`), and the full URL must contain
neither `?` nor `=` (→ `SAF_03`). Path segments with session tokens are allowed
(field evidence: `.../StorageService/service/<token>`).

**Session id** (`id`, or `fileid` when `id` is absent): at most **20** characters,
ASCII letters and digits only (checked lower-cased against `a–z0–9`) → else
`SAF_03` (`proto:UrlParametersToSign#setSignParameters` and siblings).
`autoscript` generates 20 characters from `0–9a–uw–zA–Z` (`AfirmaUtils.generateNewIdSession`).

`servicesRequired`: when the call did **not** arrive through a socket
(intermediate mode), each operation's parser is created with
`servicesRequired=true`; then if `id` is present `stservlet` becomes mandatory
(`SAF_03` otherwise). Through WebSocket/legacy socket, `stservlet` is ignored.

When `fileid` is present the parsers stop after reading `id`/`ver`/`appname`;
everything else comes from the downloaded XML ([C.3](#c3-the-request-envelope-xml)).

### A.6 Per-operation parameters

#### `sign`, `cosign`, `countersign` (`proto:UrlParametersToSign`)

| Name | Required | Values / meaning |
|---|---|---|
| `format` | **yes** (`SAF_03`) | Signature format name, case-insensitive ([A.9](#a9-formats-and-algorithms)); `auto` = detect |
| `algorithm` | **yes** (`SAF_03`) | One of `SHA1 SHA256 SHA384 SHA512`, `SHA{1,256,384,512}withRSA`, `SHA{1,256,384,512}withECDSA` — exact, case-sensitive; else `SAF_03` |
| `properties` | no | Base64 of a Java properties text (UTF-8) = *extraParams* ([A.7](#a7-properties-extraparams)). Undecodable → logged and treated as empty |
| `id` | intermediate | Session id for the result |
| `ver` | no | Minimum protocol version; default `0` |
| `sticky` | no | `true` = remember the chosen key for the next operation in the same process |
| `resetsticky` | no | `true` = ignore a remembered key this time |
| `appname` | no | Calling application name |
| any other key | — | collected as "another params" for plugins; ignored by the native processor |

#### `signandsave` (`proto:UrlParametersToSignAndSave`)

As `sign` plus:

| Name | Required | Meaning |
|---|---|---|
| `cop` | effectively yes | Crypto operation: `sign`, `cosign`, `countersign` (case-insensitive); unknown or missing → no operation → failure, probably `SAF_09` (UNCERTAIN) |
| `filename` | no | Default file name for the save dialog; must not contain `\ / : * ? " < > |` (`SAF_03`) |

Differences: `algorithm` accepts only `SHA*` and `SHA*withRSA` (no `withECDSA`
spellings) in 1.9; `appname` is not read.

#### `selectcert` (`proto:UrlParametersToSelectCert`)

`id`, `ver`, `properties` (filters only matter), `sticky`, `resetsticky`, plus
common parameters.

#### `save` (`proto:UrlParametersToSave`)

| Name | Required | Meaning |
|---|---|---|
| `dat` or `fileid` | **one of them** (`SAF_03`) | Data to save |
| `title` | no | Dialog title; default from `protocolomessages.properties` |
| `filename` | no | Suggested name; forbidden `\ / : * ? " < > |` |
| `exts` | no | Comma-separated extensions; forbidden `\ / : * ? " < > | ;` and space |
| `desc` | no | File-type description; if `exts` given and `desc` does not end with `)`, AutoFirma appends ` (*.ext1*.ext2)` style suffix |
| `id`, `ver` | as above | |

Note: the intermediate-server client of `autoscript` 1.9 sends the extension and
description as `extension` and `description` (not `exts`/`desc`), which AutoFirma
ignores (`autoscript`, `AppAfirmaJSWebService.saveDataToFile`).

#### `load` (`proto:UrlParametersToLoad`)

| Name | Meaning |
|---|---|
| `title` | Dialog title |
| `exts` | Comma-separated extensions |
| `desc` | Description |
| `filePath` | Initial directory/path (empty = none) |
| `multiload` | `true` = multiple selection |
| `ver` | as above |

`load` has **no intermediate-server return path** in 1.9: `UrlParametersToLoad`
never reads `stservlet` and `ProtocolInvocationLauncherLoad` never posts the
result; `autoscript`'s intermediate client refuses load with an
`UnsupportedOperationException`. Only WebSocket/legacy socket.

#### `batch` (`proto:UrlParametersForBatch`)

| Name | Required | Meaning |
|---|---|---|
| `batchpresignerurl` | yes unless `localBatchProcess=true` | Pre-sign service URL (validated as servlet URL) |
| `batchpostsignerurl` | yes unless `localBatchProcess=true` | Post-sign service URL |
| `dat` | yes | Batch definition: Base64 of JSON (when `jsonbatch=true`) or XML |
| `jsonbatch` | no | `true` = JSON batch (protocol of AutoFirma ≥ 1.8) |
| `localBatchProcess` | no | `true` = sign every item locally, no server (JSON only) |
| `needcert` | no | `true` = append the signing certificate to the result |
| `properties` | no | Only certificate filters are used |
| `id`, `ver`, `sticky`, `resetsticky`, `appname` | | as above |

Details in [E](#e-batch-signing-and-the-triphase-protocol).

#### `websocket` and `service` (`launch:ProtocolInvocationLauncher#getChannelInfo`)

| Name | Meaning |
|---|---|
| `ports` | Comma-separated integers (absolute value taken); non-numeric → exception. `websocket` without `ports` → port **63117**; `service` without `ports` → `SAF_03` |
| `v` | Channel protocol version, integer; default **1** if absent or unparsable |
| `idsession` | Session secret. Kept only if every character is a letter or digit (Unicode `isLetterOrDigit`); otherwise discarded **and the session check is disabled** |
| `jvc` | `autoscript` version code |

### A.7 `properties` (extraParams)

Encoding: Base64 (either alphabet) of a text in **Java `.properties` syntax**,
read as UTF-8 (`core:misc/AOUtil#base642Properties`). Keys and values follow
Java properties rules: `key=value` or `key:value`, `#`/`!` comments, `\`
escapes and line continuations, `\uXXXX`. `autoscript` encodes `extraParams`
with standard Base64 in the intermediate client and URL-safe Base64 in the
WebSocket client.

Keys interpreted by the protocol layer itself:

| Key | Effect | Source |
|---|---|---|
| `headless` | `true`: no confirmation dialogs; a needed confirmation becomes `SAF_50`; also makes certificate selection "mandatory" (auto-select when exactly one certificate matches) | `launch:AfirmaExtraParams`, `keystores-filters CertFilterManager` |
| `mandatoryCertSelection` | `false`: same auto-select behaviour | `CertFilterManager#isMandatoryCertificate` |
| `filter`, `filters`, `filters.1`, `filters.2`, … | certificate filters (below) | `CertFilterManager#getFilterValues` |
| `checkSignatures` | `true`: validate the input signature before co/counter-signing; invalid → `SAF_39` | `launch:ProtocolInvocationLauncherSign#sign` |
| `target` | countersign target: `tree` → whole tree, anything else → leaves | `launch:ProtocolInvocationLauncherSign#executeSign` |
| `mode` | `implicit`/`explicit`. XAdES + `explicit` without `useManifest=true`: legacy behaviour, data replaced by its SHA-1 and `mimeType=hash/sha1` | `#isXadesExplicitConfigurated` |
| `filenameExts`, `filenameDescription`, `filenameCurrentDir`, `filenameActualName` | open-dialog hints when `dat` is absent | `launch:AfirmaExtraParams` |
| `filenameSaveExts`, `filenameSaveDescription`, `filenameSaveCurrentDir` | save-dialog hints for `signandsave` | same |
| `expPolicy` | `FirmaAGE` or `FirmaAGE18`: expand AGE policy ([F.1](#f1-age-policy-expansion-exppolicy)); other value → `SAF_23` | `core:signers/ExtraParamsProcessor` |
| `profile` | **removed** before signing in 1.9 (baseline not offered) | `launch:ProtocolInvocationLauncherSign#processSign` |
| `serverUrl` | triphase formats only: URL of the triphase signing service ([E.8](#e8-single-signature-triphase-formats)) | `cadestri-client ProtocolConstants` |

**Certificate filter grammar** (`afirma-keystores-filters/.../CertFilterManager.java`):
`filter` or `filters` holds one filter expression; `filters.1`, `filters.2`, …
(consecutive from 1) hold alternatives, and a certificate is offered if it matches
**any** of them. Inside one expression, conditions are separated by `;` and
**all** must hold. Conditions (prefix matched case-insensitively):

| Condition | Meaning |
|---|---|
| `dnie:` | DNIe signing certificate |
| `ssl:<serial>` | the certificate with that serial (hex); if it is a DNIe authentication certificate, the same card's DNIe signing certificate instead (same holder `SERIALNUMBER`, same expiry date), or nothing (`SSLFilter`) |
| `qualified:<serial>` | the certificate with that serial if it is a signing certificate (non-repudiation; under ACCV-CA2 digital signature alone); otherwise its signing pair in the same store (same issuer, holder `SERIALNUMBER` and expiry date), or itself when there is none, unless it is a DNIe authentication certificate (`QualifiedCertificatesFilter`) |
| `signingcert:` / `authcert:` | signing / authentication certificate |
| `keyusage.<usage>:<true|false|null>` | key usage bits: `digitalsignature nonrepudiation keyencipherment dataencipherment keyagreement keycertsign crlsign encipheronly decipheronly` |
| `nonexpired:` / `nonexpired:<bool>` | hide expired (bare form = hide) |
| `sscd:` | on a secure signature-creation device |
| `subject.rfc2254:<filter>` / `issuer.rfc2254:<filter>` / `issuer.rfc2254.recurse:<filter>` | LDAP-style filter on the DN |
| `subject.contains:<text>` / `issuer.contains:<text>` | substring on the DN |
| `thumbprint:<alg>:<hex>` | exact certificate by digest |
| `policyid:<oid>[,<oid>...]` | certificate policy OIDs |
| `pseudonym:` / `pseudonym:<value>` | pseudonym certificates |
| `encodedcert:<base64>` | exact certificate (used by `autoscript` to emulate sticky in intermediate mode) |
| `disableopeningexternalstores` | user may not switch to other keystores |

With no filter at all, expired certificates are hidden by default.

trebaruna evaluates every condition above. `ssl:` and `qualified:` look at the
other certificates of the chosen key's store — a card's other identities; a
file holds one — and compare expiry dates in UTC, where AutoFirma uses the
local day. A condition it does not understand matches nothing, and the
approval says which.

Format-specific keys pass straight through to the signers; the most used by sites
(names from `PdfExtraParams`, `XAdESExtraParams`, `CAdESExtraParams`):
`mode`, `policyIdentifier`, `policyIdentifierHash`, `policyIdentifierHashAlgorithm`,
`policyQualifier`, `policyDescription`, `signerClaimedRoles`,
`signatureProductionCity` / `…Province` / `…PostalCode` / `…Country` (trebaruna:
a PDF's /Location takes the city, an XML signature declares all four in
`SignatureProductionPlaceV2`; the approval shows them, with the policy and the
roles, before anything is signed),
`precalculatedHashAlgorithm` (data is already a digest; trebaruna: CAdES
only, detached, the digest's length checked, its algorithm that of the
signature algorithm, SHA-1 refused; the approval shows the digest in hex;
`NONE` ignores it as `AOPkcs1Signer` does; other families refuse it), `format` (XAdES variant:
`XAdES Detached`, `XAdES Enveloped`, `XAdES Enveloping`),
`signatureSubFilter` (`adbe.pkcs7.detached` or `ETSI.CAdES.detached`),
`signaturePage`, `signaturePositionOnPageLowerLeftX/Y`,
`signaturePositionOnPageUpperRightX/Y`, `layer2Text`, `layer2FontFamily/Size/Style/Color`,
`signatureRubricImage`, `signatureField` (the form's empty signature field to
sign in, the seal in its box; trebaruna refuses a name the form lacks),
`visibleSignature` (`want`/`optional` opens a placement dialog), `signReason`, `signerContact`, `ownerPassword`, `tsaURL`, `tsaPolicy`,
`tsaHashAlgorithm`, `includeOnlySignningCertificate`, `signingCertificateV2`,
`allowShadowAttack`, `pagesToCheckShadowAttack` (default `10` when checking).
Note the CAdES constant for the hash-algorithm key is misspelt
`poliyIdentifierHashAlgorithm` in `CAdESExtraParams`, but the policy object is
built from the correctly spelt `policyIdentifierHashAlgorithm`
(`core:signers/AdESPolicy#buildAdESPolicy`).

### A.8 Keystores

Value of `keystore`, or Base64-decoded `ksb64`: `NAME` or `NAME:path`
(`proto:UrlParameters#getKeyStoreName/#getDefaultKeyStoreLib`). The part after
the first `:` is a library or file path (quotes stripped, made canonical).
`NAME` is matched first against the display names, then enum names, of
`AOKeyStore` (`simple:SimpleKeyStoreManager#getKeyStore`). Names `autoscript`
uses: `WINDOWS`, `APPLE`, `PKCS12`, `PKCS11`, `MOZ_UNI`, `SHARED_NSS`, `JAVA`,
`JCEKS`, `JAVACE`, `DNIEJAVA`; Firefox pages default to `MOZ_UNI`
(`autoscript`, `getDefaultKeystore`). Default when nothing applies: Windows →
`WINDOWS`, macOS → `APPLE`, Linux → `SHARED_NSS`
(`AOKeyStore#getDefaultKeyStoreTypeByOs`). A keystore chosen earlier in the same
process, or the user preference "use default store in browser calls", takes
precedence over the page's request.

### A.9 Formats and algorithms

Format names (case-insensitive, `core:signers/AOSignerFactory#getSigner`;
constants in `core:signers/AOSignConstants`):

| Family | Accepted names |
|---|---|
| CAdES | `CAdES`, `CAdEStri`, `CAdES-ASiC-S`, `CAdES-ASiC-S-tri`, `CMS/PKCS#7` |
| XAdES | `XAdES`, `XAdES Detached`, `XAdES Enveloped`, `XAdES Enveloping`, `XAdEStri`, `XAdES-ASiC-S`, `XAdES-ASiC-S-tri` |
| XMLDSig | `XMLDSig`, `XMLDSig Detached`, `XMLDSig Enveloped`, `XMLDSig Enveloping` |
| PAdES | `PAdES`, `PAdEStri`, `Adobe PDF`, `Adobe PDF TriPhase` |
| FacturaE | `FacturaE`, `Factura-e`, `FacturaEtri` |
| Office | `OOXML`, `OOXML (Office Open XML)`, `ODF`, `ODF (Open Document Format)` |
| Raw | `NONE` (PKCS#1), `NONEtri` |
| Auto | `auto` |

trebaruna: `NONE` signs the data as AutoFirma's `AOPkcs1Signer` does (the
algorithm's digest, PKCS#1 v1.5 for RSA, ASN.1 for ECDSA, checked against the
certificate; no co- or counter-signature, `SAF_04`). `NONEtri` goes through the
site's server with format `NONE`, whose `Pkcs1TriPhasePreProcessor` returns the
document itself as `PRE`; trebaruna signs only when every `PRE` is the
document the person approved, and refuses otherwise, before signing anything.

Unknown name → `SAF_06`. `auto` for `sign`: PDF → PAdES, FacturaE → FacturaE,
other XML → XAdES, anything else → CAdES; for `cosign`/`countersign`: the format
of the input signature (a CMS envelope → CAdES, a signed XML → XAdES), or `SAF_17`
if not recognised
(`launch:ProtocolInvocationLauncherUtil#identifyFormatFromData`).

trebaruna: a `cosign` with `CAdES-ASiC-S` or `XAdES-ASiC-S` takes the
container in `dat` and answers it with one more signature of the kind it
holds — its CAdES signature co-signed in place, or one more XAdES signature
in its signatures file, refused when it would break another. A
`countersign` of a container is refused (`SAF_04`, not supported yet), and
so is a `cosign` whose data is not a container (`SAF_31`).

Algorithm: the digest part of `algorithm` is kept and the suffix is **recomputed
from the key type** — `withRSA` for RSA, `withDSA` for DSA, `withECDSA` for EC
keys (`core:signers/AOSignConstants#composeSignatureAlgorithmName`). So
`SHA256withRSA` with an EC key yields `SHA256withECDSA`. Other key types →
`SAF_51`.

### A.10 Version parameters

- `ver` (operations): parsed as integer, absent → `0`, unparsable → `1`
  (`#parseProtocolVersion`). If greater than 4 → `SAF_21`. Through WebSocket v4 the
  channel version (4) is used instead of `ver`; through WebSocket v3 the message's
  own `ver` is used.
- Protocol ≥ 3 enables the third result element (file name JSON) for sign
  ([B.1](#b1-success-payloads)).
- `v` (channels): see [D](#d-local-channels-websocket-and-the-legacy-socket).
- `jvc`: integer, default 1; if less than 1 a warning dialog "insecure
  JavaScript" is shown and the call continues (`#launch`). In 1.9.1, `v=4` with
  `jvc>3` is upgraded to protocol **4.1** ([G.1](#g1-timeline)).
- `mcv`: compared part-wise as dotted integers with an optional text suffix
  against AutoFirma's version string (`launch:Version`); 1.9.0 reports `1.9`
  (log line "Autofirma 1.9"). Greater → `SAF_41`. `trebaruna` must choose which
  AutoFirma version it claims (see Open questions).

### A.11 Operation order inside AutoFirma (sign)

Useful to reproduce which error a page sees first
(`launch:ProtocolInvocationLauncherSign#processSign/#sign`): protocol version →
`mcv` → `profile` removed → signer by format (`SAF_06`) → keystore choice → ask
for a file if `dat` absent (`CANCEL` if cancelled) → `auto` detection (`SAF_17`)
→ XAdES-explicit legacy → `checkSignatures` → `expPolicy` expansion (`SAF_23`)
→ visible PDF signature placement (`SAF_43`) → certificate dialog (`CANCEL`,
`SAF_19`, `SAF_08`) → key type (`SAF_51`) → sign (format-specific `SAF_28…40`,
`SAF_52`, generic `SAF_09`; wrong PIN retries with the same certificate) →
encode/encrypt (`SAF_12`, `SAF_42`).

---

## B. Responses and error codes

### B.1 Success payloads

`b64u` = URL-safe Base64 **with** `=` padding, no line breaks
(`core:misc/Base64#encode(…, true)`). `b64` = standard Base64 with padding.
`enc(x)` = DES envelope `N.b64u(DES(x))` of [C.5](#c5-des-cipher-exact-layout),
used only when `key` was given.

| Operation | Without `key` | With `key` | Source |
|---|---|---|---|
| sign, cosign, countersign, signandsave | `b64u(cert)` `|` `b64u(sig)` [`|` `b64u(extra)`] | `enc(cert)` `|` `enc(sig)` [`|` `enc(extra)`] | `launch:NativeSignDataProcessor#postProcess` |
| selectcert | `b64u(cert)` | `enc(cert)` | `launch:ProtocolInvocationLauncherSelectCert` |
| batch | `b64(result)` [`|` `b64(cert)`] | `enc(result)` [`|` `enc(cert)`] | `launch:ProtocolInvocationLauncherBatch#processBatch` |
| save | `OK` (legacy socket: `SAVE_OK`) | `OK` (never encrypted) | `launch:ProtocolInvocationLauncherSave` |
| load | `name:b64(content)` joined by `|` | (no key path) | `launch:ProtocolInvocationLauncherLoad` |

- `cert` is the DER of the end-entity certificate only (first of the chain).
- `sig` is the complete signature file (CMS, XML or PDF); for triphase formats
  it is the bytes of the server's new document id ([E.8](#e8-single-signature-triphase-formats)).
- `extra` appears only when the user picked the input file (no `dat`) **and** the
  protocol version ≥ 3: UTF-8 text `{"filename": "<name>"}` (built by hand,
  key-colon-space-value, no escaping).
- Batch result is the text returned by the post-signer (JSON or XML,
  [E.5](#e5-result-returned-to-the-page)), encoded as bytes UTF-8. **Order is
  result first, certificate second** — the reverse of sign. The certificate is
  appended only with `needcert=true`.
- Note the encodings differ: sign/selectcert use URL-safe, batch/load use the
  standard alphabet. `autoscript` normalises `-`/`_` back on every path, so
  `trebaruna` may use URL-safe throughout — except that over the intermediate
  server the storage servlet URL-decodes its body, so standard-alphabet `+`
  would become a space there. **Always use URL-safe on the intermediate server.**
- Separator characters `|`, `.`, `:` are sent raw.

### B.2 Cancellation

The literal `CANCEL` (no prefix, no encryption) whenever the user closes a dialog:
certificate selection, file choice, save dialog, a confirmation, PIN dialog
cancelled (`launch:*#RESULT_CANCEL`). Over the intermediate server it is stored
as is; `autoscript` maps `CANCEL`, `CANCEL\n`, `CANCEL\r\n` to
`es.gob.afirma.core.AOCancelledOperationException` (`autoscript`,
`successResponseFunction`, `processResponse`).

### B.3 Error format (1.9)

`SAF_NN: <message>` — code, colon, one space, message text in Spanish, UTF-8
(`launch:ProtocolInvocationLauncherErrorManager#getErrorMessage`). Exception for
`sign`/`cosign`/`countersign`/`signandsave`: when the error was raised with an
underlying cause that has a message (typical for `SAF_08`, `SAF_09`, `SAF_23`,
`SAF_28`–`SAF_40`, `SAF_50`–`SAF_52`), the text after `SAF_NN: ` is that cause's
message (technical, usually Spanish) instead of the bundle text
(`launch:ProtocolInvocationLauncher`, sign branches; `launch:SocketOperationException#getMessage`).
Other operations always use the bundle text. Over the intermediate server the whole string is URL-encoded
(UTF-8, form rules) before being put in `dat`; the storage servlet decodes it.
AutoFirma also shows a modal error dialog unless the JVM property
`es.gob.afirma.protocolinvocation.HeadLess` is true. `autoscript` recognises any
answer starting with `SAF_` as an error and passes the whole string to the page's
error callback as message with type `java.lang.Exception`.

| Code | Constant | Spanish text (messages bundle key `ProtocolLauncher.N`) | Emitted when (1.9) |
|---|---|---|---|
| `SAF_00` | CANNOT_READ_DATA | No se han podido leer los datos a firmar | user-chosen file unreadable |
| `SAF_01` | NULL_URI | La URL recibida es nula | null URI / null options |
| `SAF_02` | UNSUPPORTED_PROTOCOL | Protocolo no soportado | not starting with `afirma://` |
| `SAF_03` | PARAMS | Error en los parámetros de entrada | any parameter error; HTTP 400 from batch services |
| `SAF_04` | UNSUPPORTED_OPERATION | Operación no soportada. Compruebe que dispone de la última versión de Autofirma. | unknown op; signer refuses operation |
| `SAF_05` | CANNOT_SAVE_DATA | No se ha podido guardar los datos | save failed |
| `SAF_06` | UNSUPPORTED_FORMAT | Formato de firma no soportado | unknown format |
| `SAF_07` | CANNOT_FIND_KEYSTORE | No se ha podido determinar el almacén de claves a utilizar | defined, no emitter found |
| `SAF_08` | CANNOT_ACCESS_KEYSTORE | Error accediendo al almacén de claves y certificados | keystore/dialog failure |
| `SAF_09` | SIGNATURE_FAILED | Error realizando la firma electrónica | generic signing failure |
| `SAF_10` | NO_CERTIFICATES_SYSTEM | No hay certificados de firma instalados en el sistema | defined, no emitter found |
| `SAF_11` | SENDING_RESULT | Error en el envio del resultado de la operación. | POST to storage failed |
| `SAF_12` | ENCRIPTING_DATA | Error en el cifrado de los datos a enviar | DES failed |
| `SAF_13` | LOCAL_ACCESS_BLOCKED | Se ha pedido acceso a una dirección local, pero por seguridad se ha bloqueado el acceso | servlet URL is localhost |
| `SAF_14` | OBSOLETE_APP | (HTML) La aplicación está obsoleta y no puede procesarse la petición… | parameter needs newer app |
| `SAF_15` | DECRYPTING_DATA | Error en el descifrado de los datos | DES decrypt of retrieved request failed |
| `SAF_16` | RECOVERING_DATA | Error al recuperar los datos del servidor intermedio | retrieve returned `err-…` or I/O error |
| `SAF_17` | UNKNOWN_SIGNER | Los datos proporcionados no son una firma electrónica reconocida | `auto` on unknown data |
| `SAF_18` | DECODING_CERTIFICATE | Error al descodificar el certificado de firma | |
| `SAF_19` | NO_CERTIFICATES_KEYSTORE | No hay ningun certificado válido en su almacén. Compruebe las fechas de caducidad e instale un certificado válido. | no certificate passes filters |
| `SAF_20` | LOCAL_BATCH_SIGN | Error en el procesado del lote de firma. | local batch failure |
| `SAF_21` | UNSUPPORTED_PROCEDURE | La versión de Autofirma instalada no es compatible con este trámite.\nActualice a la última versión disponible. | `ver`/`v` too high |
| `SAF_22` | UNSOPPORTED_WEB_PROCEDURE | El trámite web no es compatible con la versión de Autofirma instalada.\nConsulte las instrucciones del trámite para saber que versión debe instalar. | defined, no emitter found |
| `SAF_23` | INVALID_POLICY | Se ha establecido una política de firma no válida o parámetros no compatibles con ella. | `expPolicy` problems |
| `SAF_24` | RECOVERING_LOG | Error al obtener el registro de log acumulado hasta la ejecución actual. | legacy `log` op (not in 1.9) |
| `SAF_25` | CANNOT_LOAD_DATA | Error en la lectura de los datos a cargar. | load read failure |
| `SAF_26` | CONTACT_BATCH_SERVICE | Error en la comunicación con el servicio de firma de lotes. | HTTP 4xx (≠400) from batch services |
| `SAF_27` | BATCH_SIGNATURE | El servicio informó de un error durante la firma del lote. | HTTP 5xx / batch error |
| `SAF_28` | INVALID_PDF | El fichero no es un PDF o es un PDF no soportado. | |
| `SAF_29` | INVALID_XML | Las firmas XAdES Enveloped solo pueden realizarse sobre datos XML. | |
| `SAF_30` | INVALID_DATA | El formato de los datos a firmar no es adecuado para el tipo de firma seleccionado. | |
| `SAF_31` | NO_SIGN_DATA | Los datos introducidos no se corresponden con un objeto de firma. | cosign/countersign on non-signature |
| `SAF_32` | FACE_ALREADY_SIGNED | La factura ya tiene una firma electrónica y no admite firmas adicionales. | |
| `SAF_33` | PDF_WRONG_PASSWORD | La contraseña proporcionada no es válida para el PDF actual o no se proporcionó ninguna contraseña. | |
| `SAF_34` | PDF_UNREG_SIGN | El PDF contiene firmas no registradas. | |
| `SAF_35` | PDF_CERTIFIED | El PDF está certificado. | |
| `SAF_36` | CANNOT_FIND_SSL_KEYSTORE | No se ha podido encontrar el almacén de claves SSL para la comunicación segura. Restaure la instalación de Autofirma para generar uno nuevo. | defined (code path commented out) |
| `SAF_37` | CANNOT_ACCESS_SSL_KEYSTORE | No se ha podido acceder al almacén de claves SSL para la comunicación segura. Restaure la instalación de Autofirma para generar uno nuevo. | same |
| `SAF_38` | INVALID_FACTURAE | El archivo que intenta firmar no es una factura electrónica reconocida. | |
| `SAF_39` | INVALID_SIGNATURE | La firma de entrada no es válida. | |
| `SAF_40` | RECOVER_SERVER_DOCUMENT | Error al recuperar el documento | triphase server error |
| `SAF_41` | MINIMUM_VERSION_NON_SATISTIED | El uso de este trámite web requiere una versión más reciente de Autofirma.\nActualice a la última versión disponible. | `mcv` too high |
| `SAF_42` | POSTPROCESSING_DATA | Error al postprocesar una firma, probablemente debido a un plugin que afecte al sistema de firma. | |
| `SAF_43` | VISIBLE_SIGNATURE | Error durante la firma visible del PDF. | placement mandatory and cancelled |
| `SAF_44` | SIGN_WITHOUT_DATA | La firma no contiene los datos y no se compatible con la configuración seleccionada | |
| `SAF_45` | CANNOT_OPEN_SOCKET | No se pudo abrir un socket para la comunicación con la aplicación | no port could be bound |
| `SAF_46` | INVALID_SESSION_ID | Id de sesión inválido | WebSocket v4 session mismatch |
| `SAF_47` | EXTERNAL_REQUEST_TO_SOCKET | Peticion al socket desde IP externa o sin identificar | WebSocket v4 non-loopback peer |
| `SAF_48` | PDF_SHADOW_ATTACK | Posible PDF Shadow Attack | defined, no direct emitter found |
| `SAF_49` | SIGNING_LTS_SIGNATURE | Multifirma de firma de archivo | defined, no direct emitter found |
| `SAF_50` | CONFIRMATION_NEEDED | La operación puede generar firmas no validas, por lo que no se puede continuar sin confirmacion de usuario. | confirmation needed with `headless=true` |
| `SAF_51` | INCOMPATIBLE_KEY_TYPE | El tipo de clave del certificado no está soportado. | |
| `SAF_52` | LOCKED_KEYSTORE | El almacén de claves esta bloqueado. Siga las instrucciones del proveedor del almacén o tarjeta para desbloquearlo. | locked token |

Texts: `afirma-simple/src/main/resources/properties/protocolmessages.properties`
(`\n` is a real newline). "No emitter found" means a search of
`afirma-simple/.../standalone` found no use outside the table; such codes may
still surface through other paths (UNCERTAIN).

Other non-SAF answers a page may see: `MEMORY_ERROR` (legacy socket only, out of
memory), `NULL` (handled by `autoscript` as unknown error; no emitter in 1.9).

### B.4 Intermediate-server error answers (`ERR-NN:=text`)

Produced by the servlets, not by AutoFirma; format `ERR-NN:=<text>`
(`storage:ErrorManager`, `retriever:ErrorManager`):

| Code | Servlet | Meaning |
|---|---|---|
| `ERR-00` | both | no `op` |
| `ERR-01` | both | unsupported `op` |
| `ERR-02` | storage | no `dat` — the error text itself is stored as the file content |
| `ERR-05` | both | no `id` |
| `ERR-06` | retriever | id unknown, expired, or already read (the page keeps polling on this one) |
| `ERR-07` | both | invalid data; also stored instead of data larger than `maxFileSize` |
| `ERR-18` | storage | could not write the temporary file |
| `ERR-20` | both | no `v` (syntax version) |

AutoFirma treats a retrieved body longer than 8 bytes whose first 8 bytes,
lower-cased, start with `err-` as a failure → `SAF_16`
(`launch:ProtocolInvocationLauncherUtil#getDataFromRetrieveServlet`).
`autoscript` treats `ERR-11:=…` as cancellation (used by 1.9.1, [B.5](#b5-191-error-format-protocol-41)).

### B.5 1.9.1 error format (protocol 4.1)

Only when the call was upgraded to 4.1 (`v=4` and `jvc>3`, i.e. `autoscript`
1.10.x with AutoFirma 1.9.1): errors become `err-00:=AF<6 digits> - <description>`,
cancellation `err-11:=AF500001 - …` instead of `CANCEL`; codes `AF1xxxxx` hardware,
`AF2…` internal, `AF3…` third party, `AF4…` communication, `AF5…` functional,
`AF6…` request (`62…` request from browser) (`v1.9.1` `launch:ProtocolInvocationLauncherErrorManager#getErrorMessage`,
`core:ErrorCode`). Older protocols keep `SAF_NN` and add `SAF_53` "unknown".
`autoscript` 1.10 accepts both forms, so a client answering in the 1.9 format
remains compatible.

---

## C. Intermediate server mode

### C.1 Flow

```
page                         site servlets                    client
 │ (if URI ≤ 2000 chars)                                         │
 │ afirma://sign?jvc=3&ver=3&op=sign&id=I&key=K&stservlet=S&format=..&algorithm=..
 │   &properties=..&aw=true&appname=..&dat=..  ─────────────────►│
 │                                                               │
 │ (if URI > 2000 chars)                                         │
 │ POST S  op=put&v=1_0&id=F&dat=enc(XML)  ──►│                  │
 │ afirma://sign?jvc=3&fileid=F&rtservlet=R&key=K ──────────────►│
 │                                            │◄── POST R op=get&v=1_0&id=F
 │                                            │──► enc(XML) + newline (file deleted)
 │                                            │◄── POST S op=put&v=1_0&id=I&dat=#WAIT  (every 10 s, aw)
 │ POST R op=get&v=1_0&id=I&it=n (every 3 s)─►│                  │
 │◄── ERR-06 (not yet) / #WAIT / result ──────│◄── POST S op=put&v=1_0&id=I&dat=<result>
```

Sources: `autoscript` (`AppAfirmaJSWebService`: `signOperation`, `isURLTooLong`
with limit 2000, `sendDataAndExecAppIntent`, `buildUrlWithoutData`,
`getStoredFileFromServlet`, `retrieveRequest`), `launch:IntermediateServerUtil`,
`launch:ActiveWaitingThread`, `launch:ProtocolInvocationLauncher` (all branches).

When `autoscript` uploads the request it generates a **fresh** 20-character
`fileid` F distinct from the session id I; the response is stored under I,
which travels inside the XML as `id`. Default servlet URLs are
`<origin>/afirma-signature-storage/StorageService` and
`<origin>/afirma-signature-retriever/RetrieveService`, overridable with
`setServlets` (`AppAfirmaJSWebService` constructor).

### C.2 Fetching the request (`op=get`)

- Method **POST** to the `rtservlet` URL; body
  `op=get&v=1_0&id=<fileid>` (no explicit Content-Type, so Java's default
  `application/x-www-form-urlencoded`); headers `Accept: */*`,
  `Connection: keep-alive`, `Origin: <scheme>://<host of the servlet>`
  (`launch:IntermediateServerUtil#retrieveData`, `core:misc/http/UrlHttpManagerImpl#readUrl`:
  for POST the query part after `?` becomes the body).
- Proxy settings of the system apply; TLS is validated normally unless the user
  disabled checks in AutoFirma preferences ("secure connections" / "secure
  domains" list); on a trust error AutoFirma may offer the user to trust the
  server certificate (`simple:HttpManager#readUrl` with an SSL error processor).
- Body of the answer: either an `ERR-…` text, or the encrypted request
  `N.b64u(DES(xml))` followed by a line break (the servlet uses `println`;
  `\n` or `\r\n` depending on the server OS) (`retriever:RetrieveService#retrieveSign`).
  Without `key`, the body is plain Base64 of the XML.
- The servlet deletes the file after serving it once; files expire after
  `expTime` (default 60 000 ms) (`retriever:RetrieveConfig`).
- Any HTTP 4xx/5xx raises an I/O error → `SAF_16`.

### C.3 The request envelope (XML)

After decryption (`proto:ProtocolInvocationUriParserUtil#parseXml`):

```
<sign><e k="ver" v="3"/><e k="op" v="sign"/><e k="id" v="I"/><e k="key" v="K"/>…</sign>
```

- Root element name = operation (`sign`, `cosign`, `countersign`, `signandsave`,
  `selectcert`, `save`, `batch`); a root named `op` means `SIGN`. The child
  `e k="op"` overrides it.
- Every child **must** be an element named `e` with attributes `k` and `v`;
  anything else, **including whitespace text nodes**, fails the parse → `SAF_03`.
  `autoscript` writes no whitespace (`buildXML`).
- Each `v` is URL-decoded (UTF-8, `+` → space) before use. `autoscript` does
  **not** URL-encode nor XML-escape the values it writes. Consequence: a
  standard-Base64 `properties` value with `+` loses those characters (they become
  spaces, which the Base64 decoder skips) — UNCERTAIN whether this corrupts
  `properties` in practice; `trebaruna` should map spaces back to `+` in Base64
  parameters.
- Parsed with a secure DOM builder (external entities disabled).
- The parameters then follow [A.5](#a5-parameters-common-to-all-operations)/[A.6](#a6-per-operation-parameters)
  with `servicesRequired=true`.
- JSON variant: only when the *URI* carries `jsonbatch=true` together with
  `fileid`, the retrieved data is parsed as `{"params":[{"k":…,"v":…},…]}` with
  URL-decoded values (`bclient:TriphaseDataParser#parseParamsListJson`).
  `autoscript` 1.9 never does this (its `fileid` URI has only `fileid`,
  `rtservlet`, `key`).

### C.4 Posting the result (`op=put`)

- **POST** to `stservlet`, body `op=put&v=1_0&id=<id>&dat=<payload>`; the payload
  is appended raw (`launch:IntermediateServerUtil#sendData`).
- The storage servlet splits the body on `&` and the first `=`, and **URL-decodes
  `dat`** (`storage:StorageService#service/#storeSign`), so payload characters
  `+` and `%` must not appear raw. AutoFirma's payloads are URL-safe Base64,
  `|`, `.`, `#WAIT`, `OK`, `CANCEL`, or URL-encoded error strings.
- Answer `OK` (no newline) on success, else `ERR-…`; AutoFirma ignores the body.
  If the POST fails → `SAF_11` dialog.
- The servlet also accepts GET with the same parameters and `op=check`
  (GET → `OK`).
- One file per id; a later `put` overwrites (this is how `#WAIT` is replaced by
  the result).
- Sends are serialised (one at a time) so a `#WAIT` cannot overwrite the result
  (`launch:IntermediateServerUtil#getUniqueSemaphoreInstance`); sending the
  result first stops the waiting thread.

### C.5 DES cipher: exact layout

Algorithm (`simple:crypto/DesCipher`, `simple:crypto/CypherDataManager`,
`simple:crypto/NativeDataCipher`; jar confirms `DES/ECB/NoPadding`):

- Cipher: **single DES, ECB mode, no padding scheme** (56-bit effective key).
- Key: the 8 characters of `key` converted to bytes with the platform default
  charset (ASCII digits in practice) used directly as the 8-byte DES key; parity
  bits are not checked.
- Encrypt one item `x`:
  1. `N = (8 − len(x) mod 8) mod 8` (0…7).
  2. Append `N` zero bytes.
  3. DES-ECB encrypt.
  4. Output text: decimal `N`, a dot, then URL-safe Base64 **with** `=` padding
     of the ciphertext: `N.b64u(C)`.
- Decrypt (what AutoFirma accepts): replace `_`→`/`, `-`→`+`; if a `.` is
  present, `N` = integer before the first `.` and the rest is the Base64; if no
  `.`, `N = 0` and the whole text is Base64; Base64-decode (whitespace ignored),
  DES-ECB decrypt, drop the last `N` bytes.
- Each `|`-separated element is encrypted **independently** (same key, ECB, no
  IV), so equal 8-byte blocks give equal ciphertext blocks. The upload from the
  page (XML) is one item.
- Test vector (computed with OpenSSL and Go): key `12345678`, plaintext `hi` →
  `6.B1abIF3v_Do=`.

Page side (`autoscript`, `cipher`/`decipher` with the bundled DES of Paul
Tero, `Cipher.des(key, msg, encrypt, mode=0 (ECB), iv=null, padding=null)`):
the page pads with zero bytes the same way and sends `N.` + URL-safe Base64.
When **deciphering**, `autoscript` drops `N` bytes plus **8 more bytes for the
last element** (`intermediate=false`): the retrieve servlet appends a newline,
the page's Base64 decoder turns it into one stray byte, and its DES loop then
emits one extra block, which those 8 bytes remove. A test server must therefore
reproduce the trailing newline of `RetrieveService`, or pages will lose the last
8 bytes. Clients never see this quirk.

Security note (for ADR-0013): DES-ECB with a key of 10⁸ possible decimal values
offers no confidentiality against anyone who sees the ciphertext; the servlets
are reachable by anyone who learns the 20-character id. `trebaruna` must show
this to the user.

### C.6 Active waiting

With `aw=true` and intermediate mode, right after parsing (before any dialog)
AutoFirma starts a thread that posts `dat=#WAIT` to `stservlet` under the
session id, then sleeps **10 000 ms**, repeating until the result is sent
(`launch:ActiveWaitingThread`). The page polls every **3 000 ms** (4 000 ms on
mobile) and gives up after **10** polls (15 on mobile) without news; every
`#wait` read (case-insensitive prefix) resets the counter, and `ERR-06` means
"nothing yet" (`autoscript`, `WAITING_CYCLE_MILLIS`, `NUM_MAX_ITERATIONS`,
`successResponseFunction`). Hence without `#WAIT` the user has ≈ 30–33 s to
finish; with it, unlimited. Because the storage file expires after 60 s by
default, the 10 s refresh also keeps the slot alive.

### C.7 Limits

| Limit | Value | Source |
|---|---|---|
| URI length before `autoscript` switches to upload | 2000 characters | `autoscript` `MAX_LONG_GENERAL_URL` |
| `fileid` URI too long even after upload | error in page | `sendDataAndExecAppIntent` |
| Session id | ≤ 20 alphanumerics | [A.5](#a5-parameters-common-to-all-operations) |
| Storage max size | `maxFileSize`, default 0 = unlimited; over → `ERR-07` stored | `storage:StorageConfig` |
| Storage/retrieve expiry | `expTime`, default 60 s | `StorageConfig`, `RetrieveConfig` |
| Reads per stored item | one (deleted after read) | `RetrieveService#retrieveSign` |
| Chunking | none in this mode | — |

### C.8 AES envelope (1.9.1 / `autoscript` 1.10 only)

`autoscript` 1.10 in a secure context sends, besides `key`, a parameter
`cipher` = Base64 of JSON `{"algo":"AES","key":<b64 32 bytes>,"iv":<b64 16 bytes>,"legDes":<8 digits>}`
and, for uploaded requests, adds `rid` (=session id) and `stservlet` to the
`fileid` URI (`master` `autoscript`, `executeWithAdvancedCipher`, `initProcess`,
`buildUrlWithoutData`, `cipherAndSendData`). The uploaded XML is then
**AES-256-CBC/PKCS#7 with that IV**, sent as URL-safe Base64 *without* the `N.`
prefix. AutoFirma 1.9.1 reads `cipher` (adds the DES key under the JSON name
`legacydes`), encrypts each result element with AES-CBC using the **same IV for
every element**, output URL-safe Base64, and falls back to DES when AES
decryption fails (`master` `afirma-crypto-cipher2/.../AesServerCipher.java`,
`DesServerCipher.java`, `ServerCipherFactory.java`, `proto:UrlParameters#setCommonParameters`).
AutoFirma 1.9.0 ignores `cipher`; it would try to DES-decrypt an AES upload and
fail with `SAF_03`/`SAF_15` (UNCERTAIN: observed only by reading code). Results
encrypted with DES are still understood by `autoscript` 1.10 (it falls back to
`legDes`). Other new 1.9.1 parameters: `servicetimeout` (read timeout for
services), `dlgload` (page-side only). AutoFirma 1.9.1 does not appear to read
`rid` (UNCERTAIN).

### C.9 Notes for a test server

Mimic exactly: POST/GET handling, `op`/`v`/`id`/`dat`, `URLDecoder` on `dat`,
`println` (trailing newline) on retrieval, `print` (no newline) on storage
success, one-shot read, 60 s expiry, `Access-Control-Allow-Origin: *`,
`Content-Type: text/plain; charset=utf-8`.

---

## D. Local channels: WebSocket and the legacy socket

### D.1 WebSocket channel

Launch (`autoscript` `AppAfirmaWebSocketClient.openNativeApp`;
`launch:ProtocolInvocationLauncher` websocket branch):

```
afirma://websocket?ports=P1,P2,P3&v=4&jvc=3&idsession=S
```

- `autoscript` 1.8–1.10 picks **3 distinct random ports** in 49152–65535
  (or in the range the site set with `setPortRange`; 1 or 2 ports if the range is
  that small) and a 20-character `idsession` (`AfirmaUtils.getRandomPorts`,
  `generateNewIdSession`). `autoscript` 1.7 used `afirma://websocket?v=3&idsession=S`
  with the fixed port **63117**.
- AutoFirma tries the ports **in the given order** and binds the first that
  works, on all interfaces (`new InetSocketAddress(port)`, reuse-address on)
  (`launch:AfirmaWebSocketServerManager#startService`,
  `launch:AfirmaWebSocketServer`). None bindable → `SAF_45` dialog and exit.
  `v` not 3 or 4 → `SAF_21` dialog and exit. The bound port is **not announced**:
  the page simply tries all three.
- Transport is **always TLS** (`wss://`): the server socket factory is built
  from `autofirma.pfx` ([D.3](#d3-the-tls-certificate-autofirma-installs));
  `SSLContext` protocol name `TLSv1` (`launch:SecureSocketUtils`). There is no
  plain `ws://` mode in AutoFirma 1.7–1.9.1, and `autoscript` hard-codes
  `wss://127.0.0.1:` in every version checked (1.7.1, 1.8, 1.9, 1.10).
- Library: Java-WebSocket; no Origin check in the handshake
  (`AfirmaWebSocketServer` does not override the handshake hook).

Page behaviour (`autoscript`, `execAppIntent`, `waitAppAndProcessRequest`,
`createWebSocket`, `processRequest`, `sendEcho`, `onMessageEchoFunction`):

1. Navigate to the launch URI; wait 3000 ms; then every
   `AUTOFIRMA_LAUNCHING_TIME` = 2000 ms try `new WebSocket("wss://127.0.0.1:"+port)`
   on each port, up to `AUTOFIRMA_CONNECTION_RETRIES` = 15 rounds.
2. On open, send the echo text `echo=-idsession=S@EOF`.
3. Any answer to the echo triggers sending the **operation URI** as one text
   message, e.g.
   `afirma://sign?op=sign&idsession=S&algorithm=SHA256withRSA&format=CAdES&properties=<b64u>&ksb64=<b64u>&sticky=false&appname=<host>&dat=<b64u>`.
   Parameter values are `encodeURIComponent`-ed except `dat`, `properties`,
   `ksb64` which are URL-safe Base64 sent raw (`createKeyValuePair` with
   `avoidEncoding`). `mcv` is prepended when the site set a minimum version.
4. The next message received is the result, processed by type ([B.1](#b1-success-payloads)).
   Further operations reuse the open socket (echo then URI again).
5. If the socket closes, the page reports
   `java.lang.InterruptedException` "Autofirma se ha cerrado…".

Server behaviour, protocol 4 (`launch:AfirmaWebSocketServerV4#onMessage`):

- Peer address must be exactly `127.0.0.1` (IPv6 `::1` is rejected) →
  otherwise answer `SAF_47: …`.
- If an `idsession` was accepted at launch, the message must carry it: the
  text after the first `idsession=` up to the next `&`, or to the end with a
  trailing `@EOF` removed → otherwise `SAF_46: …`. This applies to echo and
  operation messages.
- Message starting with `echo=` → answer `OK`.
- Anything else → executed as an operation URI with protocol version 4 and
  "by socket" semantics (no `stservlet`, results returned directly); the answer
  is the result string. Before executing, the connection-lost timeout (ping) is
  set to **60 s**, or **240 s** for `afirma://batch?`/`afirma://batch/?`.
- Only one result per request; operations are processed synchronously on the
  socket thread.

Protocol 3 server (`launch:AfirmaWebSocketServer#onMessage`): same but **no**
peer-address or session checks, and operations use their own `ver`.

Lifecycle: the first client connection is remembered; when it closes, AutoFirma
exits (`halt(0)`) (`AfirmaWebSocketServer#onClose`). A JVM shutdown hook stops
the server.

Protocol 4.1 (1.9.1 with `autoscript` 1.10, `jvc>3`): operations run
asynchronously — the server answers `#wait`; the page then sends
`getresult?idsession=S` and gets `#wait` again or the final result
(`master` `launch:WebSocketServerOperationHandler`,
`launch:AfirmaWebSocketServerV4Sup`; `autoscript` 1.10 `processResponse`).
1.9.1 also closes the socket if no first request arrives within an inactivity
period (`initInactivityCountdown`; duration UNCERTAIN). A 1.9.0-style
synchronous answer is accepted by `autoscript` 1.10.

### D.2 Legacy socket channel (`service`)

Launch: `afirma://service?ports=P1,P2,P3&v=1&jvc=3&idsession=S`
(`autoscript` `AppAfirmaJSSocket.openNativeApp`; versions 1, 2, 3 accepted,
`launch:ServiceInvocationManager`). Used by `autoscript` only for Internet
Explorer 11 and Firefox ≤ 60 class browsers.

Server (`launch:ServiceInvocationManager`, `launch:CommandProcessorThread`):

- TLS server socket (`autofirma.pfx`, `TLSv1` context) on the first bindable
  port; cipher suites limited to a fixed list of TLS 1.2-and-older suites (no
  TLS 1.3, for old Chrome compatibility).
- Each connection is read until the marker `@EOF`; the text just before it
  (after `idsession=`) must equal the launch `idsession` (if one was accepted) →
  otherwise `SAF_03: …`. Peer must be `127.0.0.1`, `0:0:0:0:0:0:0:1` or
  `localhost`, else the socket is closed silently.
- The raw request is an HTTP POST from the page to `https://127.0.0.1:<port>/afirma`
  (`Content-type: application/x-www-form-urlencoded`); AutoFirma ignores the
  HTTP framing and searches the text for a command: `cmd=`, `echo=`,
  `fragment=`, `firm=`, `send=` (first one found in that order).
- Answer: `HTTP/1.1 200 OK\n` + headers `Connection: close`, `Pragma: no-cache`,
  `Server: Cliente @firma`, `Content-Type: text/html; charset=utf-8`,
  `Access-Control-Allow-Origin: *`, empty line, then **URL-safe Base64 of the
  UTF-8 answer**. (Lines end with `\n`; the error variant omits the newline after
  the status line.)

Commands (page side in `autoscript` `AppAfirmaJSSocket`):

| Page sends | Meaning | Answer (before Base64) |
|---|---|---|
| `echo=-idsession=S@EOF` | ping; `-` also resets fragment buffers | `OK` |
| `cmd=<b64u(URI)>idsession=S@EOF` | whole operation URI (must start `afirma://`, not `afirma://service`) | `save` → `SAVE_OK`/`CANCEL`; others → number of response parts (decimal) |
| `fragment=@i@n@<b64u(part)>idsession=S@EOF` | part `i` of `n` of a long URI | `MORE_DATA_NEED`, or `OK` after the last |
| `firm=idsession=S@EOF` | execute the reassembled URI | as for `cmd=` |
| `send=@i@n idsession=S@EOF` | fetch response part `i` of `n` | the part |

- Page splits URIs longer than 12 000 (IE), 458 752 (Firefox) or 1 048 576
  (others) characters (`URL_MAX_SIZE`). AutoFirma splits responses into parts of
  **1 000 000 characters** (`RESPONSE_MAX_SIZE`).
- Inactivity timeout **90 s** → AutoFirma exits; the timer stops while an
  operation runs.
- Out-of-memory → answer `MEMORY_ERROR`.

### D.3 The TLS certificate AutoFirma installs

At installation the configurator generates, per machine
(`afirma-ui-simple-configurator/.../CertUtil.java`, `ConfiguratorLinux.java`):

- a CA `CN=Autofirma ROOT`, RSA 2048, SHA256withRSA, ~10 years, basic
  constraints CA:true;
- a server certificate for `127.0.0.1` (SAN: IP `127.0.0.1`, DNS `localhost`),
  RSA 2048, CA:false, ~10 years, signed by that CA;
- `autofirma.pfx` (PKCS#12, password `654321`, in the application directory or
  `~/.afirma/Autofirma`) holding the server key and chain
  (`launch:SecureSocketUtils`; jar confirms `autofirma.pfx`, `654321`);
- `Autofirma_ROOT.cer`, which install scripts import into the system and Firefox
  NSS trust stores as a trusted root.

### D.4 Channels without a root CA (ADR-0013)

| Channel | Needs a browser-trusted cert for `127.0.0.1`? | Usable by `trebaruna` without installing a CA |
|---|---|---|
| Intermediate server | no (only outbound HTTPS to the site) | **yes** — the only path that works as is |
| WebSocket v3/v4/4.1 | yes (`wss://127.0.0.1:port`, hard-coded) | no |
| Legacy socket | yes (`https://127.0.0.1:port/afirma`) | no |

- No `ws://` or plain-HTTP variant exists in any AutoFirma or `autoscript`
  version examined (1.7.1 → 1.10.1).
- A certificate for the IP `127.0.0.1` cannot be obtained from a public CA, so
  WebSocket needs a locally trusted certificate.
- The page decides the channel; `trebaruna` cannot force intermediate mode.
  Sites that call `AutoScript.setForceWSMode(true)` (field evidence:
  [G.2](#g2-what-sites-send-field-evidence)) or mobile user agents use it; most
  desktop pages default to WebSocket.
- Possible CA-free workarounds, all UNCERTAIN: (a) trust the self-signed
  *leaf* certificate as a peer (NSS trust flag `P`) instead of a root — still a
  trust-store change; (b) per-site certificate exception in Firefox — impractical
  because the port is random per launch unless the site fixes the port range;
  (c) Chrome's interstitial bypass does not apply to WebSocket connections.
- trebaruna (ADR-0019, proposed): a per-user root whose private key is
  destroyed once it has signed the certificate for `127.0.0.1`, with critical
  name constraints to `127.0.0.1` and `localhost`, installed in the user's NSS
  stores on request (`trebaruna afirma local-tls install`, or the window). The
  WebSocket server binds `127.0.0.1` only, speaks protocols 3, 4 and 4.1,
  checks the session id and answers each operation as from the intermediate
  server, approved by the person. Checked with headless Chromium trusting the
  root through its NSS store: the echo and a CAdES signature come back, which
  openssl verifies; without the root the connection fails.
- Recent Chromium versions ask the person, the first time, to let a site reach
  devices on the local network ("Local Network Access"), which includes
  `127.0.0.1`; the same applies to AutoFirma.

---

## E. Batch signing and the triphase protocol

### E.1 Invocation

`afirma://batch?…` with the parameters of [A.6](#batch-protourlparametersforbatch).
Example from `autoscript` 1.9 (intermediate, JSON):
`ver=3&op=batch&id=I&key=K&keystore=MOZ_UNI&ksb64=…&stservlet=S&batchpresignerurl=PRE&batchpostsignerurl=POST&aw=true&appname=…&properties=<filters>&needcert=true&jsonbatch=true&dat=<b64 JSON>`
(`autoscript` `signBatchJSON`; matches the log in [G.2](#g2-what-sites-send-field-evidence)).
WebSocket form adds `idsession` and sends `properties`/`ksb64`/`dat` URL-safe.

AutoFirma flow (`launch:ProtocolInvocationLauncherBatch`): choose keystore →
certificate dialog with the filters from `properties` (sticky honoured) →
`signBatch` → wrong PIN restarts with the same certificate → encode the result
([B.1](#b1-success-payloads)) → post to `stservlet` if present.

### E.2 Batch definitions (page → client → pre-signer, opaque to the client)

**JSON** (AutoFirma ≥ 1.8; parsed server side by `bserver:json/JSONSignBatch`):

```json
{ "stoponerror": false,
  "algorithm": "SHA256withRSA",          // or SHA256; digest part is what matters
  "format": "CAdES",                     // default for items
  "suboperation": "sign",                // sign | cosign | countersign
  "extraparams": "<b64 properties>",     // default for items
  "singlesigns": [
    { "id": "doc1",
      "datareference": "<server-specific reference or b64>",
      "format": "…", "suboperation": "…", "extraparams": "<b64 properties>" } ] }
```

Item formats accepted by the server: `CAdES`, `CAdES-ASiC-S`, `XAdES`,
`XAdES-ASiC-S`, `PAdES`, `FacturaE`, `NONE` (`bserver:SingleSignConstants`).
The server adds `headless=true` to each item. An item may instead carry
`result`/`description` (already processed). Server limits are configuration
(`batch.maxDocuments`, max request size, max reference size).

**XML** (older; `v1.8` `bserver:xml/SignBatchXmlHandler`):

```xml
<signbatch stoponerror="false" algorithm="SHA256withRSA" concurrenttimeout="…" Id="…">
  <singlesign Id="…">
    <datasource>…</datasource><format>…</format><suboperation>…</suboperation>
    <extraparams>b64</extraparams>
    <signsaver><class>…</class><config>b64</config></signsaver>
  </singlesign>
</signbatch>
```

The client only reads the algorithm: XML root must be `signbatch` with attribute
`algorithm`; JSON must have `algorithm` (`bclient:BatchSigner#getAlgorithmForXML/#getAlgorithmForJSON`).

### E.3 Triphase exchange with the batch services

All calls are **POST** with the query moved to the body
(`bclient:BatchSigner#signJSON/#signXML`). `certs` = the certificate chain,
each URL-safe Base64, joined by `;`. `batch` = the definition re-encoded URL-safe.

| Step | Body | Answer |
|---|---|---|
| pre (JSON) | `json=<b64u batch>&certs=<chain>` | JSON pre-sign result |
| pre (XML) | `xml=<b64u batch>&certs=<chain>` | XML triphase data |
| post (JSON) | `json=<b64u batch'>&certs=<chain>&tridata=<b64u JSON triphase>` | JSON batch result |
| post (XML) | `xml=<b64u batch>&certs=<chain>&tridata=<b64u XML triphase>` | XML batch result |

JSON pre-sign answer (`bclient:JSONPreSignBatchParser`, `bclient:TriphaseDataParser`):

```json
{ "td": { "format": "…",
          "signs": [ { "signinfo": [ { "id": "…", "signid": "…",
                                         "params": { "PRE": "<b64>", "NEED_PRE": "true", … } } ] } ] },
  "results": [ { "id": "doc2", "result": "ERROR_PRE", "description": "…" } ] }
```

(`td` may also be `{"signinfo":[…]}` without `signs`.) If `td` is absent the
client returns `{"signs":[…results…]}` immediately (empty array when both are
absent). If `results` is present, batch' is the original definition with each
failed item stripped of `datareference`/`format`/`suboperation`/`extraparams`
and given `result`/`description` (`bclient:JSONBatchInfo#updateResults`).

JSON `tridata` sent to post: `{"format":"…","signinfo":[{"id":…,"signid":…,"params":{…}}]}`
(`TriphaseDataParser#triphaseDataToJsonString`).

XML triphase data (`core:signers/TriphaseData#parser/#toString`):

```xml
<xml>
 <firmas format="…">
  <firma Id="…" signid="…">
   <param n="PRE">b64</param> …
  </firma>
 </firmas>
</xml>
```

### E.4 The client's signing step

For every `TriSign` (`core:signers/TriphaseDataSigner#doSign`):

1. `PRE` (standard Base64) is mandatory; decode it.
2. Sign those bytes as an ordinary signature input with
   `composeSignatureAlgorithmName(batchAlgorithm, keyType)` — i.e. hash then
   RSA/ECDSA (PKCS#1 v1.5 for RSA), no extra parameters.
3. Add `PK1` = standard Base64 of the signature value.
4. Remove `PRE` unless `NEED_PRE=true`.
5. Keep all other params unchanged.

At least one sign is required (`AOException` → `SAF_27`).

### E.5 Result returned to the page

The post-signer's body, unchanged: JSON
`{"signs":[{"id":"…","result":"DONE_AND_SAVED","description":"…"},…]}` or XML
`<signs><signresult id="…" result="…" description="…"/>…</signs>`.
Result values: `NOT_STARTED`, `DONE_AND_SAVED`, `DONE_BUT_NOT_SAVED_YET`,
`DONE_BUT_SAVED_SKIPPED`, `DONE_BUT_ERROR_SAVING`, `ERROR_PRE`, `ERROR_POST`,
`SKIPPED`, `SAVE_ROLLBACKED` (`bclient:BatchDataResult.Result`). The signatures
themselves stay on the server (saved by its document manager).
`autoscript` tries `JSON.parse` on the decoded result and passes `(result, certificate)`
to the page.

### E.6 Local batch (`localBatchProcess=true`, JSON only)

No services; AutoFirma signs each item itself (`launch:JSONBatchManager`,
`launch:LocalBatchSigner`): top-level `format` and `algorithm` are mandatory,
`suboperation` defaults to `sign`; each item needs `id` and `datareference` =
**Base64 of the data to sign**; `extraparams` is Base64 of properties where
literal `\n` sequences are turned into newlines; `headless=true` is added.
Result: `{"signs":[{"id":…,"result":"DONE_AND_SAVED"|"ERROR_PRE"|"SKIPPED","description":…,"signature":"<b64>"}]}`;
with `stoponerror=true` the remaining items become `SKIPPED`.

### E.7 Errors in batch

`HttpError` 400 → `SAF_03`; other 4xx → `SAF_26`; 5xx → `SAF_27`; other
`AOException` → `SAF_27`; other failures → `SAF_27` (server) or `SAF_20`
(local); locked token → `SAF_52`; wrong PIN → retry
(`launch:ProtocolInvocationLauncherBatch#sign`).

### E.8 Single-signature triphase formats

Used by `sign`/`cosign`/`countersign` when the page asks for a `…tri` format
(`afirma-crypto-cadestri-client/.../AOCAdESTriPhaseSigner.java`, `PreSigner.java`,
`PostSigner.java`, `ProtocolConstants.java`; other families analogous):

- `properties` must contain `serverUrl`; `dat` is the **document id** (bytes),
  sent URL-safe Base64 as `doc`.
- pre: POST `serverUrl` with `op=pre&cop=<sign|cosign|countersign>&format=<CAdES|…>&algo=<algorithm>&cert=<chain>&doc=<docid>[&params=<b64u properties>]`;
  `cert` = URL-safe Base64 certificates joined by `,` (only the signer's if
  `includeOnlySignningCertificate=true`); `serverUrl` and `documentId` are removed
  from `params`.
- Answer: URL-safe Base64 of XML triphase data, or text starting `ERR-`
  (`ERR-21:` = needs user confirmation).
- Client computes `PK1` as in [E.4](#e4-the-clients-signing-step).
- post: POST with `op=post&cop=…&format=…&algo=…&cert=…[&params=…]&session=<b64u XML triphase with PK1>&doc=<docid>`.
- Answer: `OK NEWID=<b64u new id>`; the decoded new id is the "signature"
  returned to the page. Anything else → error (`SAF_40` family).

trebaruna does this after the person approves: the body as above, written in that
order without percent-encoding as AutoFirma's client does; an `ERR-…` or any
answer but `OK NEWID=` is `SAF_26` with the server's text, a missing `serverUrl`
`SAF_03`. Each connection is listed with the signature's report.

---

## F. Signature policies

### F.1 AGE policy expansion (`expPolicy`)

Values in AutoFirma 1.9 (`afirma-core/src/main/resources/policy.properties`,
identical in the 1.9.0 jar; logic in `core:signers/ExtraParamsProcessor` and
`core:signers/AdESPolicyPropertiesManager`):

| Set | `policyIdentifier` | `policyIdentifierHashAlgorithm` | `policyIdentifierHash` | `policyQualifier` |
|---|---|---|---|---|
| `FirmaAGE` (= v1.9, default) | `urn:oid:2.16.724.1.3.1.1.2.1.9` | `http://www.w3.org/2000/09/xmldsig#sha1` | `G7roucf600+f03r/o0bAOQ6WAs0=` (CAdES, XAdES, PAdES) | `https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf` |
| `FirmaAGE19` | same as `FirmaAGE` | same | same | same |
| `FirmaAGE18` | `urn:oid:2.16.724.1.3.1.1.2.1.8` | `http://www.w3.org/2000/09/xmldsig#sha1` | XAdES `V8lVVNGDCPen6VELRD1Ja8HARFk=`; CAdES/PAdES `7SxX3erFuH31TvAw9LZ70N7p1vA=` | `https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf` |

Expansion rules (`ExtraParamsProcessor#expandPolicyKeys`):

- Only `expPolicy=FirmaAGE` or `FirmaAGE18` are accepted; **`FirmaAGE19` is in
  the file but rejected** (`SAF_23`). The key is removed after expansion.
- Formats are normalised: `CAdES`/`CAdEStri` → CAdES; `XAdES`/`XAdEStri`/any
  `XAdES <variant>` → XAdES; `Adobe PDF`, `PAdES`, `PAdEStri`,
  `Adobe PDF TriPhase` → PAdES. Others → `SAF_23`.
- CAdES: if `mode` is not set and data are known, `mode=implicit` when data
  < 1 MiB, else `explicit`; `profile=advanced` forced.
- XAdES: property `format` forced to `XAdES Detached` unless it is
  `XAdES Detached` or `XAdES Enveloped`; `profile=advanced` forced.
- PAdES: only `FirmaAGE`; `signatureSubFilter` must be absent or
  `ETSI.CAdES.detached` (else `SAF_23`) and is set to it.
- Then the four policy keys above are set (no `policyDescription` exists in the
  file).

### F.2 Explicit policy parameters

When a page passes `policyIdentifier` directly (`core:signers/AdESPolicy`):
if `policyIdentifierHash` is absent or `0`, AutoFirma **downloads** the
identifier as a URL and hashes it (algorithm from
`policyIdentifierHashAlgorithm` or the default); otherwise
`policyIdentifierHashAlgorithm` is mandatory and the hash must look like Base64;
`policyQualifier`, if present, must be a valid URL. Hash-algorithm names are
normalised (`SHA1`, `SHA-256`, XMLDSig URIs…) via
`AOSignConstants#getDigestAlgorithmName` (exact accepted spellings: UNCERTAIN).

### F.3 FacturaE

`afirma-crypto-xades/.../AOFacturaESigner.java` (constants confirmed in the 1.9.0
jar):

| Policy | Identifier | Hash (SHA1, Base64) |
|---|---|---|
| FacturaE 3.1 (**default**) | `http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf` | `Ohixl6upD6av8N7pEvDABhEL6hM=` |
| FacturaE 3.0 | `http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf` (with spaces) | `xmfh8D/Ec/hHeE1IB4zPd61zHIY=` |

- Hash algorithm given as `SHA1`; no qualifier.
- If the page sets a policy, it must equal 3.0 or 3.1 (identifier, hash,
  algorithm, qualifier) or the signer rejects it; if absent, 3.1 is applied.
- There is **no separate "3.2" policy** in AutoFirma: FacturaE 3.2.x invoices are
  signed with policy 3.1 (UNCERTAIN whether any site expects another
  identifier).
- Forced: `format=XAdES Enveloped`, `facturaeSign=true`; `signerClaimedRoles`
  default `emisor`, allowed `emisor`, `receptor`, `tercero`, `supplier`,
  `customer`, `third party` (case-insensitive); only a whitelist of extraParams
  passes (production place, namespace, signed-properties type, policy keys,
  claimed roles, batch signature id).

---

## G. Version history and what sites send

### G.1 Timeline

| Version | Change relevant to the protocol | Evidence |
|---|---|---|
| AutoFirma ≤ 1.4 pages | plain `keystore` parameter (still accepted) | comment in `proto:UrlParameters` |
| `autoscript` 1.7 | WebSocket v3, fixed port 63117, `afirma://websocket?v=3&idsession=`; legacy socket v1; intermediate `ver=3`; no `jvc` | `v1.7.1` autoscript |
| `autoscript` 1.8 (`jvc=2`) | WebSocket **v4**: random ports, `ports=`, session and loopback checks; JSON batch (`jsonbatch`, `localBatchProcess`), `mcv`; `log` operation still in the WS client | `v1.8` autoscript |
| AutoFirma/`autoscript` 1.9.0 (`jvc=3`) | `appname`; `log` removed (`SAF_04`); errors up to `SAF_52`; max operation version 4 | `v1.9` tag, local jar |
| AutoFirma 1.9.1 / `autoscript` 1.10.1 (`jvc=4`, tag `v1.9.1`, 2026-04) | protocol **4.1** (when `v=4`, `jvc>3`): async WebSocket (`#wait`, `getresult?idsession=`), `err-00:=AF…` errors, AES `cipher`, `servicetimeout`, `rid`, intermediate `ver=4` | `v1.9.1`/`master` |
| AutoFirma 1.9.2 (tag `v1.9.2`, 2026-05) | macOS fixes on the 1.9.0 line; no 4.1 | `v1.9.2` tag |

### G.2 What sites send (field evidence)

Two invocations in the local AutoFirma 1.9 log (2026-10-16), both from the
Seguridad Social "Sistema RED" office (`sede.red.gob.es`), redacted:

- `afirma://batch?jvc=3&ver=3&op=batch&id=<20>&key=<8>&keystore=MOZ_UNI&ksb64=<MOZ_UNI>&stservlet=…&batchpresignerurl=…&batchpostsignerurl=…&aw=true&appname=<15>&properties=…&needcert=true&jsonbatch=true&dat=…`
  — URI length 1437, so inline (no upload).
- So: `autoscript` 1.9.0, **intermediate server forced** (`ver=3` with
  `stservlet`), on a Linux desktop Firefox-type keystore (`MOZ_UNI`).
- Servlet paths: `/oficina/clientsigner/StorageService/service/<token>`,
  `/oficina/clientsigner/JSONBatchPresigner/service/<token>`,
  `/oficina/clientsigner/JSONBatchPostsigner/service/<token>` (session token in
  the path, no query).
- `properties`: `filters.1` and `filters.2`, each a `subject.rfc2254:` filter.
- Batch JSON: `algorithm=SHA256withRSA`, `format=CAdES`, `suboperation=sign`,
  `stoponerror=false`, one item with `datareference` of 44 characters (Base64 of a
  32-byte SHA-256 digest) and item `extraparams` keys `mode=explicit`,
  `precalculatedHashAlgorithm=SHA-256`, `signSaver` (server-side).
- AutoFirma posted the batch result to the storage servlet ~7–10 s after the
  certificate dialog opened.

### G.3 Consequences for `trebaruna`

- Implementing the 1.9.0 behaviour (protocol 4, DES, synchronous WebSocket,
  `SAF_NN` errors) is enough for both `autoscript` 1.9 and 1.10 pages, **except**
  `autoscript` 1.10 intermediate uploads in secure contexts, which are AES
  ([C.8](#c8-aes-envelope-191--autoscript-110-only)); supporting the `cipher`
  parameter covers those.
- Without a local trusted certificate only intermediate-mode sites work
  ([D.4](#d4-channels-without-a-root-ca-adr-0013)).
- The page's identity is weakly known: `appname` (self-declared), the servlet
  host, and, on WebSocket, the handshake `Origin` header (AutoFirma does not check
  it, `trebaruna` can show it).

---

## Open questions

All items marked UNCERTAIN above:

1. Whether standard-Base64 `properties` values inside the intermediate XML are
   corrupted in practice by AutoFirma's URL-decoding (`+` → space) ([C.3](#c3-the-request-envelope-xml)).
2. Which SAF code results from `signandsave` with a missing or unknown `cop`
   ([A.6](#signandsave-protourlparameterstosignandsave)).
3. Whether `SAF_07`, `SAF_10`, `SAF_22`, `SAF_48`, `SAF_49` can still be emitted
   through paths outside `afirma-simple/.../standalone` ([B.3](#b3-error-format-19)).
4. AutoFirma 1.9.0's exact failure when an `autoscript` 1.10 page uploads an
   AES-encrypted request (`SAF_03` vs `SAF_15`), and whether 1.9.1 uses `rid`
   ([C.8](#c8-aes-envelope-191--autoscript-110-only)).
5. Duration of the 1.9.1 WebSocket inactivity countdown ([D.1](#d1-websocket-channel)).
6. Which TLS versions the `TLSv1`-named `SSLContext` actually negotiates as a
   server on current JDKs ([D.1](#d1-websocket-channel)).
7. CA-free WebSocket workarounds: NSS peer trust of a self-signed leaf in Firefox
   and Chrome on Linux; per-port Firefox exceptions ([D.4](#d4-channels-without-a-root-ca-adr-0013)).
8. Exact spellings accepted for `policyIdentifierHashAlgorithm`
   (`getDigestAlgorithmName`) ([F.2](#f2-explicit-policy-parameters)).
9. Whether any site expects a FacturaE policy identifier other than 3.0/3.1 for
   FacturaE 3.2.x ([F.3](#f3-facturae)).
10. Which AutoFirma version `trebaruna` should report against `mcv`
    (`1.9` makes pages that require `1.9.1` fail with `SAF_41`) ([A.10](#a10-version-parameters)).
11. The field evidence covers one site and one operation (JSON batch over the
    intermediate server); WebSocket invocations from real sites have not been
    observed locally.
