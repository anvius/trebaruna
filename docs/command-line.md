# Command line

Every command, every flag, and what the exit codes mean.

- [Shape of the tool](#shape-of-the-tool)
- [Exit codes](#exit-codes)
- [`sign`](#sign)
- [`verify`](#verify)
- [`timestamp`](#timestamp)
- [`verify-tsr`](#verify-tsr)
- [`certificate`](#certificate)
- [`trust`](#trust)
- [`asic`](#asic)
- [`serve`](#serve)
- [`handler`](#handler)
- [`requests` and `decide`](#requests-and-decide)
- [`version`](#version)
- [Global behaviour](#global-behaviour)

---

## Shape of the tool

```
trebaruna <command> [arguments] [flags]
```

Flags may appear before or after the positional argument:
`trebaruna sign doc.pdf --p12 k.p12` and `trebaruna sign --p12 k.p12 doc.pdf` are
the same. This matters because Go's flag parser normally stops at the first
non-flag argument, and every CLI convention (and every script) writes the file
first.

---

## Exit codes

Stable, and part of the contract with scripts:

| Code | Meaning |
|---|---|
| `0` | Success. For `verify`: verified. |
| `1` | For `verify`: the file was altered. For other commands: the operation failed. |
| `4` | For `verify`: the signer was not entitled to sign when they did — the certificate had expired, had not started, or was already revoked. The document itself is intact. |
| `2` | Usage error: unknown flag, missing argument, malformed value. |
| `3` | For `verify`: could not verify. Unknown issuer, no trust list, unreadable file. Not the same as "bad". |

The distinction between these codes is deliberate, and it is not cosmetic:

| Code | What it is a claim about | The right response |
|---|---|---|
| `1` | **The document or the signature was altered.** Someone changed the bytes. | Reject the document outright. |
| `4` | **The signer was not entitled to sign at that moment.** The bytes are untouched. | Ask for a fresh signature; do not accuse anyone of tampering. |
| `3` | **We cannot tell.** | Retry, sync the trust list, or route to a human. |

`1` and `3` differing matters because a script that treats them the same rejects
legitimate documents when a trust list is stale. `1` and `4` differing matters
more: conflating them makes the tool accuse a signer of tampering with a document
that is byte-for-byte intact. Both return a non-zero exit, so a script that only
knows pass/fail is already correct; the finer routing is there for the ones that
want to act differently on each.

```bash
if trebaruna verify "$f" --json >/dev/null; then
    echo "verified"
else
    case $? in
        1) echo "REJECTED: the document or signature was altered" ;;
        4) echo "NEEDS RESIGNING: the signer had no entitlement when they signed" ;;
        3) echo "UNKNOWN: could not verify (network, trust list, format)" ;;
    esac
fi
```

---

## `sign`

```
trebaruna sign <document> [flags]
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--format` | from the suffix | `cades`, `pades`, `xades` or `xmldsig` (plain XML-Signature: level B, no policy) |
| `--level` | `bes` | `bes`, `t`, `lt` or `lta` — see [Signing](signing.md) |
| `--p12` | — | PKCS#12 file with the certificate and key |
| `--pem` | — | PEM bundle containing certificate and key |
| `--card` | — | Sign with the card in the reader; card and signing certificate are found |
| `--token` | — | PKCS#11 token label (needs `trebaruna-token`) |
| `--certificate` | the signing one | Certificate of the card: serial or SHA-256 fingerprint (8+ digits); finds the card without `--token` |
| `--module` | OpenSC, found on the system | PKCS#11 module path |
| `--firefox` | — | Sign with a certificate of the Firefox store, in place (PIN: the primary password) |
| `--nss-db` | — | Sign with a certificate of this NSS store directory (`~/.pki/nssdb` for Chromium) |
| `--csc` | — | Sign with a key a provider keeps, through its Cloud Signature Consortium API v2 (`https://…/csc/v2`) |
| `--credential` | the only one | The provider's credential to sign with |
| `--pin` | — | Smartcard PIN |
| `--pass` | — | Passphrase for the P12 or PEM |
| `--name` | from the certificate | Signer name recorded in the signature |
| `--reason` | — | Reason for signing, shown in PDF viewers |
| `--location` | — | Location of signing, shown in PDF viewers |
| `--tsa` | — | RFC 3161 timestamp authority URL |
| `--tsa-user`, `--tsa-pass` | — | Basic auth for the TSA, when it needs an account |
| `--online-revocation` | off | Query OCSP and embed the answers in `/DSS`; required for `--level lt` and `lta` |
| `--page` | `1` | Page for the visible seal |
| `--box` | — | Seal box `x1,y1,x2,y2` in PDF points; repeatable, `PAGE:x1,y1,x2,y2` to pick a page |
| `--out` | convention | Output path |
| `--enveloping` | off | XAdES enveloping rather than enveloped: the document inside the signature; any file |
| `--invisible` | off | PAdES without a visible seal; excludes `--box` |
| `--detached` | off | The signature beside the untouched document: `<document>.p7s` (CAdES) or `<document>.xsig` (XAdES) |
| `--cosign` | off | Add a parallel signature to the `.p7m`/`.p7s` given as document |
| `--countersign` | — | Counter-sign the envelope's signatures: `leaves` or `all` |
| `--content` | — | The document a detached `.p7s` signs, to co-sign it |
| `--asic` | — | `s`: the document and its detached signature in an ASiC-S container, `<document>.asics`; `e`: every document given under one signature, an ASiC-E container, `<first document>.asice` or `--out` |
| `--policy` | — | Signature policy (EPES) by name: `age` (AGE 1.9), `age18`, `facturae` (3.1), `facturae30` |
| `--policy-id` | — | A policy by its parts: identifier, an OID (`urn:oid:` optional) or, for XAdES, a URL |
| `--policy-hash` | — | Its document's digest, Base64; required with `--policy-id` |
| `--policy-hash-alg` | `SHA1` | `SHA1`, `SHA-256`, `SHA-384`, `SHA-512` or the XMLDSig URI |
| `--policy-qualifier` | — | URL of the policy document, written into the signature |
| `--role` | — | Role the signer claims, XAdES only (`SignerRoleV2`); FacturaE: `emisor` unless given |
| `--json` | off | Machine-readable result |

#### Connections in the result

Every `--json` result of `sign`, `verify` and `timestamp` carries `network`: the
connections the command made, each with its purpose (`timestamp`,
`revocation`, `trust-list`, …), method, destination without credentials or
query values, status and bytes. An offline command says `"network": []`.
Connections opened by a library with its own client are recorded too, marked
`"via": "library"`. Human output lists them under `connections`. See ADR-0010.

#### Secrets without the command line

Any local user can read the command line of any process (`ps -ef`), so a
passphrase given as `--pass` is visible to everyone on the machine while the
command runs. Every secret flag has an environment variable that is used when
the flag is absent; a process's environment is readable only by its owner.

| Flag | Variable |
|---|---|
| `--pass` | `TREBARUNA_PASSPHRASE` |
| `--pin` | `TREBARUNA_PIN` |
| `--tsa-pass` | `TREBARUNA_TSA_PASS` |
| — | `TREBARUNA_CSC_TOKEN`, `TREBARUNA_CSC_USER`, `TREBARUNA_CSC_PASSWORD`, `TREBARUNA_OTP` (remote signing; no flag exists) |

The flag wins when both are present. The desktop app always uses the variables.

```bash
read -rs TREBARUNA_PASSPHRASE && export TREBARUNA_PASSPHRASE
trebaruna sign contratto.pdf --p12 mia-chiave.p12
```

### What it produces

| Format | Output name |
|---|---|
| PAdES | `document_signed.pdf` |
| XAdES | `document_signed.xml` |
| CAdES or XAdES `--detached` | `document.pdf.p7s`, `document.pdf.xsig` |
| CAdES | `document.pdf.p7m` |

Override with `--out`.

### Examples

The common case — a PDF, the simplest signature:

```bash
trebaruna sign contratto.pdf --p12 mia-chiave.p12 --pass segreto
```

An XML invoice with a timestamp:

```bash
trebaruna sign fattura.xml --pem bundle.pem --level t --tsa https://freetsa.org/tsr
```

A PDF with a visible seal in the bottom-left corner, long-term valid:

```bash
trebaruna sign atto.pdf --p12 k.p12 --pass x \
    --level lt --tsa https://freetsa.org/tsr --online-revocation \
    --box 60,60,280,160 --reason "Contratto di fornitura"
```

Two seals on different pages, one signature:

```bash
trebaruna sign atto.pdf --p12 k.p12 --pass x \
    --box 1:60,60,280,160 --box 3:60,60,280,160
```

Any file wrapped in CMS:

```bash
trebaruna sign backup.zip --format cades --pem bundle.pem
```

A request to the Spanish administration under the AGE policy, and a FacturaE
invoice (XAdES enveloped, FacturaE 3.1, role `emisor`):

```bash
trebaruna sign solicitud.pdf.p7m --format cades --policy age --p12 k.p12
trebaruna sign factura.xml --policy facturae --p12 k.p12
```

Sign from a smartcard:

```bash
trebaruna-token sign atto.pdf --card                        # PIN from $TREBARUNA_PIN
trebaruna-token sign atto.pdf --token "Carta Nazionale"
trebaruna-token sign atto.pdf --certificate 4a2b1d          # the card holding it
```

OpenSC is found on its own (`--module` for a vendor driver); see
[smartcards](smartcards.md) for how the card and the certificate are chosen.

### Notes

- **Exactly one key source.** Passing both `--p12` and `--pem` is an error, not a
  preference order.
- **The format follows the suffix** unless you say otherwise. `sign doc.xml`
  produces XAdES; `sign doc.pdf` produces PAdES; anything else becomes CAdES.
  Asking for PAdES on a `.xml` is refused with an explanation rather than
  producing a file that no XML tool can open.
- **A self-signed certificate is accepted** and flagged. The signature is real;
  the identity is unvouched.
- **A policy is a promise, not a lookup.** The digest goes into the signature
  as given or as AutoFirma 1.9 declares it for the named policies; trebaruna
  never downloads a policy document. CAdES and XAdES carry policies; PAdES
  refuses one for now. A policy named by a URL (FacturaE's) fits only XAdES.
- **FacturaE policies sign FacturaE invoices only**: an XML whose root is
  `Facturae`, not signed yet, XAdES enveloped. The role must be one the policy
  names: `emisor`, `receptor`, `tercero` (or `supplier`, `customer`,
  `third party`).

---

## `verify`

```
trebaruna verify <document> [flags]
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--format` | from the suffix | `pdf`, `cades`, `xades` or `asic` |
| `--territory` | from `$LANG` | Trust list to use, e.g. `IT`, `ES`, `EU` |
| `--offline` | `true` | Set `--offline=false` to query OCSP and CRL responders |
| `--lang` | from `$LANG` | `es`, `ca`, `gl`, `eu`, `it` or `en` for human output and the report |
| `--json` | off | Machine-readable report |
| `--report` | — | Also write the verification as a document to keep or send: `<file>.md`, `.html` or `.pdf` |
| `--content` | beside it | The document a detached signature signs |

The report states what was checked and when: the file and its SHA-256, the
verdict, every signature (signer, certificate validity, signing time,
integrity, trust, each finding in the chosen language), the connections
the check made, and the trebaruna version. The three formats say the same.
The PDF is written by trebaruna itself in Helvetica; the HTML is one page
with no scripts and no external resources. The home directory reads as `~`
in any path, because a report is made to be sent.

```bash
trebaruna verify contratto_signed.pdf --report verifica.pdf --lang it
```

### Recognised suffixes

`.pdf` → PAdES · `.p7m`, `.p7s` → CAdES · `.xml`, `.xsig` → XAdES ·
`.asics`, `.asice`, `.scs`, `.sce` → ASiC container

Anything else needs `--format`.

### Examples

```bash
trebaruna verify contratto_signed.pdf
trebaruna verify atto.pdf.p7m --territory IT
trebaruna verify doc.xml --json | jq '.verdict, .signers[].trust'
trebaruna verify atto.pdf --offline=false --json
```

### Reading the output

Human output:

```
  Firma 1 — signature-1
    Firmante       MARIA LOPEZ GARCIA
    Identificador  IDCES-00000000X
    Emisor         Example TSP
    Firmado        2026-11-02 12:52:30 +01:00
    Integridad     correcto
    ! la fecha de firma la declara el firmante y no está sellada
```

The `!` lines are findings, and each has a code in the JSON form. See
[Verification](verification.md) for what every code means.

---

## `timestamp`

```
trebaruna timestamp <file> --tsa <url> [--tsd]
trebaruna timestamp --hash <hex> --tsa <url>
```

Obtains an RFC 3161 token proving a document existed at a moment, and says
whether the authority is a qualified one according to the cached trusted list
of your territory (`qualified`, `qualified_by` in `--json`; offline). With
`--tsd` the document and its token travel together in `<file>.tsd`
(time-stamped data, RFC 5544: what Italian offices keep as
`name.pdf.p7m.tsd`), the file name and media type recorded beside them.

| Flag | Meaning |
|---|---|
| `--tsa` | Timestamp authority URL (required) |
| `--hash` | Timestamp a digest instead of a file |
| `--tsa-user`, `--tsa-pass` | Basic auth, when the authority requires it |
| `--tsd` | Write `<file>.tsd` with the document inside instead of a bare `.tsr` |
| `--out` | Output path, default `<file>.tsr` (or `<file>.tsd`) |
| `--json` | Machine-readable result |

```bash
trebaruna timestamp atto.pdf --tsa https://freetsa.org/tsr
trebaruna timestamp --hash 3a7bd3e2... --tsa https://freetsa.org/tsr --out proof.tsr
```

See [Timestamps](timestamps.md).

---

## `verify-tsr`

```
trebaruna verify-tsr <token.tsr> [document]
trebaruna verify-tsr <document.tsd>
```

Checks a token on its own, or that it matches a document. A `.tsd` carries its
document: every token is checked — the first against the document, each
renewal against the token before it (RFC 5544, section 4.2) — and DER or BER
files are read.

```bash
trebaruna verify-tsr atto.pdf.tsr
trebaruna verify-tsr atto.pdf.tsr atto.pdf     # also check the imprint
trebaruna verify-tsr --hash <hex> proof.tsr
```

| Flag | Meaning |
|---|---|
| `--hash` | Compare against a digest instead of a file |
| `--json` | Machine-readable result |

Exit `0` if the token's signature verifies and its imprint matches, `1` if the
token is invalid, `2` if it cannot be read at all.

---

## `certificate`

```
trebaruna certificate <file> [flags]
```

Reads a certificate without signing anything.

```bash
trebaruna certificate mia-chiave.p12 --pass segreto
trebaruna certificate bundle.pem --json
trebaruna certificate certificate.cer --territory IT
```

| Flag | Meaning |
|---|---|
| `--pass` | Passphrase for the P12/PEM |
| `--territory` | Check the issuer against a trust list |
| `--json` | Machine-readable output |

Accepts `.p12`, `.pfx`, `.pem`, `.crt`, `.cer`. See
[Certificates](certificates.md).

---

## `trust`

```
trebaruna trust sync  [--territory XX]
trebaruna trust list
trebaruna trust show <territory>
trebaruna trust tsa  [<territory>] [--json]
```

Downloads and **authenticates** the EU trust lists.

```bash
trebaruna trust sync               # all territories
trebaruna trust sync --territory IT
trebaruna trust list               # what is cached, and how old
trebaruna trust show IT            # services of one territory
trebaruna trust tsa IT             # its qualified timestamping services
```

`sync` verifies each national list against the certificates the EU list
publishes. A list that fails goes to quarantine, never to the cache. See
[Trust lists](trust-lists.md).

---

## `asic`

```
trebaruna asic [flags] <document> <signature.p7s>
```

Packs a document and its detached CAdES signature into an ASiC-S container
(ETSI EN 319 162-1): `mimetype` first and uncompressed, the document at the
root, the signature as `META-INF/signature.p7s`. To sign straight into a
container, XML signatures included, use `sign --asic s`: an XML signature
for a container is written inside it, because the namespace of its root is
part of what it signs. A `.p7m` carries the document inside and is refused.

| Flag | Meaning |
|---|---|
| `--type` | `s` (ASiC-S); ASiC-E is signed in one step |
| `--out` | Output path, default `<document>.asics` |
| `--extract` | Unpack an existing container to this directory |

```bash
trebaruna sign atto.pdf --format cades --asic s --p12 k.p12   # in one step
trebaruna asic atto.pdf atto.pdf.p7s                          # pack an existing .p7s
trebaruna asic --extract bundle.asics --out ./out
```

---

## `serve`

```
trebaruna serve --root <dir> [--listen addr]
```

Starts the local HTTP API. Blocks until interrupted.

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:0` | Loopback address; port `0` picks a free one |
| `--root` | working directory | Directory a client may read from; repeatable |

Binds loopback only — anything else is refused. See [Local API](local-api.md).

---

## `handler`

```
trebaruna handler "trebaruna://sign?..." [--root <dir>] [--p12 f] [--pem f] [--pass s]
```

Receives a URI from a web page, verifies the document, and asks for approval.

```bash
trebaruna handler "trebaruna://sign?document=/tmp/atto.pdf&format=pdf" \
    --root /tmp --p12 key.p12 --pass secret
```

| Flag | Meaning |
|---|---|
| `--root` | Directory a request may name; repeatable |
| `--p12`, `--pem`, `--pass` | The key used after approval |

See [Web pages](web-pages.md).

---

## `requests` and `decide`

Two commands the desktop window uses, also usable by hand:

```bash
trebaruna requests --api 127.0.0.1:8080            # list pending requests
trebaruna decide <id> --secret <secret> --approved  # answer one
```

| Flag | Meaning |
|---|---|
| `--api` | Address of the running server |
| `--secret` | The approval secret printed by `handler` |
| `--approved` | Approve; omit for reject |

They read the server token from `TREBARUNA_TOKEN`, or from
`$XDG_RUNTIME_DIR/trebaruna/token`.

---

## `version`

```bash
trebaruna version        # or --version, -v
```

Prints the version and exits `0`. The same string appears in `GET /version` and
in the desktop window title.

---

## Global behaviour

### Output

Human-readable by default, in the language from `$LANG` when the command
supports it (`verify`). `--json` everywhere that reports something.

### Nothing is interactive

Once every parameter is supplied, no command asks a question. This is what makes
the tool usable from a script, a cron job or an agent.

The one exception is `handler`, which must ask: that is its purpose.

### No hidden network access

`verify` and `sign` reach the network only when you ask:

- `verify`: `--offline=false`
- `sign --level lt|lta`: `--online-revocation`
- `sign --level t|lt|lta`: `--tsa` is explicit
- `trust sync`: always, and that is the point

Every request names the program with the User-Agent `trebaruna`, without a
version, and is listed at the end of the command's output.

### Cache location

Trust lists: `~/.cache/trebaruna/`. Nothing else is cached.

### Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `LANG`, `LC_ALL` | `verify`, desktop | Default language and territory |
| `TREBARUNA_BIN` | desktop | Path to the CLI binary |
| `TREBARUNA_LANG` | desktop | Force the window language |
| `TREBARUNA_TOKEN` | `requests`, `decide` | Server token, instead of the file |
| `TREBARUNA_TOKEN_DIR` | `serve`, `handler` | Where to write the token |
| `XDG_RUNTIME_DIR` | `serve`, `handler` | Default token directory |
| `TREBARUNA_PASSPHRASE` | `sign`, `certificate` | Passphrase of the `.p12` / `.pem` |
| `TREBARUNA_PIN` | `sign`, `token`, `pin change` | Card PIN, or Firefox's primary password |
| `TREBARUNA_PUK` | `pin unlock` | Card PUK (no flag exists) |
| `TREBARUNA_NEW_PIN` | `pin change`, `pin unlock` | The new PIN (no flag exists) |
| `TREBARUNA_TSA_PASS` | `sign`, `timestamp` | Timestamp authority password |
| `TREBARUNA_CSC_TOKEN` | `sign --csc` | Access token of the remote signing service |
| `TREBARUNA_CSC_USER`, `TREBARUNA_CSC_PASSWORD` | `sign --csc` | Sign in to the service when there is no token |
| `TREBARUNA_OTP` | `sign --csc` | One-time password a credential asks for |
| `SOFTHSM2_MODULE` | tests only | PKCS#11 module for the test suite |

---

## `encrypt` and `decrypt`

```bash
trebaruna encrypt offerta.pdf --to luca.pem --to maria.cer     # offerta.pdf.p7e
trebaruna decrypt offerta.pdf.p7e --p12 luca.p12                # offerta.pdf
trebaruna-token decrypt offerta.pdf.p7e --card                  # the key stays on the card
```

An encrypted envelope (`.p7e`, CMS EnvelopedData) only the recipients'
certificates open, AutoFirma's digital envelope. The
content is encrypted with AES-256-CBC and its key sent to each recipient with
RSA PKCS#1 v1.5, which every tool reads, or RSA-OAEP with SHA-256 (`--oaep`).
A recipient certificate must have an RSA key and, if it declares key usages,
`keyEncipherment`: a signature-only certificate is refused, as is an expired
one. `decrypt` takes the same key flags as `sign` (file, card, Firefox store);
with a card and no `--certificate`, the certificate the envelope names is found
on the card without the PIN, and only the envelope's content key is decrypted
on the card. Neither command overwrites a file; the output is written readable
only by its owner. Envelopes made by `openssl cms -encrypt` (PKCS#1 v1.5 or
OAEP with SHA-1 or SHA-256) open, and ours open with `openssl cms -decrypt`.
Many cards decrypt OAEP only with SHA-1; the error says so.

## `afirma`

```bash
trebaruna afirma '<afirma://…>' [--approve] [--p12 key.p12 | --card | --firefox …] [--file path] [--save-to path]
```

Answers an AutoFirma request (see [Web pages](web-pages.md#autofirmas-afirma-protocol)).
The request is printed on stderr in full; without `--approve` the site hears
`CANCEL`. `--file` is the document to sign when the page sends none, `--save-to`
where `save` and `signandsave` write. The answer is printed on stdout (and
posted to the site when the request names its storage service); failures are
AutoFirma's `SAF_NN` codes.

## `pin`

```bash
read -rs TREBARUNA_PIN TREBARUNA_NEW_PIN && export TREBARUNA_PIN TREBARUNA_NEW_PIN
trebaruna-token pin change [--token label] [--module path] [--json]
read -rs TREBARUNA_PUK TREBARUNA_NEW_PIN && export TREBARUNA_PUK TREBARUNA_NEW_PIN
trebaruna-token pin unlock [--token label] [--module path] [--json]
```

`change` replaces the card's PIN given the current one; `unlock` sets a new PIN
with the PUK (for a locked PIN, or a forgotten one). The secrets are read only
from the environment: there are no flags for them. Before any attempt the card
is read, so a locked card (for `change`), a locked PUK (for `unlock`) or a new
PIN outside the lengths the card declares is refused without the card counting
a try; a refused PIN or PUK is named, with a warning when one attempt is left.
`--json` prints `{"changed": true, "action": …}`, or `"changed": false` with the
error.

## `extract`

```
trebaruna extract <document.p7m|document.tsd> [--out path] [--json]
```

Takes the signed document out of a CAdES envelope: what AutoFirma calls
*extraer datos*. Nested envelopes
(`contratto.pdf.p7m.p7m`, two people signing one after the other) are opened
down to the document, through time-stamped data too (`contratto.pdf.p7m.tsd`);
DER, BER, PEM and bare Base64 envelopes are all read.
The default output is the envelope's name without `.p7m`; an existing file is
never overwritten (exit 2). Extraction checks nothing: verify the envelope.
A detached `.p7s` has no document inside and is refused with that reason.

---

## `about`

```
trebaruna about [--json]
```

What the binary is and what it contains: version, platform, Go release, source
revision (and whether it had local changes), whether it supports cards, and
every module linked into it with its version and licence. Anyone can rebuild
from the revision and compare (ADR-0017).

The licence table is regenerated from each module's licence file and checked by
a test that fails on any module whose licence is unknown or not free:

```bash
go test ./tests/transparency -run TestEveryLinkedModuleHasAFreeReviewedLicense -update
```

