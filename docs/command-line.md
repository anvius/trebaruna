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
| `--format` | from the suffix | `cades`, `pades` or `xades` |
| `--level` | `bes` | `bes`, `t`, `lt` or `lta` — see [Signing](signing.md) |
| `--p12` | — | PKCS#12 file with the certificate and key |
| `--pem` | — | PEM bundle containing certificate and key |
| `--card` | — | Sign with the card in the reader; card and signing certificate are found |
| `--token` | — | PKCS#11 token label (needs `trebaruna-token`) |
| `--certificate` | the signing one | Certificate of the card: serial or SHA-256 fingerprint (8+ digits); finds the card without `--token` |
| `--module` | OpenSC, found on the system | PKCS#11 module path |
| `--firefox` | — | Sign with a certificate of the Firefox store, in place (PIN: the primary password) |
| `--nss-db` | — | Sign with a certificate of this NSS store directory (`~/.pki/nssdb` for Chromium) |
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
| `--enveloping` | off | XAdES enveloping rather than enveloped |
| `--invisible` | off | PAdES without a visible seal; excludes `--box` |
| `--detached` | off | CAdES without the content: `<document>.p7s` beside it |
| `--cosign` | off | Add a parallel signature to the `.p7m`/`.p7s` given as document |
| `--countersign` | — | Counter-sign the envelope's signatures: `leaves` or `all` |
| `--content` | — | The document a detached `.p7s` signs, to co-sign it |
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

---

## `verify`

```
trebaruna verify <document> [flags]
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--format` | from the suffix | `pdf`, `cades` or `xades` |
| `--territory` | from `$LANG` | Trust list to use, e.g. `IT`, `ES`, `EU` |
| `--offline` | `true` | Set `--offline=false` to query OCSP and CRL responders |
| `--lang` | from `$LANG` | `es`, `it` or `en` for human output |
| `--json` | off | Machine-readable report |

### Recognised suffixes

`.pdf` → PAdES · `.p7m`, `.p7s` → CAdES · `.xml`, `.xsig` → XAdES

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
trebaruna timestamp <file> --tsa <url>
trebaruna timestamp --hash <hex> --tsa <url>
```

Obtains an RFC 3161 token proving a document existed at a moment.

| Flag | Meaning |
|---|---|
| `--tsa` | Timestamp authority URL (required) |
| `--hash` | Timestamp a digest instead of a file |
| `--tsa-user`, `--tsa-pass` | Basic auth, when the authority requires it |
| `--out` | Output path, default `<file>.tsr` |
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
```

Checks a token on its own, or that it matches a document.

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
```

Downloads and **authenticates** the EU trust lists.

```bash
trebaruna trust sync               # all territories
trebaruna trust sync --territory IT
trebaruna trust list               # what is cached, and how old
trebaruna trust show IT            # services of one territory
```

`sync` verifies each national list against the certificates the EU list
publishes. A list that fails goes to quarantine, never to the cache. See
[Trust lists](trust-lists.md).

---

## `asic`

```
trebaruna asic [flags] <document> <signature>...
```

Packs a document and its signature into an ASiC container (ETSI EN 319 162).

| Flag | Meaning |
|---|---|
| `--type` | `s` (ASiC-S, one document) or `e` (ASiC-E, several) |
| `--out` | Output path, default `<document>.asics` |
| `--extract` | Unpack an existing container to this directory |

```bash
trebaruna asic atto.pdf atto.pdf.p7m
trebaruna asic --type e doc.pdf sig1.p7m sig2.p7m --out bundle.asice
trebaruna asic --extract ./out bundle.asics
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
| `SOFTHSM2_MODULE` | tests only | PKCS#11 module for the test suite |

---

## `extract`

```
trebaruna extract <document.p7m> [--out path] [--json]
```

Takes the signed document out of a CAdES envelope: what AutoFirma calls
*extraer datos*. Nested envelopes
(`contratto.pdf.p7m.p7m`, two people signing one after the other) are opened
down to the document; DER, BER, PEM and bare Base64 envelopes are all read.
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

