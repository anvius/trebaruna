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
pignus <command> [arguments] [flags]
```

Flags may appear before or after the positional argument:
`pignus sign doc.pdf --p12 k.p12` and `pignus sign --p12 k.p12 doc.pdf` are
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
if pignus verify "$f" --json >/dev/null; then
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
pignus sign <document> [flags]
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--format` | from the suffix | `cades`, `pades` or `xades` |
| `--level` | `bes` | `bes`, `t`, `lt` or `lta` — see [Signing](signing.md) |
| `--p12` | — | PKCS#12 file with the certificate and key |
| `--pem` | — | PEM bundle containing certificate and key |
| `--token` | — | PKCS#11 token label (needs `pignus-token`) |
| `--module` | system | PKCS#11 module path |
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
| `--json` | off | Machine-readable result |

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
pignus sign contratto.pdf --p12 mia-chiave.p12 --pass segreto
```

An XML invoice with a timestamp:

```bash
pignus sign fattura.xml --pem bundle.pem --level t --tsa https://freetsa.org/tsr
```

A PDF with a visible seal in the bottom-left corner, long-term valid:

```bash
pignus sign atto.pdf --p12 k.p12 --pass x \
    --level lt --tsa https://freetsa.org/tsr --online-revocation \
    --box 60,60,280,160 --reason "Contratto di fornitura"
```

Two seals on different pages, one signature:

```bash
pignus sign atto.pdf --p12 k.p12 --pass x \
    --box 1:60,60,280,160 --box 3:60,60,280,160
```

Any file wrapped in CMS:

```bash
pignus sign backup.zip --format cades --pem bundle.pem
```

Sign from a smartcard:

```bash
pignus-token sign atto.pdf --token "Carta Nazionale" --pin 123456 \
    --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

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
pignus verify <document> [flags]
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
pignus verify contratto_signed.pdf
pignus verify atto.pdf.p7m --territory IT
pignus verify doc.xml --json | jq '.verdict, .signers[].trust'
pignus verify atto.pdf --offline=false --json
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
pignus timestamp <file> --tsa <url>
pignus timestamp --hash <hex> --tsa <url>
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
pignus timestamp atto.pdf --tsa https://freetsa.org/tsr
pignus timestamp --hash 3a7bd3e2... --tsa https://freetsa.org/tsr --out proof.tsr
```

See [Timestamps](timestamps.md).

---

## `verify-tsr`

```
pignus verify-tsr <token.tsr> [document]
```

Checks a token on its own, or that it matches a document.

```bash
pignus verify-tsr atto.pdf.tsr
pignus verify-tsr atto.pdf.tsr atto.pdf     # also check the imprint
pignus verify-tsr --hash <hex> proof.tsr
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
pignus certificate <file> [flags]
```

Reads a certificate without signing anything.

```bash
pignus certificate mia-chiave.p12 --pass segreto
pignus certificate bundle.pem --json
pignus certificate certificate.cer --territory IT
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
pignus trust sync  [--territory XX]
pignus trust list
pignus trust show <territory>
```

Downloads and **authenticates** the EU trust lists.

```bash
pignus trust sync               # all territories
pignus trust sync --territory IT
pignus trust list               # what is cached, and how old
pignus trust show IT            # services of one territory
```

`sync` verifies each national list against the certificates the EU list
publishes. A list that fails goes to quarantine, never to the cache. See
[Trust lists](trust-lists.md).

---

## `asic`

```
pignus asic [flags] <document> <signature>...
```

Packs a document and its signature into an ASiC container (ETSI EN 319 162).

| Flag | Meaning |
|---|---|
| `--type` | `s` (ASiC-S, one document) or `e` (ASiC-E, several) |
| `--out` | Output path, default `<document>.asics` |
| `--extract` | Unpack an existing container to this directory |

```bash
pignus asic atto.pdf atto.pdf.p7m
pignus asic --type e doc.pdf sig1.p7m sig2.p7m --out bundle.asice
pignus asic --extract ./out bundle.asics
```

---

## `serve`

```
pignus serve --root <dir> [--listen addr]
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
pignus handler "pignus://sign?..." [--root <dir>] [--p12 f] [--pem f] [--pass s]
```

Receives a URI from a web page, verifies the document, and asks for approval.

```bash
pignus handler "pignus://sign?document=/tmp/atto.pdf&format=pdf" \
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
pignus requests --api 127.0.0.1:8080            # list pending requests
pignus decide <id> --secret <secret> --approved  # answer one
```

| Flag | Meaning |
|---|---|
| `--api` | Address of the running server |
| `--secret` | The approval secret printed by `handler` |
| `--approved` | Approve; omit for reject |

They read the server token from `PIGNUS_TOKEN`, or from
`$XDG_RUNTIME_DIR/pignus/token`.

---

## `version`

```bash
pignus version        # or --version, -v
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

Trust lists: `~/.cache/pignus/`. Nothing else is cached.

### Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `LANG`, `LC_ALL` | `verify`, desktop | Default language and territory |
| `PIGNUS_BIN` | desktop | Path to the CLI binary |
| `PIGNUS_LANG` | desktop | Force the window language |
| `PIGNUS_TOKEN` | `requests`, `decide` | Server token, instead of the file |
| `PIGNUS_TOKEN_DIR` | `serve`, `handler` | Where to write the token |
| `XDG_RUNTIME_DIR` | `serve`, `handler` | Default token directory |
| `SOFTHSM2_MODULE` | tests only | PKCS#11 module for the test suite |