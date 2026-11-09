# trebaruna

> *Trebaruna* was a goddess of the Lusitanian and Gallaecian pantheons, worshipped
> in what is now Galicia and Portugal. Her name is Celtic: *trebo-* ("home") and
> *runa-* ("secret", "mystery") — **the secret kept at home**, the trust that does
> not travel and does not change.
>
> That is what a signature is: a thing given so that a document can never be
> quietly altered afterwards. The Romans had a god for the same idea and called him
> Sancus; his oaths protected contracts and were spoken when a pact was sealed.

AdES electronic signatures in a single static binary. Signs and verifies PDF,
XML and arbitrary files as **CAdES**, **PAdES** and **XAdES**, from the baseline
profile up to long-term archival, and checks every claim against the European
trust lists instead of assuming.

No proprietary code, no browser engine, no JVM. The whole CLI is ~9 MB and needs
nothing installed.

```bash
trebaruna sign contratto.pdf --p12 key.p12 --pass secret \
    --reason "Fornitura" --box 100,600,300,700
# → contratto_signed.pdf, PAdES-B, ETSI EN 319 142-1
```

**Licence: AGPL-3.0-or-later.** See [LICENSE](LICENSE).

---

## Documentation

Full manual, in English, in [`docs/`](docs/README.md):

| | |
|---|---|
| [Installation](docs/installation.md) | Linux, macOS, Windows; which binary you need |
| [Command line](docs/command-line.md) | Every command and flag, exit codes, environment |
| [Signing](docs/signing.md) | Formats, levels, seals, chained signatures |
| [Verification](docs/verification.md) | Verdicts, finding codes, what is really checked |
| [Certificates](docs/certificates.md) | Accepted key types, inspecting, self-signed |
| [Timestamps](docs/timestamps.md) | RFC 3161: obtaining, using, verifying |
| [Trust lists](docs/trust-lists.md) | Where "trusted" comes from |
| [Desktop app](docs/desktop.md) | The window |
| [Web pages](docs/web-pages.md) | `trebaruna://` and why approval is required |
| [Local API](docs/local-api.md) | HTTP surface for scripts and agents |
| [Smartcards](docs/smartcards.md) | PKCS#11, PINs, what is tested |
| [Troubleshooting](docs/troubleshooting.md) | The errors you will actually hit |
| [Becoming a CA](docs/becoming-a-ca.md) | Issuing qualified certificates: the Spanish process, honestly |

This README is the summary. The manual is the reference.

---

## What it does

| Capability | Detail |
|---|---|
| **CAdES** | BES and T, content embedded, `.p7m` |
| **PAdES** | B, T, LT and LTA; visible seal, `/DSS` validation store, document timestamp |
| **XAdES** | BES, T and A; enveloped and enveloping; `SignatureTimeStamp` and `ArchiveTimeStamp` |
| **Verification** | Integrity, certificate validity, revocation, qualified status, timestamp authority |
| **Trust** | 18 national lists authenticated against the EU root; no list is trusted because it downloaded |
| **Revocation** | OCSP, four explicit states instead of a boolean |
| **Timestamps** | RFC 3161 issue and verify, including the archive layers |
| **Seal** | Drawn from the certificate, positioned in a free gap, never truncated |
| **Keys** | PKCS#12, PEM, PKCS#11 smartcard |
| **Machine output** | `--json` everywhere, stable shapes, documented exit codes |
| **Web pages** | `trebaruna://` URI handler with mandatory human approval |

Everything above is exercised by 234 tests and, where it matters, by an
independent implementation: `openssl cms -verify`, `openssl ts -verify`,
`pdfsig`, `qpdf` and `signxml` are used as judges, not as decoration.

---

## Why another signing tool

Because producing a signature is a solved problem and *knowing what you have* is
not.

A signature can be cryptographically perfect and still worthless: expired when it
was made, issued by an authority nobody supervises, or self-signed by whoever
sent you the file. Tools that report a single "valid" flag hide that distinction,
and users end up trusting the wrong documents.

This tool refuses to report a claim it cannot substantiate:

- A self-signed certificate is **not** "advanced": no third party vouches for the
  identity. It is reported as untrusted.
- A certificate that expired yesterday does not invalidate a signature made two
  years ago; one that had expired *at signing time* does. Two different findings,
  two different severities.
- A signature is called **qualified** only when three independent conditions
  hold: a qualified certificate, a qualified signature-creation device, and a
  currently granted qualified issuer in an **authenticated** trust list. None
  implies the others.
- A timestamp covers the signature *and* its authority is proven qualified, or
  the report says which half is missing.
- "Not revoked" and "nobody asked" are different answers. They never collapse
  into one.

---

## Install

Prebuilt static binaries for Linux (amd64, arm64), macOS (amd64, arm64) and
Windows (amd64) are attached to each release.

```bash
chmod +x trebaruna-linux-amd64
mv trebaruna-linux-amd64 ~/.local/bin/trebaruna
```

Or build it, which takes about ten seconds and needs only a Go toolchain:

```bash
git clone https://codeberg.org/simplicer/trebaruna
cd trebaruna
make build          # static CLI
make install        # ~/.local/bin
```

Two optional builds need cgo, and are kept separate so the main binary stays
static and portable:

```bash
make build-token    # PKCS#11 smartcards
make build-gui      # desktop app (needs make deps-gui first)
```

---

## Signing

```bash
trebaruna sign <document> [flags]
```

The format is inferred from the suffix, or set with `--format`:

```bash
trebaruna sign atto.pdf                      # PAdES
trebaruna sign fattura.xml                   # XAdES
trebaruna sign contratto.pdf --format cades  # CAdES, .p7m
```

Output follows the conventions Italian and Spanish signers expect, so the result
opens in the tools people already use:

| Format | Output |
|---|---|
| CAdES | `document.pdf.p7m` |
| PAdES | `document_signed.pdf` |
| XAdES | `document_signed.xml` |

### Levels

```bash
--level bes    # baseline, no timestamp
--level t      # + RFC 3161 timestamp
--level lt     # + timestamp + /DSS validation store   (PAdES)
--level lta    # + archive timestamp                    (PAdES, XAdES; XAdES uses `t` and `a`)
```

`--level lt` and above reach the network to collect revocation answers, so they
need to be authorised:

```bash
trebaruna sign doc.pdf --p12 key.p12 --level lt \
    --tsa https://freetsa.org/tsr --online-revocation
```

### The visible seal

```bash
--box 100,600,300,700          # x1,y1,x2,y2 in PDF points
--box 2:100,600,300,700        # page 2
--box 100,600,300,700 --box 100,500,300,600   # several marks, one signature
```

The seal contains only what the certificate says: name, identifier and the
signing instant with its UTC offset. There is deliberately no option to type
arbitrary text onto a signature — a stamp carrying the signer's own prose is
decoration, not proof.

If the identity does not fit the box, the signature is refused rather than
printed truncated. `--auto-box` finds a free area on the page using a poppler
render.

### Keys

```bash
--p12 key.p12 --pass secret        # PKCS#12 from any authority
--pem bundle.pem                   # certificate + key in one PEM
--token "My Smartcard" --pin 1234  # PKCS#11, needs make build-token
```

Self-signed certificates work: the signature is produced and the report states
plainly that no third party vouches for it.

---

## Verification

```bash
trebaruna verify <document> [flags]
```

```bash
trebaruna verify contratto_signed.pdf
trebaruna verify atto.pdf.p7m --territory IT --json
trebaruna verify doc.xml --offline=false     # also ask OCSP
```

Exit codes are part of the contract:

| Code | Meaning |
|---|---|
| `0` | verified |
| `1` | altered, or revoked before signing |
| `2` | usage error |
| `3` | could not be verified (unknown issuer, no trust list) |

The human output separates three questions that are usually merged:

```
  Firma 1 — signature-1
    Firmante       MARIA LOPEZ GARCIA
    Identificador  IDCES-00000000X
    Emisor         Example TSP
    Firmado        2026-11-02 12:52:30 +01:00
    Integridad     correcto
    ! la fecha de firma la declara el firmante y no está sellada
```

`--json` emits the same facts with the evidence attached, including *which*
condition kept a signature from being qualified:

```json
{
  "verdict": "advanced",
  "signers": [{
    "trust": "advanced",
    "qualified": false,
    "qualification": {
      "certificate_qualified": true,
      "device_qualified": false,
      "service_listed": true,
      "missing": ["the private key is not proven to live in a qualified device"]
    }
  }]
}
```

Languages: `--lang es|it|en`, or `$LANG`.

---

## Trust lists

The only defensible source of "is this issuer recognised" is the official EU
list of trusted lists. Downloaded lists are **inventory, not trust**: a file that
merely downloaded is not an anchor.

Every list is authenticated before use: the LOTL publishes each territory's
signing certificates, and a national list is only accepted when its own XML
signature verifies against them. A list that fails goes to quarantine, never to
the cache.

```bash
trebaruna trust sync            # download and authenticate every list
trebaruna trust list            # what is cached, with counts and next update
trebaruna trust show IT         # services of one territory
```

Measured on the Italian list: 562 services, 142 granted qualified CAs, 137 root
anchors. Territories that publish their list only as a PDF cannot be parsed and
stay inventory — that is stated, not hidden.

---

## Timestamps

```bash
trebaruna timestamp document.pdf --tsa https://freetsa.org/tsr   # → .tsr
trebaruna timestamp --hash <hex> --tsa <url>                     # over a digest
trebaruna verify-tsr token.tsr document.pdf                      # check a token
```

A token is only reported as *accredited* when three independent facts hold: its
imprint matches this signature, its certificate carries the `timeStamping` key
usage, and a granted qualified authority in an authenticated list can issue it.

---

## Certificates

```bash
trebaruna certificate key.p12 --pass secret
trebaruna certificate bundle.pem --json
```

Reports subject, issuer, validity window, key size, qualified statements and
whether the certificate is self-signed. It never signs and never needs a private
key operation, which matters with a smartcard where every operation can ask for a
PIN.

---

## ASiC containers

```bash
trebaruna asic document.pdf signature.p7m     # ASiC-S
trebaruna asic --extended document.pdf sig1.p7m sig2.p7m   # ASiC-E
```

---

## The desktop app

A native window (Fyne, ~33 MB) with a sign tab and a verify tab, in Spanish,
Italian and English. It drives the same CLI binary rather than reimplementing
anything: one validation path, one behaviour.

Without poppler the preview degrades to manual box entry with an explicit
message; signing still works. That degradation is tested behaviour, not a
promise.

---

## The local HTTP API

For agents and tools that cannot spawn a process:

```bash
trebaruna serve --root ~/Documents        # binds 127.0.0.1, picks a free port
```

The token is written to `$XDG_RUNTIME_DIR/trebaruna/token` with mode `0600`,
printed as a path (never as the secret), and removed on exit.

```bash
TOKEN=$(cat "$XDG_RUNTIME_DIR/trebaruna/token")

curl -s http://127.0.0.1:PORT/version
curl -s -X PUT http://127.0.0.1:PORT/v1/signatures/job-1 \
     -H "X-Firma-Token: $TOKEN" \
     -d '{"path":"a.pdf","format":"pades","level":"bes","p12":"k.p12","passphrase":"x"}'
```

| Route | Purpose |
|---|---|
| `GET /status` | health |
| `GET /version` | `{"data":{"version":"x.y.z"}}` |
| `PUT /v1/signatures/{id}` | sign; returns the artefact |
| `PUT /v1/verifications/{id}` | verify; the report is kept for retrieval |
| `GET /v1/verifications/{id}` | read a stored report |

A local signing endpoint is a known attack surface: it is the flaw that makes
naive local signing agents exploitable by any page the user happens to open. Four
mitigations are structural here, not optional: loopback-only binding, a token
required on every privileged route, an `Origin` check that refuses cross-origin
requests, and a path allow-list resolved with `EvalSymlinks`.

Errors are `application/problem+json` (RFC 9457), as the Zalando guidelines
require.

---

## Smartcards

```bash
make build-token     # needs cgo and libdl
trebaruna-token sign doc.pdf --token "My Card" --pin 1234 \
    --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

Tested against SoftHSM2 with a key generated inside the token, a certificate
issued for that key, and signatures produced through it.

---

## What is verified, and how

Claims in this project are backed by tools that were not written here:

| Claim | Judge |
|---|---|
| CAdES verifies | `openssl cms -verify -cades` |
| Timestamps verify | `openssl ts -verify` → `Verification: OK` |
| PAdES verifies | `pdfsig` → `Signature is Valid` |
| PDF structure after `/DSS` and B-LTA | `qpdf --check` |
| XAdES verifies | `signxml`, an independent implementation |
| Canonicalisation is byte-exact | `lxml` comparison |
| PKCS#11 signatures | SoftHSM2 + `openssl cms -verify` |

---

## Known limits

Stated rather than hidden:

- **A physical smartcard is untested.** The PKCS#11 path is exercised with
  SoftHSM2, which is a real driver but software. Only the module differs, and
  that is not proof.
- **Some states publish their trust list only as a PDF** (ES, FR, PT, LU, BG,
  CZ, DK, EE, HU, IS, NO). Without XML there are no services to parse.
- **The macOS `.app` needs a macOS runner to build.** Fyne links Cocoa and
  cannot be cross-compiled from Linux. The CI job is written; the artefact is
  not built here.
- **Gatekeeper will warn** on other machines: the bundle is ad-hoc signed.
  Notarisation needs a paid Apple Developer account, which is a decision, not
  code.

---

## Architecture

Domain-driven, vertically sliced: code is organised by capability, not by
technical layer, and dependencies point inwards.

```
src/
├── signing/         sign:      domain → application → infrastructure
├── verification/    verify:    domain → application → infrastructure
├── trust/           TSL/LOTL:  domain → application → infrastructure
├── encryption/      .p7e:      domain → application → infrastructure
├── afirma/          AutoFirma's afirma:// protocol: domain → application → infrastructure
├── transparency/    connection record, licences, SBOM
├── desktop/         the Fyne window (build tag `gui`)
└── entrypoint/      cli and serve, thin adapters
```

- The domain knows nothing about PDF, HTTP or Fyne.
- Use cases expose one method and are the unit of behaviour.
- Adapters translate libraries into the domain; they decide nothing.
- Business concepts are value objects, never bare strings.

Details in the source: every package documents its reason for existing, and the
non-obvious decisions carry the measurement that produced them.

---

## Building from source

```bash
make            # help
make build      # static CLI, no cgo
make test       # the suite
make check      # tests + vet
make cross      # linux/windows/darwin binaries
make build-gui  # desktop app (needs make deps-gui)
```

Requirements: Go 1.24 or newer. The optional GUI build additionally needs a C
toolchain and OpenGL/X11 headers; `make deps-gui` documents what to install.

---

## Protocol handlers and AutoFirma

Can a web page ask `trebaruna` to sign, the way Spanish administrations invoke
AutoFirma through an `autofirma://` URI?

**The request half is implemented. The automatic-approval half is not, on
purpose.**

```bash
trebaruna handler "trebaruna://sign?document=/home/user/atto.pdf&format=pdf&origin=https://sede.example.gob.es"
```

```
request  8f8f6d7525135721329686bf956652bd
verdict  advanced
secret   dd8e185e11d506de65bffa7be5773a6a54e4f592430c71f626d437fc4e9026a8
the desktop app must now approve this request
the request expires in 30 seconds
```

### How it works

A page cannot spawn a process, so it asks the operating system to open a URI.
The app receives it, and then:

1. **resolves the document** against the allowed roots, refusing anything
   outside them;
2. **verifies it immediately**, so nobody is invited to sign a file whose
   content has not been examined — the verdict is shown before the decision;
3. **generates a secret** that the page never sees, and prints it to the
   terminal, where the person sitting at the machine can read it;
4. **waits for an explicit approval** through the desktop window or the local
   API;
5. **expires in 30 seconds** and is **single use**.

The scheme is registered in `packaging/trebaruna.desktop`
(`x-scheme-handler/trebaruna`) and `packaging/macos/Info.plist`
(`CFBundleURLTypes`).

### Why approval is not automatic

The obvious implementation — sign whatever the URI names and post the result
back — is the reason existing local signing agents have been exploitable: any
page the user has open can trigger a scheme handler, and without a step only the
human can complete, the page obtains a signature on a document of the attacker's
choosing. The secret is that step. The page cannot read it, cannot guess it
(32 random bytes), cannot replay it (single use), and cannot wait it out (30
seconds).

### Delivering the result

After approval the signature is produced and posted to the declared callback:

```bash
trebaruna handler "trebaruna://sign?document=/tmp/atto.xml&format=pdf&origin=https://sede.example.gob.es&callback=https://sede.example.gob.es/result" --root /tmp --p12 key.p12 --pass secret
```

```
sign /tmp/atto.xml ?  [y/N] y
signed   /tmp/atto_signed.xml
delivered to https://sede.example.gob.es/result
```

The POST carries JSON describing the artefact — path, format, level, size,
signing time, signer, verdict — not the file itself. The timeout is 20 seconds,
and a non-2xx answer is reported as a failed delivery rather than a successful
one: the signature exists, the delivery did not happen, and the caller must be
able to tell the difference.

The document is read from the **approved** request, never from a parameter sent
later, so what the person saw is what gets signed.

### What is still missing

- **Per-issuer request formats.** Spanish administrations each define their own
  payload dialect. This implements one explicit shape (`document`, `format`,
  `territory`, `origin`, `callback`) rather than guessing at a dozen undocumented
  ones. Supporting a specific administration means writing an adapter that maps
  its URI onto these five parameters; the approval, signing and delivery steps are
  already generic.
- **A tested integration against a real administration.** Everything above is
  exercised against a local receiver. No public endpoint was available to test
  against, and claiming compatibility without one would be the kind of unverified
  claim this project refuses to make.

## Contributing

Issues and patches are welcome on Codeberg. Conventions used here:

- **Conventional Commits**, one commit per change, in English.
- `make check` must pass before a commit.
- New behaviour needs a test, and a claim needs a measurement.
- A capability that is not tested is documented as a limit, not as a feature.

---

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE).

The AGPL was chosen over the GPL because this tool is meant to be usable as a
network service: if someone runs a modified `trebaruna serve` for others, those
users are entitled to the source of what is signing their documents.