# Web pages

Making a browser ask `trebaruna` to sign, without letting any open tab do it on
its own.

- [The problem](#the-problem)
- [The flow](#the-flow)
- [The URI format](#the-uri-format)
- [Approving](#approving)
- [Delivery](#delivery)
- [Registering the scheme](#registering-the-scheme)
- [AutoFirma's afirma:// protocol](#autofirmas-afirma-protocol)
- [What is missing](#what-is-missing)
- [Why approval is not automatic](#why-approval-is-not-automatic)

---

## The problem

A web page cannot start a program. When a public administration's form needs a
signature, it asks the browser to open a custom URI — this is the mechanism
AutoFirma and similar agents use — and the operating system hands that URI to
whichever application registered the scheme.

Implementing only that much is dangerous: **any page you have open can trigger the
handler**. Without a step that only a human at the machine can complete, a page
obtains a signature on a document of its choosing.

So the handler here asks first.

---

## The flow

```
page                         trebaruna                      person
 │                              │                            │
 │  trebaruna://sign?...         │                            │
 ├─────────────────────────────►│                            │
 │                              │ verify the document        │
 │                              │ print the verdict          │
 │                              │ generate a secret          │
 │◄─────────────────────────────┤ (id only, no secret)       │
 │                              │                            │
 │                              │   "sign atto.pdf ? [y/N]"  │
 │                              ├───────────────────────────►│
 │                              │◄───────────────────────────┤
 │                              │         y                  │
 │                              │ sign                       │
 │◄─────────────────────────────┤ POST to the callback       │
```

Three properties follow from the secret:

- The page **cannot approve**, because it never sees the secret.
- The page **cannot guess** it: 32 random bytes.
- The page **cannot replay** it: the approval is consumed by the first use.
- The page **cannot wait it out**: the request expires in 30 seconds.

---

## The URI format

```
trebaruna://sign?document=<path>&format=<pdf|cades|xades>
                &territory=<ISO>&origin=<url>&callback=<url>
```

| Parameter | Required | Meaning |
|---|---|---|
| `document` | **yes** | Absolute path to the document |
| `format` | — | `pdf`, `cades`, `xades`; inferred from the suffix when absent |
| `territory` | — | Trust list to use, e.g. `IT` |
| `origin` | — | The page's origin, e.g. `https://sede.example.gob.es` |
| `callback` | — | Absolute URL that receives the result |

### Rules

- **Unknown parameters are refused**, not ignored. A silently dropped parameter is
  one the caller believes was applied.
- **`origin` must be a bare origin**: scheme and host, no path, no query.
- **`callback` must stay inside `origin`.** A callback pointing elsewhere would
  turn the handler into a way to post your signature to a third party.
- **The document must be inside an allowed root** (`--root`).

Example:

```
trebaruna://sign?document=/tmp/atto.pdf&format=pdf&origin=https://sede.example.gob.es&callback=https://sede.example.gob.es/result
```

Percent-encode anything unusual:

```
trebaruna://sign?document=%2Ftmp%2Fatto%20firmato.pdf
```

---

## Approving

```bash
trebaruna handler "trebaruna://sign?document=/tmp/atto.pdf&format=pdf" \
    --root /tmp --p12 key.p12 --pass secret
```

```
request  8f8f6d7525135721329686bf956652bd
verdict  unknown
secret   dd8e185e11d506de65bffa7be5773a6a54e4f592430c71f626d437fc4e9026a8
the desktop app must now approve this request; so does:
  curl -X POST http://127.0.0.1:37489/v1/requests/8f8f.../decision \
       -H 'X-Firma-Token: /run/user/1000/trebaruna/token' \
       -d '{"secret":"dd8e...","approved":true}'

sign /tmp/atto.pdf ?  [y/N] y
signed   /tmp/atto_signed.pdf
delivered to https://sede.example.gob.es/result
```

What the person sees before deciding:

- the **verdict** of the verification that ran before the request was queued;
- the **path** being signed;
- the **signer** and the **time left**.

That is the minimum for an informed decision. Asking "approve this signature?"
with no information is how users learn to click yes.

---

## Delivery

After approval the result is posted to the callback as JSON:

```json
{
  "request": "8f8f6d75...",
  "path": "/tmp/atto_signed.pdf",
  "format": "pades",
  "level": "bes",
  "size": 15234,
  "signed_at": "2026-11-08T09:12:44Z",
  "signer": "handler",
  "verdict": "advanced",
  "self_signed": false
}
```

Not the file itself: the page can read it from the local API, and shipping
megabytes through a form post serves nobody.

- Timeout: **20 seconds**.
- A non-2xx answer is reported as a **failed delivery**, not a success. The
  signature exists, the delivery did not happen, and the caller can tell the
  difference.
- The document signed is the one from the **approved** request, never a parameter
  sent later.

---

## Registering the scheme

### Linux

`packaging/trebaruna.desktop` declares it:

```ini
Exec=trebaruna-desktop %U
MimeType=application/pdf;text/xml;application/xml;x-scheme-handler/trebaruna;
```

Install the entry and register it:

```bash
make install-desktop
xdg-mime default trebaruna.desktop x-scheme-handler/trebaruna
```

### AutoFirma's afirma:// links (Linux)

The same entry declares `x-scheme-handler/afirma`, so trebaruna is offered for
AutoFirma's links without taking them from AutoFirma: with both installed, the
default stays where it was until you choose.

```bash
make afirma-default        # this user: afirma:// links open trebaruna
make afirma-autofirma      # back to AutoFirma
xdg-mime query default x-scheme-handler/afirma
```

Firefox: the AutoFirma package installs `/etc/firefox/pref/Autofirma.js`,
which sets `network.protocol-handler.app.afirma` to `/usr/bin/autofirma` and
so bypasses the choice above. With AutoFirma installed, point that preference
at `trebaruna-desktop` in `about:config` (or remove AutoFirma's file) for
Firefox to open trebaruna. Without AutoFirma, Firefox asks which application to
use the first time. trebaruna installs no browser preference of its own.

### macOS

`packaging/macos/Info.plist` declares `CFBundleURLTypes` with the `trebaruna`
and `afirma` schemes. macOS keeps one default per scheme, so trebaruna does not
take `afirma` over from an installed AutoFirma. Not verified on macOS here: the
system hands a URL to an app as an Apple Event, and the window has only been
tested receiving it as an argument (Linux).

### Windows

A registry entry under
`HKEY_CLASSES_ROOT\trebaruna\shell\open\command` pointing at the binary with `%1`.
Not packaged by this project; use `trebaruna handler "%1"` as the command.

### Using the CLI instead of the window

The desktop entry launches the window. For a server or a terminal session, call
the CLI directly and wire your own browser handler:

```bash
trebaruna handler "%1" --root ~/Documents --p12 ~/Documents/key.p12 --pass secret
```

---

## AutoFirma's afirma:// protocol

Spanish administration pages start AutoFirma with `afirma://` URIs.
trebaruna reads and answers them as AutoFirma 1.9 does, from the protocol's
free source ([afirma-protocol.md](afirma-protocol.md)), with the difference
that matters here: nothing is signed, downloaded or sent before a person has
seen the request and approved it.

In the desktop, the URI opens an approval window ([Desktop](desktop.md#requests-from-autofirma-pages-afirma));
from a terminal:

```bash
trebaruna afirma 'afirma://sign?…'                       # shows the request, answers CANCEL
trebaruna afirma 'afirma://sign?…' --approve --p12 k.p12   # signs and answers the site
```

What a request shows: the operation, the site the answer goes to (the host of
its storage service) and the name the page gives itself, the format, the data
(size and SHA-256, or the address it would be downloaded from), the certificate
filters the page sets, and warnings — the intermediate server's single DES with
an eight-digit key protects nothing against anyone who sees the traffic, and
trebaruna says so.

Channels:

- **Intermediate server** (implemented): the answer is posted to the site's
  StorageService, ciphered with the page's key (DES, or AES for autoscript
  1.10), with `#WAIT` every 10 seconds while the person decides; long requests
  are fetched from its RetrieveService. Pages that force this channel work
  (Sistema RED does).
- **WebSocket and the legacy socket** (not offered): they are TLS on
  `127.0.0.1` and need a certificate the browser trusts; AutoFirma installs its
  own root CA for that, and trebaruna installs none (ADR-0013). Pages that use
  them by default do not reach trebaruna.

Operations: `sign`, `cosign`, `countersign`, `signandsave`, `selectcert`,
`save` and `batch`. A batch (JSON or XML) goes through the site's pre- and
post-signers: the documents stay on the site, the key signs what its server
prepares from them (each `PRE`, hashed and signed with RSA or ECDSA), and the
post-signer's result goes back to the page; the person is shown every document
of the batch first. A local batch (`localBatchProcess`) is signed document by
document here. Formats: CAdES (implicit or explicit, co- and counter-signatures),
PAdES (invisible unless the page places the seal), XAdES (enveloping when the
page names no variant, as AutoFirma; enveloped; and "XAdES Detached", the
`AFIRMA` root holding `CONTENT` and the signature), XMLDSig in the same
variants (no signed properties: a policy or a timestamp is refused, roles are
left out as AutoFirma does), `ODF` (the document signed inside itself, as LibreOffice does),
`CAdES-ASiC-S` and `XAdES-ASiC-S` (the
container, the data named `asicsFilename` or `dataobject.<extension>` as
AutoFirma names it), and FacturaE (named, or recognised by `auto`: the invoice signed
enveloped with FacturaE 3.1, or the 3.0/3.1 policy the page gives exactly, and
the role in `signerClaimedRoles`, `emisor` by default; an invoice already
signed is refused with `SAF_38`, never signed again as plain XAdES). Signature policies are
read as AutoFirma 1.9 reads them: `expPolicy=FirmaAGE` or `FirmaAGE18` expands
to the AGE policy and fixes the packaging as AutoFirma does (CAdES implicit
below 1 MiB unless `mode` says otherwise, XAdES detached unless the page asked
for enveloped), `FirmaAGE19` and anything else is `SAF_23`; `policyIdentifier`
with `policyIdentifierHash`, `policyIdentifierHashAlgorithm` and
`policyQualifier` declares any other. AutoFirma downloads the policy when the
page gives no digest; trebaruna answers `SAF_23` instead, because it does not
fetch what a page points at. XAdES signatures claim the roles in
`signerClaimedRoles` (several separated by `|`). Asked for something not done
yet — a policy in PAdES, co-signing an ASiC container, a digest the page computed, single signatures
through the site's server (`CAdEStri` and siblings) — trebaruna answers with an
AutoFirma error naming it, never with a different signature.

## What is missing

Being explicit, because "compatible with AutoFirma" is a claim this project will
not make without evidence.

### Per-issuer request formats

Spanish administrations each define their own payload dialect. This implements
**one explicit shape** — `document`, `format`, `territory`, `origin`, `callback`
— rather than guessing at a dozen undocumented ones.

Supporting a specific administration means writing an adapter that maps its URI
onto those five parameters. The approval, signing and delivery steps are already
generic:

```
administración URI ──► [adapter] ──► the five parameters ──► approval ──► sign ──► deliver
```

That adapter is a small, well-scoped piece of work, and the only part that needs
knowledge of a particular site.

### A tested integration against a real administration

Everything above is exercised against a local receiver in the test suite. No
public endpoint was available to test against, and claiming compatibility without
one would be the kind of unverified claim the rest of this project avoids.

If you have access to a staging environment for one of these flows, that is the
single most useful thing to contribute.

---

## Why approval is not automatic

Because automatic approval is what made previous local signing agents
exploitable, and this tool exists to be trusted.

The attack: a user has a page open. That page navigates to a URI handler with a
document of the attacker's choosing. If the handler signs without asking, the
attacker has a valid qualified signature from the user on a document the user
never saw.

The secret breaks that chain, and it breaks it structurally rather than by
convention: the approving process is not the requesting process, and the
requesting process has no way to learn the secret.

---

## Next

- [Local API](local-api.md) — the routes behind all of this
- [Desktop app](desktop.md) — approving in the window
- [Verification](verification.md) — what the verdict shown to the user means