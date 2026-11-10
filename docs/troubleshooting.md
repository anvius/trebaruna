# Troubleshooting

The errors you will actually hit, what each one means, and what to do.

- [Start here](#start-here)
- [Signing errors](#signing-errors)
- [Verification results that surprise](#verification-results-that-surprise)
- [Certificate and key errors](#certificate-and-key-errors)
- [Timestamp errors](#timestamp-errors)
- [Trust list errors](#trust-list-errors)
- [Seal errors](#seal-errors)
- [Smartcard errors](#smartcard-errors)
- [Desktop window](#desktop-window)
- [Local API](#local-api)
- [When nothing helps](#when-nothing-helps)

---

## Start here

Three questions resolve most problems:

```bash
read -rs TREBARUNA_PASSPHRASE && export TREBARUNA_PASSPHRASE   # the passphrase, never on the command line
trebaruna version                 # what am I running?
trebaruna certificate key.p12   # what is my certificate?
trebaruna verify out.pdf          # what did I actually produce?
```

That last one is the most useful habit: **verify your own output** before sending
it anywhere. It is how you discover that your issuer is not in any trust list,
rather than learning it from a counterparty.

---

## Signing errors

### "signature format not applicable to this document: .xml cannot hold a pades signature"

You asked for PAdES on a non-PDF. PAdES embeds the signature in the PDF
structure; an XML file has none.

```bash
trebaruna sign doc.xml --format xades     # or just omit --format
```

### "no key source: use --p12, --pem or --token"

No key was given. Exactly one is required:

```bash
trebaruna sign doc.pdf --p12 k.p12
```

### "ambiguous key source: use only one of --p12, --pem, --token"

Two were given. The tool refuses to guess which one you meant.

### "level t needs a timestamp authority: pass --tsa <url>"

The level you asked for includes a timestamp, and no authority was named:

```bash
trebaruna sign doc.pdf --p12 k.p12 --level t --tsa https://freetsa.org/tsr
```

Or use `--level bes` if you do not need one.

### "level lt needs embedded revocation (DSS) and a source for it"

`lt` and `lta` need to query OCSP, which is opt-in:

```bash
trebaruna sign doc.pdf --p12 k.p12 --level lt \
    --tsa https://freetsa.org/tsr --online-revocation
```

### "refusing to sign: the certificate ... is revoked since ..."

The certificate was revoked. Signing is refused deliberately: producing a
signature with a revoked certificate wastes everyone's time and may be unlawful.
Contact your issuer.

### "the signature could not be produced: open PDF: ..."

The file is not a valid PDF. Test with:

```bash
pdfinfo doc.pdf        # poppler
qpdf --check doc.pdf
```

### XAdES: "lta for XAdES needs a timestamp authority"

XAdES archival level requires a TSA. Add `--tsa`.

---

## Verification results that surprise

### Verdict `untrusted` — "el emisor no está en ninguna lista de confianza"

The cryptography is fine; the issuer is not supervised in the lists you have.

```bash
trebaruna trust sync
trebaruna trust list                     # is anything cached?
trebaruna verify doc.pdf --territory IT  # right country?
trebaruna certificate k.p12     # is it self-signed?
```

Most common causes, in order:

1. Lists never downloaded.
2. Wrong territory (`$LANG` guessed wrong).
3. Private CA — expected, not fixable.
4. Self-signed — expected, not fixable.

### Verdict `unknown` with exit code 3

Not a bad signature. Something prevented a decision. The first `unknown` finding
explains which:

- `trustlist.unavailable` — no list cached.
- `certificate.untrusted_issuer` — a list was read and the issuer is absent.
- `format.unsupported` — the container could not be parsed.

### Verdict `broken` on a document you just signed

Two possibilities, both worth checking:

**The document was modified after signing.** Any edit — even a harmless one, even
with a PDF editor that "preserves" signatures — breaks it. Signing is the last
step.

**The certificate had expired when you signed.** The finding
`certificate.expired_at_signing` confirms it.

### "certificate.expired_at_signing" on an old document

If a **trusted timestamp** proves the signature was made earlier, the report
judges the certificate at that time. Without one, the only time available is the
signer's own claim, and the report says so:

```
warn certificate.validity_unproven
```

This is a reason to use `--level t` for anything that must survive.

### "certificate.revoked_before_signing"

A responder said the certificate was revoked before the signature. Verify the
signing time: if the signature really predates the revocation, re-check with a
trusted timestamp present.

---

## Certificate and key errors

### "cannot read the P12: decryption password incorrect"

Wrong passphrase. Quote it if it has shell characters:

```bash
--pass 'correct horse battery staple'
```

### "unsupported private key format, or the key is encrypted and no passphrase was given"

A PEM whose key this build cannot parse. Convert it:

```bash
openssl pkcs8 -topk8 -nocrypt -in old.key -out key.pem
```

### "trebaruna signs with a Brainpool key on a card only, not from a file"

The certificate's key is on a Brainpool curve (brainpoolP256r1, P384r1 or
P512r1), as on German health professionals' cards. trebaruna signs with
such a key through the card, which does the arithmetic; Go has none for
these curves, so a PKCS#12 file or a PEM bundle holding one is refused.
Sign with the card (`--token`); see [Smartcards](smartcards.md). A
PKCS#12 file encrypted the old way (RC2, `openssl pkcs12 -legacy`) still
gives Go's "x509: unsupported elliptic curve" for the same reason.

### "cannot decrypt private key"

The passphrase was given and is wrong, or the encryption algorithm is not
supported. Re-export the key.

### The `.pem` has no certificate

A PEM bundle needs **both** the certificate and the key:

```bash
cat certificate.pem key.pem > bundle.pem
```

---

## Timestamp errors

### "TSA answered 401"

The authority needs credentials:

```bash
--tsa https://tsa.example/tsr --tsa-user account --tsa-pass secret
```

Some public authorities require registration. freeTSA does not.

### "timestamp response nonce does not match the request"

The response does not answer your request. Usually a proxy or a broken TSA. Try
another authority.

### "the token covers a different signature value"

The token is genuine but belongs to another signature. Expected if you moved a
`.tsr` between documents.

### `timestamp.untrusted_authority` with a valid token

The token verifies and is bound; its authority is not a granted qualified service
in the lists. Expected for free authorities. If it should be qualified:

```bash
trebaruna trust sync
```

---

## Trust list errors

### `trebaruna trust sync` fails for one territory

The national list's XML signature did not verify against the certificate the EU
list publishes, or it does not sign the whole list. That list goes to
**quarantine** and is not used. Causes: the state rotated its signing
certificate and the LOTL lags, or the download was tampered with. The reason
`trust sync` prints says which.

Retry later; the LOTL is updated by the EU.

### `trustlist.stale`

The cached list is past the `NextUpdate` it declares. It is still used, and the
report says so. Refresh:

```bash
trebaruna trust sync
```

### A Spanish certificate is always `untrusted`

Spain publishes its TSL only as a PDF, which cannot be parsed. This is a
limitation of the published format. The other findings — integrity, validity,
revocation — do not need a list and still apply.

---

## Seal errors

### "the identity does not fit the seal box"

The name needs more room than the box gives. Either enlarge it or drop the seal:

```bash
--box 60,540,340,700      # bigger
# or omit --box entirely for an invisible signature
```

The tool refuses to truncate: a signature showing half a name looks like a
different person.

### The seal is invisible or off the page

PDF coordinates start at the **bottom-left**, and A4 is 595×842 points. A box at
`y=600` is near the top, not the bottom.

If poppler is installed, the desktop window lets you drag the box instead of
guessing.

### Two seals, one signature

That is by design:

```bash
--box 1:60,60,280,160 --box 3:60,600,280,700
```

One cryptographic signature, several marks.

---

## Smartcard errors

See [Smartcards](smartcards.md#errors) for the full list. The two you will hit:

### "cannot open PKCS#11 token"

```bash
pcsc_scan                        # does the system see the card?
systemctl status pcscd           # is the daemon running?
pkcs11-tool --list-tokens        # is the label exactly right?
```

### "token exposes no certificate paired with a private key"

The card has no certificate linked to its key. It may need provisioning by its
issuer.

---

## Desktop window

### "The trebaruna binary was not found"

The window calls the CLI. Make it findable:

```bash
export TREBARUNA_BIN=/path/to/trebaruna
```

### The preview is blank

poppler is not installed:

```bash
sudo apt install poppler-utils       # Linux
brew install poppler                 # macOS
```

Signing still works; the seal box is typed by hand.

### `make build-gui` fails on missing GL headers

```bash
make deps-gui
```

It needs OpenGL and X11 development headers. On a headless machine, use the CLI.

---

## Local API

### "refusing to listen on ... the local API must stay on loopback"

Only `127.0.0.1`, `::1` and `localhost` are accepted. This is deliberate: a local
signing service reachable from the network is a security hole.

### 401 `token-required`

The token is missing or wrong:

```bash
TOKEN=$(cat "$XDG_RUNTIME_DIR/trebaruna/token")
curl -H "X-Firma-Token: $TOKEN" ...
```

The token is regenerated each time the server starts, and removed when it stops.

### 403 `origin-rejected`

You sent an `Origin` header that is not this server. Remove it, or send the
correct one. Browsers always send it; `curl` does not.

### 403 `path-rejected`

The path is outside every `--root`:

```bash
trebaruna serve --root /home/user/Documents --root /tmp
```

Symlinks are resolved, so a link inside a root that points outside it is also
refused.

### 404 on `GET /v1/signatures/{id}`

Signatures are returned by the `PUT` that creates them and are not stored. The
`404` says exactly that.

---

## When nothing helps

1. Reproduce with `--json`, which carries the codes rather than prose.
2. Check the file independently: `pdfsig` for PDFs, `openssl cms -verify` for
   CAdES, `xmllint` for XML integrity.
3. Try a minimal case: a one-page PDF, a `.p12` you know works, `--level bes`.

If you report a problem, include:

- `trebaruna version`
- the exact command
- the `--json` output
- the output of the independent tool you used

That is enough to reproduce nearly anything.