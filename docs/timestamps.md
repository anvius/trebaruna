# Timestamps

RFC 3161 tokens: what they prove, how to obtain one, how to use it, and how to
check one.

- [What a timestamp proves](#what-a-timestamp-proves)
- [How timestamps appear in signatures](#how-timestamps-appear-in-signatures)
- [Obtaining a token on its own](#obtaining-a-token-on-its-own)
- [Verifying a token](#verifying-a-token)
- [Choosing an authority](#choosing-an-authority)
- [How the tool judges a timestamp](#how-the-tool-judges-a-timestamp)
- [Archive timestamps](#archive-timestamps)
- [Problems](#problems)

---

## What a timestamp proves

A signature carries a time — but that time is written by the signer. Anyone can
set their computer clock, or edit the field. A timestamp is different: an
independent authority signs "these bytes existed at this moment".

That is what makes it evidence. Without one, `verify` says so:

```
! la fecha de firma la declara el firmante y no está sellada
```

With one, the time is a fact:

```
good timestamp.bound      the timestamp covers this signature
good timestamp.accredited the authority is a qualified service
```

The distinction matters when a certificate expires. A signature made in 2020 with
a certificate that expired in 2022 is fine — but only if there is proof it was
made in 2020.

---

## How timestamps appear in signatures

The level decides:

| Level | What is timestamped |
|---|---|
| `t` | The signature value (CAdES, PAdES, XAdES) |
| `lt` | Nothing new; `t` is included |
| `lta` | The entire document, including the validation material |

```bash
trebaruna sign atto.pdf --p12 k.p12 --pass x --level t --tsa https://freetsa.org/tsr
```

The authority is contacted during signing. Without `--tsa`, a level that needs a
timestamp is refused with an explanation rather than silently downgraded.

### What it adds to the file

- **CAdES-T**: a `signature-time-stamp` unsigned attribute in the CMS container.
- **PAdES-B-T**: a `/DocTimeStamp` entry in the signature dictionary.
- **XAdES-T**: a `xades:SignatureTimeStamp` element inside
  `xades:UnsignedSignatureProperties`.

All three follow the same rule: the token covers the **signature value**, not the
document, so it proves the signature existed at that moment. For XAdES the token
covers the canonical form of `ds:SignatureValue` — a detail that matters, because
hashing the wrong serialisation produces a token nobody can verify.

---

## Obtaining a token on its own

For a document you have already signed, or for any file you want to prove existed:

```bash
trebaruna timestamp atto.pdf --tsa https://freetsa.org/tsr
# → atto.pdf.tsr
```

Over a digest, when you do not want to send the file:

```bash
trebaruna timestamp --hash 3a7bd3e2f1c0... --tsa https://freetsa.org/tsr --out proof.tsr
```

| Flag | Meaning |
|---|---|
| `--tsa` | Authority URL (required) |
| `--hash` | Timestamp a digest instead of a file |
| `--tsa-user`, `--tsa-pass` | Basic auth, for authorities that need an account |
| `--out` | Output path |
| `--json` | Machine-readable result |

The `.tsr` file is a standard `TimeStampResp`, readable by any RFC 3161 tool.

---

## Verifying a token

```bash
trebaruna verify-tsr atto.pdf.tsr            # the token on its own
trebaruna verify-tsr atto.pdf.tsr atto.pdf   # also check it matches this file
trebaruna verify-tsr --hash <hex> proof.tsr  # against a digest
```

Exit `0` when the token's signature verifies and, if a document was given, its
imprint matches.

To confirm independently:

```bash
openssl ts -verify -in atto.pdf.tsr -data atto.pdf \
    -CAfile tsa-ca.pem -untrusted tsa-ca.pem
```

`openssl` needs the TSA's certificate as an anchor, which is why the tool's own
check is typically easier.

---

## Choosing an authority

Free, qualified where it matters:

| Authority | URL | Notes |
|---|---|---|
| **freeTSA** | `https://freetsa.org/tsr` | Free, no account, widely used for testing and small operations |
| **DFN** (Germany) | `https://zeitstempel.dfn.de/` | Free for research and education |
| National qualified providers | see below | Required when the recipient expects a qualified timestamp |

To list the **qualified** authorities your national list publishes:

```bash
trebaruna trust sync
trebaruna trust show IT | grep -i QTST
```

A timestamp from a free authority is cryptographically valid and proves the time.
Whether it counts as *qualified* depends on the service being listed — which is
exactly what the `timestamp.accredited` finding checks.

Some authorities require credentials; the tool supports Basic auth:

```bash
--tsa https://tsa.example/tsr --tsa-user account --tsa-pass secret
```

---

## How the tool judges a timestamp

Three independent conditions, checked separately:

| Condition | What it proves |
|---|---|
| **Bound** | The token's imprint matches this signature's value |
| **Accredited** | A granted qualified authority in an authenticated list can issue it |
| **Time-stamping certificate** | The token's certificate carries `id-kp-timeStamping` |

If all three hold: `timestamp.accredited`. Otherwise the report names what is
missing:

```
warn timestamp.untrusted_authority
     no granted TSA/QTST in the authenticated trust list issued it
```

A token can be perfectly valid — correct signature, matching imprint — and still
not be accredited, because nobody is listed as supervising that authority. Those
are different facts and the report separates them.

### One subtlety worth knowing

Some states publish the authority's CA in their list; others publish the
time-stamping unit's own certificate. The tool accepts both, matching the exact
certificate first. It was measured: of 231 granted qualified TSA services across
18 national lists, 227 publish the unit itself and only 60 can be reached through
their issuer. Matching only by issuer would have left 167 qualified authorities
unproven while looking implemented.

---

## Archive timestamps

`lta` adds a second, larger timestamp that covers **everything**, including the
validation material added by `lt`:

```bash
trebaruna sign mutuo.pdf --p12 k.p12 --pass x \
    --level lta --tsa https://freetsa.org/tsr --online-revocation
```

This is what protects a signature beyond the lifetime of the certificates that
made it checkable. When the OCSP responder and the CA both disappear, the proof
that they behaved correctly at signing time is inside the sealed bytes.

- **PAdES-B-LTA**: a `/Type /DocTimeStamp` signature over the whole file.
- **XAdES-A**: `xades141:ArchiveTimeStamp` over every object of the signature.

Both are verified with `openssl ts -verify`.

Note for XAdES: `--level lt` is not available, since XAdES has no `/DSS`
equivalent in this implementation. Use `lta` directly when you need long-term
protection.

---

## Problems

### "level t needs a timestamp authority"

You asked for a level that requires a TSA without giving one. Add `--tsa`, or use
`--level bes`.

### "TSA answered 401"

The authority requires credentials. Add `--tsa-user` and `--tsa-pass`. Many public
authorities need an account; freeTSA does not.

### "timestamp response nonce does not match the request"

The response does not correspond to your request. Usually a proxy or a misbehaving
TSA. Try another authority.

### "the token covers a different signature value"

The token is real but belongs to another signature. If you moved a token between
documents, this is the expected and correct refusal.

### `timestamp.untrusted_authority` with a valid token

The token is fine and bound; its authority is simply not in the lists. If it is a
free authority, that is expected. If it is a qualified one, run
`trebaruna trust sync` — the list may be missing or stale.

---

## Next

- [Trust lists](trust-lists.md) — where accreditation comes from
- [Signing](signing.md#choosing-a-level) — which level you need
- [Verification](verification.md) — reading the report