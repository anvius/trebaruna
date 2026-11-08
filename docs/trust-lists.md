# Trust lists

Where "trusted issuer" comes from, why a downloaded list is not enough, and what to
do when a verdict surprises you.

- [Why lists at all](#why-lists-at-all)
- [How a list becomes trusted](#how-a-list-becomes-trusted)
- [Working with the lists](#working-with-the-lists)
- [What is inside a list](#what-is-inside-a-list)
- [Coverage](#coverage)
- [Reading a verification against the lists](#reading-a-verification-against-the-lists)
- [When the verdict is "untrusted"](#when-the-verdict-is-untrusted)
- [Maintenance](#maintenance)

---

## Why lists at all

A signature says "this key signed these bytes". It says nothing about whether the
key belongs to anyone in particular — that claim comes from the **certificate**,
and the certificate's authority comes from being **supervised**.

In the EU, that supervision is published. Each member state publishes a **Trusted
List** (TSL) of the trust service providers it supervises, and the EU publishes a
**List of the Lists** (LOTL) pointing at them. Regulation (EU) No 910/2014 —
eIDAS — makes this the authoritative register.

So "is this issuer trusted" has a real answer, and it is not "does the certificate
look plausible".

---

## How a list becomes trusted

This is the part that distinguishes a verification tool from a downloader.

```
LOTL (EU) ── lists every national TSL, with its signing certificates
    │
    └── TSL (IT, ES, DE, …) ── signed XML
            │
            └── verified against the certificate the LOTL publishes for it
                    │
                    └── accepted into the cache, or quarantined
```

A national list is only used when **its own XML signature verifies against the
certificate the EU list publishes for it**. A file that merely downloaded is not
an anchor: an attacker who can intercept your network could otherwise hand you a
list naming their own CA as qualified.

Concretely, `pignus trust sync`:

1. Downloads the LOTL from `https://ec.europa.eu/tools/lotl/eu-lotl.xml`.
2. For each territory, extracts the list URL **and the certificates authorised to
   sign it**.
3. Downloads the national list.
4. Verifies the national list's XML signature against those certificates.
5. Caches it only if step 4 succeeds.

A list that fails goes to **quarantine**, never to the cache. The tool will report
it as unavailable rather than use it.

---

## Working with the lists

### Download

```bash
pignus trust sync
```

```
IT  562 services, 142 qualified CAs   ok
ES  ...                                ok
DE  ...                                signature verification failed → quarantine
```

### Inspect what is cached

```bash
pignus trust list
```

Shows each territory, its service count, when it was downloaded, and when it says
it should be refreshed.

### Look at one territory

```bash
pignus trust show IT
pignus trust show ES --match fnmt          # is my issuer in there?
pignus trust show IT --type TSA/QTST       # only timestamp authorities
pignus trust show ES --match fnmt --json
```

Lists the services: provider, service name, type, status, and validity. `--match`
searches provider and service name; `--type` filters by service type.

This is the command that answers "will my signature verify for someone else?" —
run it before you sign.

### Refresh a single territory

```bash
pignus trust sync --territory IT
```

### Point at a different LOTL

```bash
pignus trust sync --lotl https://example.org/eu-lotl.xml
```

### Cache location

`$XDG_CACHE_HOME/pignus/tsl`, normally `~/.cache/pignus/tsl`.

Override with `PIGNUS_CACHE`:

```bash
PIGNUS_CACHE=/srv/pignus pignus trust sync
```

---

## What is inside a list

Each service entry carries:

| Field | Meaning |
|---|---|
| **Provider** | The organisation operating the service |
| **Service name** | The specific service |
| **Type** | `CA/QC` (qualified CA), `TSA/QTST` (qualified timestamp), `AdESigQC` (qualified signature service) |
| **Status** | `granted`, `withdrawn`, `suspended`, … |
| **Since** | When the current status began |
| **Certificates** | The certificates the service operates |

Only services that are **granted** and **qualified** are used for verdicts. A
withdrawn service still appears in the list, and the tool reads the status rather
than the mere presence of the name — this is why a CA that once issued qualified
certificates but no longer does will not silently keep vouching for new ones.

The date matters too: a service granted in 2024 cannot have issued a certificate
that signed something in 2023, and the tool checks that.

---

## Coverage

The EU list is the primary source. What it gives you:

| Coverage | Territories |
|---|---|
| **Full** (machine-readable XML) | 19 territories, including ES, IT, DE, NL, BE, AT, PL, SE, LV, RO, SK, HR, SI, IE, LT |
| **Not machine-readable** | FR, PT, LU, BG, CZ, DK, EE, HU, IS, NO publish their list only as a PDF |

Spain publishes **both** a PDF and an XML pointer in the EU list, and the XML one
is used. An earlier version took the first pointer it found — the PDF — and
rejected the whole territory, which made every Spanish qualified signature read as
untrusted. That is fixed, and the pointer selection is pinned by tests.

For the territories that only publish a PDF there are no services to parse, so no
verdict can come from their list. That is a limitation of the published format,
not of the parser, and the tool says so rather than pretending.

Verified against the real lists: **ES 442 services, 131 qualified** (six active
FNMT-RCM qualified CAs among them), **IT 562 services, 142 qualified**.

---

## Reading a verification against the lists

```
certificate.trusted        good      the issuer is granted in an authenticated list
certificate.untrusted_issuer unknown  no list vouches for this issuer
trustlist.unavailable      warn      nothing cached for this territory
trustlist.stale            warn      the cached list is past its refresh date
```

`untrusted` and `unavailable` are different:

- **`untrusted_issuer`** — a list was read, and the issuer is not in it.
- **`trustlist.unavailable`** — no list was read at all.

The second is a problem with your setup; the first is a fact about the
certificate.

---

## When the verdict is "untrusted"

Work through these in order:

**1. Are the lists downloaded?**

```bash
pignus trust list
```

Empty? Run `pignus trust sync`.

**2. Is the right territory selected?**

```bash
pignus verify atto.pdf --territory IT
pignus verify atto.pdf --territory EU
```

The default comes from `$LANG`. A Belgian certificate checked with the Italian
list will be `untrusted` — correctly.

**3. Is the issuer a private CA?**

Enterprise PKI, a bank, a university. The cryptography is sound; the CA is simply
not supervised under eIDAS. For internal use that is expected and fine.

**4. Is it self-signed?**

`pignus certificate k.p12 --pass x` will say so. Self-signed means no third
party vouches for the identity, and no list will ever change that.

**5. Is the list stale?**

```bash
pignus trust sync
```

A CA granted last month will not appear in a list from last year.

---

## Maintenance

Lists change. A service gets granted, suspended or withdrawn; a provider renames
itself; a certificate is rotated.

Refresh periodically:

```bash
# weekly
0 6 * * 1 pignus trust sync >/dev/null 2>&1
```

The tool does not phone home or refresh on its own. That is deliberate: a
verification must work offline, and a tool that quietly downloads things in the
background is a tool you cannot reason about.

When a cached list is past the `NextUpdate` the list itself declares, `verify`
reports:

```
trustlist.stale   warn   the cached list is past its next update
```

It still uses it, and it tells you it did.

---

## Next

- [Verification](verification.md) — what the verdicts mean
- [Timestamps](timestamps.md) — the qualified authorities in the lists
- [Certificates](certificates.md) — inspecting your own