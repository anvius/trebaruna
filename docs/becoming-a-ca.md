# Becoming a certificate authority in Spain

What it actually takes to become a **qualified trust service provider** issuing
qualified certificates, from someone who has read the standards and the Spanish
scheme rather than done it. Read the disclaimer first.

> **This is not legal advice, and it is not a shortcut.** The requirements below
> come from Regulation (EU) No 910/2014 (eIDAS) and from the Spanish trust list
> scheme, whose operator the list itself names:
>
> ```
> SchemeOperatorName  MINISTERIO DE ASUSTOS ECONOMICOS Y TRANSFORMACION DIGITAL
> SchemeTerritory     ES
> ```
>
> The unit that handles trust service supervision inside that ministry is the
> one to approach, and **its name and procedure have changed more than once**.
> Ask the ministry itself which unit currently does this, and confirm every step
> below with them and with a lawyer before spending money. What is stated here is
> what the regulation and the published scheme say; the administrative detail is
> theirs to confirm.

---

## The short answer

Yes, it is complex. It is not the cryptography — that is the easy part, and this
repository demonstrates it. What takes two years and a large budget is:

- becoming a **supervised financial-adjacent entity** with capital, audits and
  insurance;
- passing a **conformity assessment audit** against ETSI standards by an
  accredited body;
- operating a **certificate lifecycle** with identity proofing, hardware HSMs,
  physical security and 24/7 revocation;
- maintaining **liability** for signatures you issued.

| Question | Answer |
|---|---|
| Can a person do it alone? | No. It is an entity-level authorisation. |
| Is it expensive? | Yes. Realistically six figures to start, five to six figures a year to run. |
| Does it need complex infrastructure? | Yes, but the infrastructure is the cheapest part. |
| How long? | 12–24 months to first qualified certificate, typically. |
| Is there a cheaper legal route? | Qualified **timestamps** and **seals** are lighter than qualified **signature** certificates. See [the ladder](#the-ladder-actually-start-at-the-bottom). |

---

## Two different things people mean

Before anything else, separate these:

**A CA that issues certificates your own systems trust.** Anyone can do this
today. This repository can sign with a self-signed certificate in one command. It
means nothing outside your organisation, and that is often all a company needs for
internal document flow.

**A Qualified Trust Service Provider (QTSP).** A supervised entity whose
certificates make signatures legally equivalent to handwritten ones across the EU.
This is what the rest of this document is about.

The gap between them is not technical. It is regulatory, financial and
organisational.

---

## What the law requires

### The regulation

**Regulation (EU) No 910/2014** (eIDAS) is the framework. Relevant articles for a
prospective CA:

| Article | What it says |
|---|---|
| 17 | A qualified trust service requires **supervision** by a supervisory body |
| 19 | Security requirements and incident notification |
| 20 | **Supervision and audits**: at least every 24 months, at your cost |
| 21 | Start of operation: notify the supervisory body **before** starting |
| 22 | **Conformity assessment** by an accredited body before starting, and every 24 months |
| 24 | Publication in the national **trusted list** |

Article 24 is the one that matters for this tool: a certificate is recognised
across the EU because it appears in the list, and the list appears in the EU LOTL.
That is exactly the chain `pignus trust sync` verifies.

### The Spanish scheme

The Spanish trusted list is published by the **Ministerio de Asuntos Económicos y
Transformación Digital** at:

```
https://tsl.digital.gob.es/TSL.xml
```

The list itself names its operator and its scheme rules:

```
SchemeOperatorName     MINISTERIO DE ASUNTOS ECONOMICOS Y TRANSFORMACION DIGITAL
SchemeTerritory        ES
TSLType                http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric
SchemeRules            .../schemerules/ES  +  .../schemerules/EUcommon
```

You can read it with this tool:

```bash
pignus trust sync --territory ES
pignus trust show ES --type CA/QC | head -20
```

Those are your competitors, and their entries are the format yours will take.

### The standards you will be audited against

| Standard | Covers |
|---|---|
| **ETSI EN 319 401** | General policy requirements for trust service providers |
| **ETSI EN 319 411-1** | Policy for CAs issuing **qualified** certificates |
| **ETSI EN 319 411-2** | Policy for non-qualified certificates |
| **ETSI EN 319 412-x** | Certificate profiles (what goes in each field) |
| **ETSI EN 319 421** | Policy for **timestamping** authorities |
| **ETSI EN 319 422** | Timestamping protocol |
| **ETSI EN 319 102-1** | Signature validation procedures |
| **EN 319 403** | How the conformity assessment itself is performed |
| **ISO/IEC 27001** or equivalent | Information security management |
| **CWA 14167-1 / EN 419 221-5** | Requirements for the **HSM** protecting the CA key |

The audit is against these, so the documentation you must write is essentially a
**Certificate Policy** and a **Certification Practice Statement** that map onto
them, clause by clause.

---

## The practical process in Spain

This is the sequence as it is generally described by the Ministry and by
accredited auditors. Confirm each step with them; the order of some filings varies
by case.

### 1. Decide what you are issuing

The scope determines almost everything: the audit, the policy, the price.

| Service | Difficulty | Notes |
|---|---|---|
| Qualified **timestamping** (QTST) | Lowest of the qualified set | No identity proofing of subscribers; you run an HSM and an accurate clock |
| Qualified **seals** (QSeal) | Low–medium | No natural persons to identify; organisational vetting only |
| Qualified **signature certificates** for natural persons (QES) | Highest | Identity proofing, face-to-face or equivalent, per subscriber |
| Qualified **website authentication** certificates (QWAC) | Medium–high | Regulated by browsers as well as by eIDAS |

**Start with timestamping or seals.** Issuing QES certificates for the public is
where the liability and the operational burden really are.

### 2. Incorporate and capitalise

You need a legal entity in Spain, with:

- **share capital** and professional indemnity insurance sized against the
  liability cap you declare in your policy — the figure is yours, but the auditor
  will test that you can honour it;
- **segregation of duties**: the people who operate the HSM must not be the people
  who authorise certificate issuance — the "four-eyes" model, evidenced in
  procedure not just in intent;
- payroll for the roles ETSI EN 319 401 requires by name: security officer, system
  administrator, system auditor, registration authority.

### 3. Build the infrastructure

The cryptography is not the hard part, but the requirements around it are strict:

- **HSM certified to a recognised level** (FIPS 140-2/3 Level 3, or Common
  Criteria EAL4+ with the appropriate protection profile) holding the CA private
  key for its whole life;
- **key ceremony** with witnesses, a script, a signed record, and split knowledge
  of the activation data — the auditor will ask for the video;
- **root key offline**, in a safe, in a room with access control and logging;
- **dual control** on every operation that touches the key;
- **clock** with traceable time source for timestamps and validity dates;
- **revocation**: OCSP responder and CRLs published continuously, with a
  commitment on availability written into the policy and measured;
- **disaster recovery** with a tested restore, not a documented one;
- **logging** tamper-evident, retained for the periods the policy states.

None of this requires unusual software. A great deal of it is procedure.

### 4. Write the policy and the practice statement

The **CP/CPS** is the document the audit is conducted against and the document
your customers' validators rely on. Roughly 60–150 pages, mapping ETSI EN 319
411-1 clause by clause: subscriber obligations, identity verification method,
key lifetimes, publication, revocation reasons, liability caps, audit and
disclosure.

It is published, and it is binding. Promising availability you cannot deliver is
the fastest way to fail the second audit.

### 5. Conformity assessment audit

Performed by a **conformity assessment body** accredited for eIDAS, against
EN 319 403 and the applicable ETSI policies. It covers:

- documents and procedures (desk review);
- the site, the HSM room, the key ceremony records;
- a technical test: certificates the auditor requests must validate correctly;
- incident handling, with at least one simulated incident.

A finding at this stage means correcting it and being re-audited. Budget for two
rounds.

### 6. Notify the supervisory body and get listed

With the audit report, you notify the ministry's trust services unit before
starting to operate (eIDAS art. 21). Once accepted, your services are added to
the Spanish trusted list — and, after the EU process catches up, to the LOTL.

**Only then** does a certificate you issue produce the verdict `qualified` in this
tool, because that verdict is defined by the list, not by the certificate.

You can watch it happen:

```bash
pignus trust sync --territory ES
pignus trust show ES --match "your company name"
```

### 7. Operate, and keep being audited

- Full **re-audit at least every 24 months** (art. 20).
- **Incident notification**: a security breach that affects a qualified service
  must be reported; failing to do so is itself a breach.
- **Termination plan**: what happens to your certificates if you close. The
  policy must state it, and the auditor checks it, because a CA that vanishes
  takes every signature it issued with it.

---

## What it costs

Order-of-magnitude figures, gathered from public procurement and from providers of
the relevant services. Treat them as a starting point for your own budget, not as
quotations.

| Item | One-off | Annual |
|---|---|---|
| Legal entity, capital, insurance | 5,000–30,000 | 5,000–20,000 |
| CP/CPS drafting (external counsel) | 15,000–50,000 | maintenance |
| Conformity assessment audit | 25,000–60,000 | same again every 24 months |
| HSM (certified, HA pair) | 20,000–80,000 | support ~15% |
| Secure facility, rack, access control | 10,000–50,000 | 5,000–20,000 |
| Staff: security officer, ops, audit | — | 150,000–400,000 |
| OCSP/CRL infrastructure, monitoring | — | 10,000–30,000 |
| **Realistic first year** | **≈ 150,000–400,000** | **≈ 200,000–500,000** |

The dominant costs are **people and audit**, not technology. That is the part
people underestimate.

---

## The ladder: actually start at the bottom

If the goal is "my signatures are qualified", buying a certificate from an
existing QTSP costs a few tens of euros a year. Becoming one only makes sense if
issuing is your business.

If it is, climb in this order:

1. **Non-qualified CA for your own organisation.** Days of work. This tool already
   does it. Useful, honest, and worth nothing to third parties.
2. **Qualified timestamping (QTST).** The lightest qualified service. No identity
   proofing, one protocol, one audit. Many organisations start here because it also
   strengthens every signature they already make.
3. **Qualified seals.** Organisational vetting only, which removes the hardest
   operational requirement.
4. **QES certificates.** Only when you already run a supervised operation and have
   the compliance function to sustain it.

Each step reuses the previous one's facility, HSM and compliance function, so the
incremental cost of the next step is much smaller than the first.

---

## What this repository gives you, and what it cannot

Honest scope:

| You still have to do | You get from this tool |
|---|---|
| Entity, capital, insurance | — |
| CP/CPS | — |
| Audit | — |
| HSM and key ceremony | — (the HSM is a vendor product) |
| Identity proofing | — |
| **Issue certificates** | Your CA issues them; the tool signs with the resulting keys |
| **Produce signatures people can verify** | ✅ CAdES, PAdES, XAdES up to `lta`, each verified by independent tools |
| **Prove your certificates chain to a qualified issuer** | ✅ `pignus certificate --territory ES` |
| **Confirm your services appear in the Spanish list** | ✅ `pignus trust show ES --match "…"` |
| **Check your OCSP responses before you rely on them** | ✅ four explicit revocation states |
| **Test your TSA end to end** | ✅ RFC 3161 issue and verify |

A concrete use: once you are listed, run `pignus trust sync` and `pignus trust
show ES` to confirm the entry you wrote is the one validators read, and sign a
sample document with `--level lta` to prove your whole chain — certificate,
timestamp, OCSP, archive — verifies by tools that are not yours.

---

## Sources

Primary, and worth reading before talking to anyone:

- **Regulation (EU) No 910/2014**, articles 17–24 — the legal basis.
- **Implementing Regulation (EU) 2015/1505** — the format of trusted lists.
- **ETSI EN 319 401, 411-1, 411-2, 412-x, 421** — published free of charge
  by ETSI.
- **Spanish trusted list**: `https://tsl.digital.gob.es/TSL.xml`, readable with
  `pignus trust show ES`.
- **EU LOTL**: `https://ec.europa.eu/tools/lotl/eu-lotl.xml`.
- **EN 319 403** — how your audit will be conducted.

Ask the **Ministry of Economic Affairs and Digital Transformation** which unit
handles trust service supervision today before drafting anything; the name and the
procedure have changed more than once. The list's own `SchemeOperatorName` is the
place to start, and it is the authority for the rest.

---

## If you only take one thing from this

The technology in this repository is the part you can have solved by Friday.

The other part — supervision, audit, liability, staff — is what "being a CA"
actually means, and no amount of code replaces it. Start with timestamping, talk
to the ministry early, and budget for two audits.