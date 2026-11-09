# Smartcards

Signing with a physical token: PKCS#11 setup, PINs, and what has actually been
tested.

- [Do you need this?](#do-you-need-this)
- [The token build](#the-token-build)
- [Platform setup](#platform-setup)
- [Finding the module and the label](#finding-the-module-and-the-label)
- [Signing](#signing)
- [What has been tested, and what has not](#what-has-been-tested-and-what-has-not)
- [Errors](#errors)

---

## Do you need this?

If you can **export** your certificate and key as a `.p12`, you do not need this
page: use `--p12` and the static binary.

You need PKCS#11 when the key **cannot leave the card**. That is the better
design — it is what makes the device qualified — and it is common for national
identity cards.

| Situation | Use |
|---|---|
| Bank or authority gave you a `.p12` | `--p12`, static binary |
| Card exports a `.p12` | `--p12`, static binary |
| Key is inside the card and cannot be exported | `--token`, `trebaruna-token` |

---

## The token build

PKCS#11 loads a driver at runtime, which requires cgo. The static binary
deliberately excludes it, so smartcard support is a separate build:

```bash
make build-token        # → bin/trebaruna-token
```

It needs a C compiler and `libdl`:

```bash
sudo apt install build-essential          # Debian / Ubuntu
sudo dnf install gcc                      # Fedora
```

Same commands as `trebaruna`, same flags, plus `--token`, `--pin` and `--module`.

---

## Platform setup

### Linux

The card reader is reached through **pcscd**:

```bash
sudo apt install pcscd pcsc-tools opensc
sudo systemctl enable --now pcscd
pcsc_scan                                     # is the card seen?
```

`pcsc_scan` should print the card's ATR when you insert it. If it does not, the
problem is below this tool: reader, driver, or card.

### macOS

Built in; no daemon to install. Install OpenSC with its package or
`brew install opensc`; trebaruna finds the module in `/Library/OpenSC/lib`,
`/opt/homebrew/lib` or `/usr/local/lib`.

### Windows

Install OpenSC (its installer puts `opensc-pkcs11.dll` in `System32`, where
trebaruna finds it), or the vendor's middleware and pass its DLL with `--module`.

---

## Finding the module and the label

trebaruna finds the free OpenSC module by itself, and picks the card and the
certificate when there is no doubt. `--module`, `--token` and `--certificate`
are only needed when there is.

### List the tokens

The tool can do this itself, and its answer is more useful than the generic one
because it says what this tool needs and what is wrong:

```bash
trebaruna token                      # OpenSC, found on this system
trebaruna token --module /path/to/vendor-pkcs11.so
```

```
slot 0: Identifies Slot 0
  token:      Carta Nazionale
  maker:      Example Manufacturer
  serial:     0123456789
  login:      login required
  certificate: CN=MARIA LOPEZ GARCIA MARTINEZ (FIRMA),C=ES
    issuer:    CN=Example Issuing CA,C=ES
    serial:    4a2b1d
    sha-256:   a18a885526bbb04eea216f1135dd2f858f89ffe3471a52d606e785e08c144beb
    signs:     by default, when no --certificate is given
    valid:     2026-01-14 09:22:00Z .. 2029-01-14 09:22:00Z
    key usage: contentCommitment
  certificate: CN=MARIA LOPEZ GARCIA MARTINEZ (AUTENTICACION),C=ES
    issuer:    CN=Example Issuing CA,C=ES
    serial:    4a2b1c
    sha-256:   40be7f7afc580abb743542a9827a37b54686ea29b82ada037b3de84933e60890
    valid:     2026-01-14 09:22:00Z .. 2029-01-14 09:22:00Z
    key usage: digitalSignature
```

The **token label** is what goes in `--token`; the **serial** or the
**sha-256** fingerprint (or its first eight digits or more) is what goes in
`--certificate`. The **signs** line says which certificate a signature uses
when none is named. The **key usage** tells you whether a certificate can sign a
document at all: one that declares no signing usage cannot, and a missing
certificate means the card holds a key with nothing to identify it.

Add `--json` for machine-readable output.

This command reads the public objects, so it works **without the PIN**. It is
the first thing to run when the card does not work, because it distinguishes
the four cases that otherwise look identical: no reader, no card in the reader,
a card that cannot be logged into, and a card that holds nothing usable.

If the tool was built without cgo, it says so and points at the token build.

The generic tool does the same job:

```bash
pkcs11-tool --list-tokens
```

```
Token 0:
    Label:  Carta Nazionale
    Model:  ...
```

The `Label` is what goes in `--token`.

### Find the module

Without `--module`, trebaruna looks for OpenSC where each system installs it,
in this order, and uses the first one present:

| System | Locations tried |
|---|---|
| Debian/Ubuntu | `/usr/lib/<triplet>/opensc-pkcs11.so`, `/usr/lib/<triplet>/pkcs11/opensc-pkcs11.so` (`x86_64-linux-gnu`, `aarch64-linux-gnu`, …) |
| Fedora, openSUSE | `/usr/lib64/opensc-pkcs11.so`, `/usr/lib64/pkcs11/opensc-pkcs11.so` |
| Arch, others, BSD | `/usr/lib/opensc-pkcs11.so`, `/usr/lib/pkcs11/opensc-pkcs11.so`, `/usr/local/lib/opensc-pkcs11.so` |
| macOS | `/Library/OpenSC/lib/opensc-pkcs11.so`, `/opt/homebrew/lib/opensc-pkcs11.so`, `/usr/local/lib/opensc-pkcs11.so` |
| Windows | `C:\Windows\System32\opensc-pkcs11.dll`, `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll` |

A vendor module is used only when you give it with `--module`. When OpenSC is
not found and no module is given, the command says so instead of guessing.

### Check what is inside

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
            --login --pin 123456 --list-objects
```

You should see a private key, a public key, and a certificate. If the certificate
is missing, the card exposes a key with nothing to identify it, and signing will
fail with "no certificate paired with a private key".

---

## Signing

The PIN is read from `TREBARUNA_PIN` (or `--pin`, which leaves it in the shell
history; ADR-0006).

```bash
read -rs TREBARUNA_PIN && export TREBARUNA_PIN   # typed without echo
trebaruna-token sign atto.pdf --card              # the card in the reader
trebaruna-token sign atto.pdf --token "Carta Nazionale"
```

Naming the certificate is enough; the reader that holds it is found:

```bash
trebaruna-token sign atto.pdf --certificate 4a2b1d
trebaruna-token sign atto.pdf --certificate a18a8855
```

With a vendor module:

```bash
trebaruna-token sign atto.pdf --token "Carta Nazionale" \
    --module /path/to/vendor-pkcs11.so
```

**Which certificate signs.** A card often holds two: the Spanish DNIe and most
Italian signature cards carry one certificate to authenticate and one to sign,
and only the second declares non-repudiation (`contentCommitment`). Without
`--certificate`, the only certificate of the card signs, or the only one that
declares non-repudiation. When that leaves a doubt — two signing certificates,
or none that declares it — nothing is signed and the error lists the
certificates with their serial and fingerprint. A `--certificate` that matches
nothing on the card is refused: the signature never goes out under another
certificate than the one asked for.

**The PIN and its attempts.** A card allows a few PIN attempts (three on most)
before it locks, and unlocking it needs the PUK. trebaruna spends none it can
avoid:

- the card's state is read before any login: a locked card, or one whose PIN
  must be changed, is reported without trying;
- an empty PIN is never sent (the card would count it), except to a reader with
  its own keypad, which asks for it;
- a refused PIN stops the run: in a batch the remaining documents are reported
  as *not tried* instead of trying the same PIN on each;
- after a refusal the card is read again, and the message says when the next
  mistake would lock it.

`trebaruna token` prints the state as `pin:` (a wrong PIN was entered, one
attempt left, locked, must be changed) and `pin` / `pinpad` in `--json`.

**Which card.** With `--token`, the card with that label; two cards with the
same label, such as two identity cards, are told apart by `--certificate`. Without it, the card
that holds the named certificate, or the only card present. The readers are
read without the PIN, so the PIN is never tried on a card that is not the one
meant. With two cards that both fit, nothing is signed and the error names their
labels.

### Verify your own output

```bash
trebaruna verify atto_signed.pdf
```

Worth doing once per card: it is how you find out that the card's certificate is
not in any public list, before a counterparty does.

---

## What has been tested, and what has not

This is the honest state, and it matters more here than elsewhere.

### Tested

Against **SoftHSM2**, which is a real PKCS#11 driver in software:

- a key pair generated inside the token;
- a certificate issued for that key;
- signatures produced through the token;
- CAdES verified with `openssl cms -verify`;
- XAdES reporting `integrity: good`;
- PAdES reporting `Signature is Valid` in `pdfsig`;
- the reader, the token, the serial number and the certificates on the card
  listed by `trebaruna token`.

The test suite runs this in CI with `-tags token`.

### Not tested

**A physical smartcard.** There is none available to test with here. The code path
is identical — same driver interface, same calls — but "identical path" is not
evidence, and this project does not present it as such.

What *is* tested is the part that a physical card and a software card differ
on: the reader enumeration, the token information, and the reading of the
certificate objects. What is not tested is the part they share, because the
driver interface is the same.

Two things a physical card does that SoftHSM does not, and that this project
cannot claim to have verified:

- **PIN handling.** A card can refuse a wrong PIN, lock after a few attempts, or
  require a change on first use. The driver reports each of those and the
  `trebaruna token` output names them, but no wrong PIN was ever sent to a card
  that could be damaged by it.
- **Card readers that need pcscd.** The reader path was exercised with a
  software module that needs no daemon.

If you use a card and it works, or it does not, that report is valuable.

### A bug this found

The first real run against a driver failed with `context is closed`: the session
was being closed before the signature was produced, so every operation ran against
a dead driver. It had never been exercised, only compiled. It is fixed, and a
regression test now covers it.

---

## Errors

### "cannot open PKCS#11 token ... check: systemctl status pcscd"

The driver is not reachable. In order:

1. `pcsc_scan` — does it see the card?
2. `systemctl status pcscd` — is the daemon running?
3. Is the label exactly right? Case and spaces matter.
4. Is the module the one for your card? A vendor card usually needs its own.

### "token exposes no certificate paired with a private key"

The card has a key but no certificate, or the certificate is not linked to the
key. List the objects:

```bash
pkcs11-tool --module <path> --login --pin <pin> --list-objects
```

If the certificate is absent, the card needs provisioning by its issuer. If it is
present but the IDs differ, the middleware is misconfigured.

### "context is closed"

This was a bug in this tool, fixed in 0.2. If you see it on an older build,
upgrade.

### The PIN is refused

Cards lock after a small number of wrong attempts, usually three. If the card is
locked you need a PUK from its issuer. Check the layout: some cards want 5 digits,
some 6, some 8.

### "unsupported private key format"

You passed a `.p12` to `--token`, or vice versa. They are different key sources;
use only one.

---

## Next

- [Certificates](certificates.md) — which key types are accepted
- [Signing](signing.md) — levels and seals
- [Troubleshooting](troubleshooting.md) — errors outside the card itself