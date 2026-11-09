# Desktop app

The graphical window: signing, verifying, and approving what a web page asked for.

- [Installing](#installing)
- [Sign tab](#sign-tab)
- [Verify tab](#verify-tab)
- [Requests tab](#requests-tab)
- [Languages](#languages)
- [Without poppler](#without-poppler)
- [How it relates to the CLI](#how-it-relates-to-the-cli)
- [Known limits](#known-limits)

---

## Installing

The window is a separate binary because it needs cgo while the CLI is
deliberately static:

```bash
make deps-gui        # system packages: OpenGL, X11, poppler
make build-gui       # ./bin/trebaruna-desktop
make install-desktop # binary + .desktop entry + icon
```

From a release: `trebaruna-desktop` (Linux only, ~33 MB).

### Finding the CLI

The window drives `trebaruna` rather than reimplementing signing, so it must find
the binary. It looks next to itself, then on `PATH`. Override:

```bash
export TREBARUNA_BIN=/opt/trebaruna/trebaruna
```

If it cannot find one, the window says so instead of failing silently.

---

## Sign tab

Three steps on the left, the page on the right, one button at the bottom.
Nothing the document or the certificate already says is asked for.

| Step | What you do | What the window fills in |
|---|---|---|
| **1 Document** | Choose any file, or drop it on the window | The formats that fit it, and the name the signed file will get |
| **2 Certificate** | **File**: choose a `.p12`, `.pfx` or `.pem` and type its passphrase. **Card**: pick a certificate of the card in the reader and type its PIN. **Firefox**: pick a certificate of the Firefox store | Holder, identifier, issuer, expiry, and whether a trusted list vouches for it; for a card, which certificate signs and how many PIN attempts are at stake |
| **3 Signature** | Pick signed PDF, `.p7m` envelope or detached `.p7s`; for a `.p7m`/`.p7s`, add a parallel signature, counter-sign, or wrap it again | The seal position, from where it sits on the page |

The certificate is read as soon as the passphrase is typed, so a wrong
passphrase, an expired certificate or an issuer no trusted list knows is said
before signing, not after. The verdict line reads, for instance:

- *Qualified certificate: the signature has full legal effect (eIDAS).*
- *No trusted list vouches for this issuer: the signature will be technically
  sound but carry no legal weight.*
- *Expired on 12/03/2026: it can no longer sign.*

As soon as a document is chosen, its SHA-256 fingerprint appears under its name,
selectable so it can be compared elsewhere. The signer reports the fingerprint
of what it actually signed; if the two differ because the file changed in
between, the result says so and names the version that was signed.

The certificate path (or, for a card, the fingerprint of the certificate
chosen), the level and the timestamp authority are remembered between sessions.
The passphrase and the PIN never are.

### Signing with a card

Choose **Card** in step 2. The readers are read without the PIN, so looking at
the cards never spends an attempt, and every certificate on them is listed in
full (a list, not a drop-down that would cut a long name). The certificate the
card signs with — the only one, or the only one that declares non-repudiation,
such as the signature certificate of a Spanish DNIe — is chosen already; when
two certificates name the same holder, each says whether it is the one *for
signing*. Under the list, the card and the reader it sits in.

What the card says about its PIN is shown before you type it:

- *A wrong PIN has already been entered: few attempts are left before the card
  locks.*
- *One attempt left: one more wrong PIN locks the card.*
- *The card is locked: unlock it with its PUK.* — the PIN field is disabled and
  **Sign** refuses without trying.
- a reader with its own keypad asks for the PIN there, and the field is disabled.

If the card refuses the PIN, nothing is signed, the PIN field is cleared and the
cards are read again, so the attempts left are on screen before the next try. In
a batch, the remaining documents are reported as *not tried*: the same PIN is
never sent twice. The PIN reaches the signer in its environment, like the
passphrase. **Look for cards** reads the readers again after inserting a card.
Choosing a certificate file (File → Choose certificate…, or dropping one)
switches the step back to **File**.

**Card → Change the PIN…** and **Card → Unlock with the PUK…** act on the card
chosen in step 2 (or the only card present). The dialog asks for the current PIN
or the PUK, and the new PIN twice; two new PINs that differ, an empty secret or
a new PIN the card cannot take are said in the dialog without reaching the card.
A refused PIN or PUK is cleared, the dialog stays open with the reason, and the
last-attempt warning is shown when the card gives it.

**Firefox** lists the certificates of the Firefox store the same way and signs
with them in place, never exporting them. Its PIN field asks for Firefox's
primary password, and is disabled when the store has none. An empty store says
how to import a certificate into Firefox.

**More options** holds what is rarely changed: an invisible signature (signed
PDF only; the page pane then says no seal will be drawn), the level (basic, with
timestamp, LT, LTA — the authority fields appear only when the level needs
them), the reason, and the place, which is prefilled from the certificate when
it carries a locality. Next to the authority address go its user and password,
for authorities that only timestamp with an account (Aruba's
`https://servizi.arubapec.it/tsa/ngrequest.php` answers 401 without one). The
user is remembered; the password travels in the environment and is never
stored.

Press **Sign**. Signing runs off the UI thread, so a slow smartcard or a
distant TSA does not freeze the window. The result is reported in place, with
**Open**, **Folder** and **Check**; the last one opens the verification tab on
the file just signed.

The passphrase reaches the signing process through its environment, never its
command line, where other users of the machine could read it.

### Placing the seal

For a PDF signed as PAdES the right half of the window shows the page, with the
seal already in the emptiest conventional spot (bottom right first). There are
no coordinate or page-number fields: the seal goes where you put it, on the page
you are looking at.

| To | Do |
|---|---|
| Put the seal somewhere | Click the page: the seal centres under the pointer |
| Move it | Drag it, or drag from any empty spot on the paper |
| Make it larger | Drag the square handle in its bottom-right corner |
| Nudge it | Click the page, then use the arrow keys (2 pt per press) |
| Try another gap | **Find free space** cycles through the empty areas of the page |
| Change page | The arrows above the page; the seal follows the page shown |

The seal is drawn the way it will be printed: the certificate holder's name in
bold, the identifier and date, the time with its offset, and the blue rule on
the left. If it sits on top of text, its frame turns amber and the line under
the page says so.

The seal never leaves the page and never shrinks below 64x48 pt, the size at
which the certificate identity still fits without truncation.

CAdES and XAdES signatures carry no visible mark; the page pane says so instead
of showing a page you cannot use.

---

## Check tab

Choose a signed file, or drop it on the window while this tab is open. The
result reads top to bottom:

- **the verdict**, as a word and a sentence, coloured as a second signal:
  green (qualified, advanced), amber (no trusted list vouches for the issuer,
  undetermined), red (the document changed, or the signer could not sign at
  that moment);
- **one block per signature**: signer, identifier, issuer, signing time (as the
  seal prints it, with the offset), integrity, and the findings that are not
  good, in the window language.

Counter-signatures sit under the signature they sign, indented, so who
signed over whom reads at a glance. For a container, each signature lists the
files it covers, and the files no signature covers are named.

For a `.p7m` or time-stamped data (`.tsd`), **Extract the signed document**
writes the document inside next to the envelope (under a free name, never
over an existing file) and opens it. For an ASiC container, **Extract the
container's documents** unpacks it into a folder beside it. Extraction checks
nothing; the check is the verdict above.

**Save report…** writes the verification as a PDF (`verify --report`), in the
window's language, and opens it: the file and its SHA-256, the verdict, every
signature and finding.

Checking runs **offline** by default, like the CLI. The checkbox *Ask over the
network whether the certificate was revoked (OCSP)* turns revocation on and
checks again.

---

## Requests from AutoFirma pages (afirma://)

When a Spanish administration page starts AutoFirma's protocol, the system
opens `trebaruna-desktop` with the `afirma://` URI, and an approval window
shows the request before anything happens: what the page asks (sign, sign a
batch, give the certificate, save a file), the site the answer goes to and the
name the page gives itself, the data (size and SHA-256, or the address it would
be downloaded from), every document of a batch, the certificate filters the
page sets, and the warnings — among them that the answer travels to the site
under single DES. The certificate is chosen as in step 2 of the Sign tab (card
by default, Firefox store or file, with its PIN or passphrase); a certificate
the page does not accept is refused with the reason and another can be chosen.
**Sign and send** answers the page; **Decline**, or closing the window,
answers `CANCEL`. The window drives `trebaruna afirma --interactive`: the
decision, secrets included, goes to the command through a pipe, never on a
command line, and the command keeps the page waiting meanwhile.

## Requests from web pages

**Tools → Requests from web pages…** opens a separate window. It is where a
person approves what a web page asked for; it is not a tab because requests are
rare and arrive from a browser, and an empty third tab was noise the rest of
the time.

The window shows what is waiting, with the file name and the time left; on
selection, the full path and the format; and **Approve** and **Reject**.
Either asks for the **approval secret**, which `trebaruna handler` printed in a
terminal. The window does not hold it, so a window that lists requests still
cannot approve one on its own.

See [Web pages](web-pages.md) for the full flow.

---

## Network activity

**Tools → Network activity…** lists every connection made in the session: why
(timestamp, revocation check, trusted list…), where, the result and the bytes
moved, newest first. After a signature that needed the network, the line under
the Sign button names the destinations. The window opens no connection itself:
it shows what each command reported (ADR-0008, ADR-0010).

---

## Menus, shortcuts and drag and drop

Every action has a menu entry; the frequent ones have a shortcut (`Ctrl` on
Linux and Windows, `Cmd` on macOS):

| Menu | Entry | Shortcut |
|---|---|---|
| File | Open document to sign… | `Ctrl+O` |
| File | Choose certificate… | `Ctrl+K` |
| File | Check a signed document… | `Ctrl+Shift+O` |
| Signature | Sign | `Ctrl+Enter` |
| Signature | Previous page / Next page | `Ctrl+PgUp` / `Ctrl+PgDn` |
| Signature | Find free space | `Ctrl+F` |
| Card | Change the PIN…, Unlock with the PUK… | — |
| Tools | Requests from web pages… | — |
| Help | Manual, About trebaruna | — |

Dropping several files on the signing tab, or **File → Sign a folder…**, starts
a batch: every document with the same settings, each in its own format unless
an envelope or a detached signature is chosen for all; PDFs get the seal in the
corner of their first page (or none, with the invisible option); the result
lists what failed and why.

Dropping a file on the window does what the file suggests: a `.p12`, `.pfx` or
`.pem` becomes the certificate; on the Check tab any file is checked; anywhere
else it becomes the document to sign.

---

## Languages

Spanish, Italian and English, chosen from `TREBARUNA_LANG` or `$LANG`:

```bash
TREBARUNA_LANG=it trebaruna-desktop
```

The catalogue is compile-checked: a missing translation is a build error and a
test failure, not an empty label at runtime. Fyne's own strings are supplied by
hand for Italian, because Fyne does not ship them.

---

## Without poppler

The page preview and the automatic free-space detection use **poppler**
(`pdftoppm`).

Without it:

- the page pane explains that poppler is missing;
- the seal goes in the signer's default place, the bottom-right corner of page 1;
- **signing still works**.

The window says this explicitly rather than showing a blank preview that looks
like a broken document. On macOS install it with `brew install poppler`; on Linux
it is usually `poppler-utils`.

---

## How it relates to the CLI

The window calls the CLI binary. It does not link the signing packages.

This is a deliberate decision, recorded as ADR-0008: one validation path, one
behaviour, nothing to keep in sync. A bug fixed in the CLI is fixed in the window
by construction.

The cost is one extra process per operation, a few milliseconds, which is
irrelevant next to a smartcard or a TSA round trip.

The visible consequence: if `trebaruna` is not on `PATH` and `TREBARUNA_BIN` is not
set, the window cannot sign or check. Signing then reports the missing program,
and **Help → About** shows the version as unknown.

---

## Known limits

Stated rather than hidden:

- **Linux only, prebuilt.** Fyne links Cocoa on macOS; the `.app` needs a macOS
  runner to build and the CI job that does it is written but the artefact is not
  produced here.
- **No Windows build of the window.** The CLI works on Windows; the window does
  not ship.
- **Keyboard navigation is partial.** Every action is in the menu with a
  shortcut, the seal moves with the arrow keys and the form follows the tab
  order, but nothing has been audited against a screen reader.

---

## Next

- [Signing](signing.md) — the same operations, explained in depth
- [Verification](verification.md) — reading the verdict
- [Web pages](web-pages.md) — the requests you approve here