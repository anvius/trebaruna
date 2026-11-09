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
| **2 Certificate** | Choose a `.p12`, `.pfx` or `.pem`; type its passphrase | Holder, identifier, issuer, expiry, and whether a trusted list vouches for it |
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

The certificate path, the level and the timestamp authority are remembered
between sessions. The passphrase never is.

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

For a `.p7m`, **Extract the signed document** writes the document inside next
to the envelope (under a free name, never over an existing file) and opens it.

Checking runs **offline** by default, like the CLI. The checkbox *Ask over the
network whether the certificate was revoked (OCSP)* turns revocation on and
checks again.

---

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