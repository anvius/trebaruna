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

The form, in order:

| Field | Notes |
|---|---|
| **Document** | File picker; the format is inferred from the suffix |
| **Certificate** | `.p12`, `.pfx` or `.pem` |
| **Passphrase** | For the P12 or an encrypted key |
| **Format** | `cades`, `pades`, `xades`; preselected from the suffix |
| **Level** | `bes`, `t`, `lt`, `lta` |
| **TSA** | Timestamp authority URL, when the level needs one |

Press **Sign**. The signing runs off the UI thread, so the window stays
responsive; a slow smartcard or a distant TSA will not freeze it.

When it finishes you can open the result directly in the system viewer.

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

## Verify tab

Drop a file, press **Verify**. The result is rendered as:

- a large verdict, coloured: green (`advanced`, `qualified`), amber (`untrusted`,
  `unknown`), red (`broken`);
- one block per signature: signer, issuer, identifier, signing time, integrity;
- the findings, in the window language.

The raw JSON is available in a collapsible panel, for copying into a report.

Verification in the window runs **offline** by default, like the CLI. Turning on
network revocation is a checkbox that says what it does.

---

## Requests tab

This is where a person approves what a web page asked for. It exists because the
URI handler cannot approve itself: the secret lives here, not in the process that
received the URI.

The tab shows:

- what is waiting, with the file name and the time left before it expires;
- on selection: the full path, the format, and the countdown;
- **Approve** and **Reject** buttons.

Pressing either asks for the **approval secret**, which `trebaruna handler` printed
in a terminal. The window does not hold it, so a window that lists requests still
cannot approve one on its own.

See [Web pages](web-pages.md) for the full flow.

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
set, the window cannot sign. That is why it checks at start and tells you.

---

## Known limits

Stated rather than hidden:

- **Linux only, prebuilt.** Fyne links Cocoa on macOS; the `.app` needs a macOS
  runner to build and the CI job that does it is written but the artefact is not
  produced here.
- **No Windows build of the window.** The CLI works on Windows; the window does
  not ship.
- **Keyboard navigation is partial.** Tab order follows the form and the buttons
  are reachable, but it has not been audited against a screen reader.

---

## Next

- [Signing](signing.md) — the same operations, explained in depth
- [Verification](verification.md) — reading the verdict
- [Web pages](web-pages.md) — the requests you approve here