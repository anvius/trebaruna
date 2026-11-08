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
make build-gui       # ./bin/firma-it-desktop
make install-desktop # binary + .desktop entry + icon
```

From a release: `firma-it-desktop` (Linux only, ~33 MB).

### Finding the CLI

The window drives `firma-it` rather than reimplementing signing, so it must find
the binary. It looks next to itself, then on `PATH`. Override:

```bash
export FIRMA_IT_BIN=/opt/firma-it/firma-it
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
| **Page** | Which page gets the visible seal |
| **Box** | `x1,y1,x2,y2` in PDF points |
| **TSA** | Timestamp authority URL, when the level needs one |

Press **Sign**. The signing runs off the UI thread, so the window stays
responsive; a slow smartcard or a distant TSA will not freeze it.

When it finishes you can open the result directly in the system viewer.

### The seal overlay

For PDFs the window shows a preview of the page with a **draggable rectangle** for
the seal. Drag it where you want it, and the coordinates are filled in.

The rectangle is clamped to the page: it cannot be dragged off the edge, which
would produce a seal nobody can see.

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

Pressing either asks for the **approval secret**, which `firma-it handler` printed
in a terminal. The window does not hold it, so a window that lists requests still
cannot approve one on its own.

See [Web pages](web-pages.md) for the full flow.

---

## Languages

Spanish, Italian and English, chosen from `FIRMA_IT_LANG` or `$LANG`:

```bash
FIRMA_IT_LANG=it firma-it-desktop
```

The catalogue is compile-checked: a missing translation is a build error and a
test failure, not an empty label at runtime. Fyne's own strings are supplied by
hand for Italian, because Fyne does not ship them.

---

## Without poppler

The page preview and the automatic free-space detection use **poppler**
(`pdftoppm`).

Without it:

- the preview shows a placeholder;
- the seal box must be typed by hand;
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

The visible consequence: if `firma-it` is not on `PATH` and `FIRMA_IT_BIN` is not
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
- **The preview renders the first page only** when poppler is present.

---

## Next

- [Signing](signing.md) — the same operations, explained in depth
- [Verification](verification.md) — reading the verdict
- [Web pages](web-pages.md) — the requests you approve here