# Accessibility

A review of the desktop window against WCAG 2.2 level AA, applied to a desktop
application as WCAG2ICT describes, made for 0.45.0. Each criterion says what
the window does and how that is checked: by a test when one can say it, by
reading the code otherwise. The command line is the fully accessible way to
use trebaruna today (see the end).

## What the window does

| Criterion | State | How it is met, and checked |
|---|---|---|
| 1.1.1 Non-text content | met | Buttons carry text; the two page arrows, which show only an icon, have names ("Previous page", "Next page"). The seal preview is a drawing; the line under the page says in words where it is and whether it covers text. Test: `TestScreenReadersGetNamesNotIconFiles`. |
| 1.3.1 Info and relationships | partly | The form is three numbered steps with headings and labels above their fields. Screen readers learn the structure only where Fyne exposes it (below). |
| 1.4.1 Use of colour | met | Findings carry a symbol (✓ ! ✗) and words; a seal over text turns amber *and* the line under the page says so. |
| 1.4.3 Contrast (minimum) | met | Every text colour reaches 4.5:1 on the window, the fields, the buttons and the dialogs; the text on a primary button too; in the dark palette and in the light one, which a light desktop gets. Test: `TestEveryTextColourReadsOnEverySurface`. |
| 1.4.4 Resize text | met | `FYNE_SCALE=1.5 trebaruna-desktop` scales the whole window; labels wrap instead of being cut. |
| 1.4.11 Non-text contrast | met | The edges of fields and the focus ring reach 3:1 on every surface (same test). |
| 2.1.1 Keyboard | met | Every action has a shortcut: Ctrl+O open a document, Ctrl+K choose the certificate, Ctrl+Shift+O check a document, Ctrl+Enter sign, Ctrl+PgUp / Ctrl+PgDn change page, Ctrl+F next free space. Tab reaches the page and the sign button; on the page the arrows move the seal and + and − resize it. Tests: `TestTabReachesThePageAndTheSignButton`, `TestTheSealGrowsAndShrinksFromTheKeyboard`. |
| 2.4.3 Focus order | met | Tab follows the steps from top to bottom, then the page. |
| 2.4.7 Focus visible | met | Fyne's focus outline in the accent colour (3:1 or more), and a ring around the page when it has the keyboard. |
| 2.5.7 Dragging movements | met | Moving the seal: a click, the arrows, or Find free space. Resizing it: + and −, besides the corner handle. |
| 3.1.1 / 3.1.2 Language | met | Seven interface languages; the HTML report names its language in `lang`. |
| 3.3.1 Error identification | met | Errors are sentences next to the action, in the person's language, and come before signing (a certificate that does not open, an image that cannot be a rubric). |
| 4.1.2 Name, role, value | partly | Fyne 2.8 exposes buttons, labels and links to Windows' UI Automation and macOS's VoiceOver behind its `accessibility` build tag, which the Windows and macOS builds enable; the page reports its description. Linux has no screen-reader support in Fyne yet (no AT-SPI). Not tried with NVDA, Narrator or VoiceOver here: it needs those systems. |

## Changed by this review

- The accent teal and the error red are a little lighter: on raised surfaces
  they were 4.08:1 and 3.88:1, below the 4.5:1 text needs.
- Field edges have a colour of their own (`Outline`), 3:1 or more; they used
  the separator colour, 1.3:1.
- + and − resize the seal from the keyboard; the hint says so in every
  language.
- The page arrows and the page itself have names for screen readers.
- The Windows and macOS windows are built with Fyne's accessibility tag.

## Pending

- Screen readers on Linux, which waits for Fyne; and a try with NVDA,
  Narrator and VoiceOver on the Windows and macOS builds.
- A high-contrast theme: the window has a dark and a light palette, both
  AA, neither AAA.
- Fyne has no tooltips in its core widgets, so icon buttons rely on their
  names.

## The command line

Everything the window does, the command line does, and it works with any
screen reader in a terminal: messages in the person's language
(`--lang`), no colour needed to read them, `--json` for anyone who wants to
process the answer, and `verify --report informe.html` for a report a
browser reads aloud. See [command-line.md](command-line.md).
