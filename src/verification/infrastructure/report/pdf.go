package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/helvetica"
)

// A4, in points, and the page's furniture.
const (
	pageWidth   = 595.28
	pageHeight  = 841.89
	margin      = 56.0
	footerSpace = 28.0
	labelWidth  = 128.0
	bodySize    = 9.0
	bodyLeading = 12.5
)

// pdfLayout lays text out in pages of Helvetica, written with WinAnsi
// encoding so Spanish and Italian letters print as themselves.
type pdfLayout struct {
	pages []*bytes.Buffer
	y     float64
}

// page is the page being written.
func (l *pdfLayout) page() *bytes.Buffer {
	if len(l.pages) == 0 {
		l.newPage()
	}
	return l.pages[len(l.pages)-1]
}

func (l *pdfLayout) newPage() {
	l.pages = append(l.pages, &bytes.Buffer{})
	l.y = pageHeight - margin
}

// room starts a new page unless height fits above the footer.
func (l *pdfLayout) room(height float64) {
	if len(l.pages) == 0 || l.y-height < margin+footerSpace {
		l.newPage()
	}
}

// show writes one line of text at x on the current baseline.
func (l *pdfLayout) show(x float64, bold bool, size float64, gray float64, text string) {
	font := "F1"
	if bold {
		font = "F2"
	}
	fmt.Fprintf(l.page(), "BT %.3g g /%s %.2f Tf %.2f %.2f Td (%s) Tj ET\n", gray, font, size, x, l.y, pdfString(text))
}

// lines wraps text to width.
func lines(text string, width, size float64, bold bool) []string {
	wrapped := helvetica.Wrap(strings.Join(strings.Fields(text), " "), width, size, bold)
	if len(wrapped) == 0 {
		return []string{""}
	}
	return wrapped
}

// paragraph writes wrapped text, breaking pages between lines.
func (l *pdfLayout) paragraph(x, width float64, bold bool, size, leading, gray float64, text string) {
	for _, line := range lines(text, width, size, bold) {
		l.room(leading)
		l.y -= leading
		l.show(x, bold, size, gray, line)
	}
}

// renderPDF writes the report as a PDF of its own: no library, the
// structure a reader needs and nothing else.
func renderPDF(content document, at time.Time) ([]byte, error) {
	layout := &pdfLayout{}
	layout.paragraph(margin, pageWidth-2*margin, true, 16, 22, 0, content.title)
	layout.y -= 6

	valueX, valueWidth := margin+labelWidth, pageWidth-2*margin-labelWidth
	for _, part := range content.sections {
		layout.room(40)
		layout.y -= 14
		layout.paragraph(margin, pageWidth-2*margin, true, 11.5, 15, 0, part.heading)
		fmt.Fprintf(layout.page(), "0.75 G 0.5 w %.2f %.2f m %.2f %.2f l S\n", margin, layout.y-4, pageWidth-margin, layout.y-4)
		layout.y -= 6

		for _, item := range part.rows {
			labelLines := lines(item.label, labelWidth-8, bodySize, true)
			valueLines := lines(item.value, valueWidth, bodySize, false)
			height := float64(max(len(labelLines), len(valueLines))) * bodyLeading
			layout.room(height)
			top := layout.y
			for index, line := range labelLines {
				layout.y = top - float64(index+1)*bodyLeading
				layout.show(margin, true, bodySize, 0.2, line)
			}
			for index, line := range valueLines {
				layout.y = top - float64(index+1)*bodyLeading
				layout.show(valueX, false, bodySize, 0, line)
			}
			layout.y = top - height
		}

		if len(part.list) > 0 {
			if part.listLabel != "" {
				layout.y -= 4
				layout.paragraph(margin, pageWidth-2*margin, true, bodySize+0.5, bodyLeading+1, 0, part.listLabel)
			}
			for _, entry := range part.list {
				wrapped := lines(entry, pageWidth-2*margin-12, bodySize, false)
				for index, line := range wrapped {
					layout.room(bodyLeading)
					layout.y -= bodyLeading
					if index == 0 {
						layout.show(margin, false, bodySize, 0, "•")
					}
					layout.show(margin+12, false, bodySize, 0, line)
				}
			}
		}
	}
	layout.y -= 18
	layout.paragraph(margin, pageWidth-2*margin, false, 8, 11, 0.3, content.note)

	for index, page := range layout.pages {
		fmt.Fprintf(page, "BT 0.4 g /F1 8 Tf %.2f %.2f Td (%s) Tj ET\n", margin, margin-6,
			pdfString(fmt.Sprintf("%s — %d/%d", content.title, index+1, len(layout.pages))))
	}
	return assemble(layout.pages, content.title, verifiedAt(at)), nil
}

// assemble writes the PDF objects and their cross-reference table.
func assemble(pages []*bytes.Buffer, title string, created time.Time) []byte {
	var out bytes.Buffer
	var offsets []int
	object := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	// 1 catalog, 2 pages, 3-4 fonts, 5 info; then each page and its content.
	kids := make([]string, len(pages))
	for index := range pages {
		kids[index] = fmt.Sprintf("%d 0 R", 6+2*index)
	}
	object("<< /Type /Catalog /Pages 2 0 R >>")
	object(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))
	object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	object(fmt.Sprintf("<< /Title (%s) /Producer (trebaruna) /CreationDate (D:%s) >>",
		pdfString(title), created.UTC().Format("20060102150405Z")))
	for index, page := range pages {
		object(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>",
			pageWidth, pageHeight, 7+2*index))
		object(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", page.Len(), page.String()))
	}

	start := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, start)
	return out.Bytes()
}

// winAnsi maps the characters of Windows-1252 that differ from Latin-1.
var winAnsi = map[rune]byte{
	'€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87, 'ˆ': 0x88,
	'‰': 0x89, 'Š': 0x8a, '‹': 0x8b, 'Œ': 0x8c, 'Ž': 0x8e, '‘': 0x91, '’': 0x92, '“': 0x93,
	'”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97, '˜': 0x98, '™': 0x99, 'š': 0x9a, '›': 0x9b,
	'œ': 0x9c, 'ž': 0x9e, 'Ÿ': 0x9f,
}

// pdfString encodes text as a WinAnsi literal string: parentheses and
// backslashes escaped, characters WinAnsi lacks as "?".
func pdfString(text string) string {
	var out strings.Builder
	for _, character := range text {
		var code byte
		switch mapped, special := winAnsi[character]; {
		case special:
			code = mapped
		case character < 0x80 || (character >= 0xa0 && character <= 0xff):
			code = byte(character)
		default:
			code = '?'
		}
		switch code {
		case '(', ')', '\\':
			out.WriteByte('\\')
			out.WriteByte(code)
		case '\n', '\r', '\t':
			out.WriteByte(' ')
		default:
			if code < 0x20 {
				code = '?'
			}
			out.WriteByte(code)
		}
	}
	return out.String()
}
