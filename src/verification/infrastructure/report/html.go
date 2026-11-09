package report

import (
	"html"
	"strings"
)

// htmlStyle is a quiet page that prints well: the content is the point.
const htmlStyle = `body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#1a1a1a;max-width:46rem;margin:2.5rem auto;padding:0 1.25rem;line-height:1.5}
h1{font-size:1.5rem;margin:0 0 1.5rem}
h2{font-size:1.1rem;margin:2rem 0 .5rem;padding-bottom:.25rem;border-bottom:1px solid #ccc}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;vertical-align:top;padding:.3rem .5rem .3rem 0;font-size:.95rem}
th{width:11rem;font-weight:600}
td{overflow-wrap:anywhere}
h3{font-size:.95rem;margin:1rem 0 .25rem}
ul{margin:.25rem 0;padding-left:1.25rem}
li{margin:.15rem 0;overflow-wrap:anywhere}
.note{margin-top:2.5rem;font-size:.9rem;color:#444}
@media print{body{margin:0;max-width:none}}`

// renderHTML writes the report as one HTML page, well-formed XML as well,
// so any XML reader can take it apart.
func renderHTML(content document, language string) []byte {
	if language == "" {
		language = "en"
	}
	var out strings.Builder
	out.WriteString(`<!DOCTYPE html>` + "\n")
	out.WriteString(`<html lang="` + html.EscapeString(language) + `"><head><meta charset="utf-8"/>`)
	out.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1"/>`)
	out.WriteString(`<title>` + html.EscapeString(content.title+" — "+firstHeading(content)) + `</title>`)
	out.WriteString(`<style>` + htmlStyle + `</style></head><body>` + "\n")
	out.WriteString(`<h1>` + html.EscapeString(content.title) + `</h1>` + "\n")
	for _, part := range content.sections {
		out.WriteString(`<section><h2>` + html.EscapeString(part.heading) + `</h2>`)
		if len(part.rows) > 0 {
			out.WriteString(`<table>`)
			for _, item := range part.rows {
				out.WriteString(`<tr><th scope="row">` + html.EscapeString(item.label) + `</th><td>` + html.EscapeString(item.value) + `</td></tr>`)
			}
			out.WriteString(`</table>`)
		}
		if len(part.list) > 0 {
			if part.listLabel != "" {
				out.WriteString(`<h3>` + html.EscapeString(part.listLabel) + `</h3>`)
			}
			out.WriteString(`<ul>`)
			for _, line := range part.list {
				out.WriteString(`<li>` + html.EscapeString(line) + `</li>`)
			}
			out.WriteString(`</ul>`)
		}
		out.WriteString(`</section>` + "\n")
	}
	out.WriteString(`<p class="note">` + html.EscapeString(content.note) + `</p>` + "\n")
	out.WriteString(`</body></html>` + "\n")
	return []byte(out.String())
}

// firstHeading names the verified document in the page title.
func firstHeading(content document) string {
	if len(content.sections) == 0 {
		return ""
	}
	return content.sections[0].heading
}
