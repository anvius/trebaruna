package report

import "strings"

// renderMarkdown writes the report as Markdown: a table per section, its
// list below.
func renderMarkdown(content document) []byte {
	var out strings.Builder
	out.WriteString("# " + markdownText(content.title) + "\n")
	for _, part := range content.sections {
		out.WriteString("\n## " + markdownText(part.heading) + "\n")
		if len(part.rows) > 0 {
			out.WriteString("\n| | |\n|---|---|\n")
			for _, item := range part.rows {
				out.WriteString("| **" + markdownCell(item.label) + "** | " + markdownCell(item.value) + " |\n")
			}
		}
		if len(part.list) > 0 {
			out.WriteString("\n")
			if part.listLabel != "" {
				out.WriteString("**" + markdownText(part.listLabel) + "**\n\n")
			}
			for _, line := range part.list {
				out.WriteString("- " + markdownText(line) + "\n")
			}
		}
	}
	out.WriteString("\n---\n\n" + markdownText(content.note) + "\n")
	return []byte(out.String())
}

// markdownText keeps text on its line and stops it reading as markup.
func markdownText(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	return strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "`", "\\`", "<", "&lt;", "[", `\[`).Replace(text)
}

// markdownCell is markdownText inside a table cell.
func markdownCell(text string) string {
	return strings.ReplaceAll(markdownText(text), "|", `\|`)
}
