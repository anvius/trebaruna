//go:build gui

package infrastructure

import (
	"context"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
)

// sketchRenderer answers as the built-in renderer does: an approximate page.
type sketchRenderer struct{ blankRenderer }

func (r sketchRenderer) RenderPage(ctx context.Context, path string, page int) (application.PagePreview, error) {
	preview, err := r.blankRenderer.RenderPage(ctx, path, page)
	preview.Approximate = true
	return preview, err
}

// TestASketchedPageSaysSo: the line under the page tells trebaruna's sketch
// from the page poppler draws.
func TestASketchedPageSaysSo(t *testing.T) {
	fixture := newFormFixture(t, scriptedCertificate{summary: qualifiedRossi()})
	pages := fixture.desktop.pages
	fixture.desktop.form.setDocument("/tmp/contratto.pdf")
	settle(t, func() bool { return pages.canvas != nil })
	if strings.Contains(pages.hint.Text, pages.messages.PreviewApproximate) {
		t.Error("poppler's page is called a sketch")
	}

	pages.preview = application.NewPreviewPage(sketchRenderer{}, application.InkFinder{})
	pages.show("/tmp/contratto.pdf")
	settle(t, func() bool { return pages.canvas != nil && pages.result.Preview.Approximate })
	if !strings.Contains(pages.hint.Text, pages.messages.PreviewApproximate) {
		t.Errorf("the hint does not say the page is a sketch: %q", pages.hint.Text)
	}
}
