package infrastructure

// This file carries no build tag: the renderers and their order are plain Go.

import (
	"context"
	"errors"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
)

// ErrRendererMissing reports that a renderer's program is not installed.
// Preview needs a renderer; signing does not, so a missing one must never
// block a signature.
var ErrRendererMissing = errors.New("no PDF renderer available")

// FirstAvailableRenderer renders with the first renderer whose program is
// installed: poppler when it is, trebaruna's own sketch otherwise.
type FirstAvailableRenderer []application.DocumentRenderer

// RenderPage tries each renderer in turn while it reports itself missing.
func (renderers FirstAvailableRenderer) RenderPage(ctx context.Context, documentPath string, page int) (application.PagePreview, error) {
	err := ErrRendererMissing
	for _, renderer := range renderers {
		preview, renderErr := renderer.RenderPage(ctx, documentPath, page)
		if !errors.Is(renderErr, ErrRendererMissing) {
			return preview, renderErr
		}
		err = renderErr
	}
	return application.PagePreview{}, err
}
