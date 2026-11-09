package application_test

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// blankPage renders an empty A4 page at roughly one cell per two points.
type blankPage struct {
	width, height int
	pointsW       float64
	pointsH       float64
	err           error
}

func (r blankPage) RenderPage(_ context.Context, _ string, page int) (application.PagePreview, error) {
	if r.err != nil {
		return application.PagePreview{}, r.err
	}
	ink, err := domain.NewInkMap(r.width, r.height, make([]float64, r.width*r.height))
	if err != nil {
		return application.PagePreview{}, err
	}
	return application.PagePreview{
		PageNumber: page, WidthPoints: r.pointsW, HeightPoints: r.pointsH,
		RasterWidth: r.width, RasterHeight: r.height, Ink: ink, PageCount: 3,
	}, nil
}

func a4() blankPage {
	return blankPage{width: 298, height: 421, pointsW: 595.28, pointsH: 841.89}
}

// scriptedFinder answers with fixed candidates, so a test can force the
// fallback paths that a real page rarely produces.
type scriptedFinder struct {
	candidates []domain.Candidate
	err        error
}

func (f scriptedFinder) Suggest(domain.InkMap, int, int, int) ([]domain.Candidate, error) {
	return f.candidates, f.err
}

func TestPreviewProposesAConventionalCorner(t *testing.T) {
	useCase := application.NewPreviewPage(a4(), application.InkFinder{})

	result, err := useCase.Execute(context.Background(), "contratto.pdf", 1, application.SealSize{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if result.SealSize != application.DefaultSealSize() {
		t.Errorf("seal size = %+v, want the default when none is given", result.SealSize)
	}
	if !result.Geometry.Valid(result.SealRect) {
		t.Fatalf("proposed rectangle %+v is outside the page", result.SealRect)
	}
	if result.Suggestions[0].Zone != domain.ZoneBottomRight {
		t.Errorf("zone = %s, want bottom-right on a blank page", result.Suggestions[0].Zone)
	}
	if result.Preview.PageCount != 3 {
		t.Errorf("page count = %d, want the renderer's", result.Preview.PageCount)
	}
}

func TestPreviewReportsARendererFailure(t *testing.T) {
	broken := a4()
	broken.err = errors.New("pdftoppm crashed")
	useCase := application.NewPreviewPage(broken, application.InkFinder{})

	if _, err := useCase.Execute(context.Background(), "x.pdf", 1, application.SealSize{}); err == nil {
		t.Fatal("a renderer failure must reach the window")
	}
}

func TestPreviewRejectsAPageWithoutSize(t *testing.T) {
	flat := a4()
	flat.pointsW = 0
	useCase := application.NewPreviewPage(flat, application.InkFinder{})

	if _, err := useCase.Execute(context.Background(), "x.pdf", 1, application.SealSize{}); err == nil {
		t.Fatal("a page of zero points cannot host a seal")
	}
}

func TestPreviewRefusesASealTooSmallToSee(t *testing.T) {
	useCase := application.NewPreviewPage(a4(), application.InkFinder{})

	_, err := useCase.Execute(context.Background(), "x.pdf", 1, application.SealSize{Width: 2, Height: 2})
	if err == nil {
		t.Fatal("a 2x2 pt seal must be refused")
	}
}

func TestPreviewReportsAPageWithNoRoom(t *testing.T) {
	full := scriptedFinder{err: errors.New("no empty space")}
	useCase := application.NewPreviewPage(a4(), full)

	if _, err := useCase.Execute(context.Background(), "x.pdf", 1, application.SealSize{}); err == nil {
		t.Fatal("a page without room must be reported")
	}
}

func TestPreviewSkipsACandidateOutsideThePage(t *testing.T) {
	// The first candidate has no area once converted; the second is fine.
	finder := scriptedFinder{candidates: []domain.Candidate{
		{X: 10, Y: 10, Width: 0, Height: 0},
		{X: 200, Y: 380, Width: 32, Height: 24},
	}}
	useCase := application.NewPreviewPage(a4(), finder)

	result, err := useCase.Execute(context.Background(), "x.pdf", 1, application.SealSize{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.SealRect.Width() <= 0 {
		t.Errorf("rect = %+v, want the second, valid candidate", result.SealRect)
	}
}

func TestSuggestOffersOnlyPlacementsInsideThePage(t *testing.T) {
	useCase := application.NewPreviewPage(a4(), application.InkFinder{})
	result, err := useCase.Execute(context.Background(), "x.pdf", 1, application.SealSize{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	rects, err := useCase.Suggest(result, application.DefaultSealSize())
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if len(rects) < 2 {
		t.Fatalf("got %d alternatives, want several on a blank page", len(rects))
	}
	for _, rect := range rects {
		if !result.Geometry.Valid(rect) {
			t.Errorf("alternative %+v is outside the page", rect)
		}
	}
}

func TestSuggestReportsAFinderFailure(t *testing.T) {
	working := application.NewPreviewPage(a4(), application.InkFinder{})
	result, err := working.Execute(context.Background(), "x.pdf", 1, application.SealSize{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	failing := application.NewPreviewPage(a4(), scriptedFinder{err: errors.New("no space")})
	if _, err := failing.Suggest(result, application.DefaultSealSize()); err == nil {
		t.Fatal("a finder failure must reach the window")
	}
}
