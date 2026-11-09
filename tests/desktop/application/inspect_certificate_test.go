package application_test

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

type scriptedReader struct {
	calls   int
	summary domain.CertificateSummary
	err     error
}

func (r *scriptedReader) Read(context.Context, domain.CertificateFile) (domain.CertificateSummary, error) {
	r.calls++
	return r.summary, r.err
}

func TestNoFileMeansNoReading(t *testing.T) {
	reader := &scriptedReader{}
	_, err := application.NewInspectCertificate(reader).Execute(context.Background(), domain.CertificateFile{Path: " "})

	var problem domain.Problem
	if !errors.As(err, &problem) || problem.Code != domain.ProblemMissingKey {
		t.Fatalf("err = %v, want ProblemMissingKey", err)
	}
	if reader.calls != 0 {
		t.Error("the reader must not run without a file")
	}
}

func TestTheSummaryComesFromTheReader(t *testing.T) {
	reader := &scriptedReader{summary: domain.CertificateSummary{Holder: "MARIO ROSSI", Qualified: true}}
	got, err := application.NewInspectCertificate(reader).Execute(context.Background(), domain.CertificateFile{Path: "/tmp/m.p12"})
	if err != nil || got.Holder != "MARIO ROSSI" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestALockedFileIsReported(t *testing.T) {
	reader := &scriptedReader{err: domain.Problem{Code: domain.ProblemLockedCertificate}}
	_, err := application.NewInspectCertificate(reader).Execute(context.Background(), domain.CertificateFile{Path: "/tmp/m.p12"})

	var problem domain.Problem
	if !errors.As(err, &problem) || problem.Code != domain.ProblemLockedCertificate {
		t.Fatalf("err = %v, want ProblemLockedCertificate", err)
	}
}
