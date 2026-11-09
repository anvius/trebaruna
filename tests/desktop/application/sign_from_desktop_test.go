package application_test

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/application"
	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

// recordingSigner stands in for the command: it remembers what it was asked
// and answers with whatever the test scripted.
type recordingSigner struct {
	calls   int
	receipt domain.Receipt
	err     error
}

func (s *recordingSigner) Sign(_ context.Context, _ domain.SigningIntent) (domain.Receipt, error) {
	s.calls++
	return s.receipt, s.err
}

func completeIntent() domain.SigningIntent {
	return domain.SigningIntent{
		DocumentPath: "/tmp/contratto.pdf",
		KeyPath:      "/tmp/mario.p12",
		Format:       "pades",
		Level:        "bes",
		Seal:         domain.SealChoice{Page: 1},
	}
}

func TestAnInvalidIntentNeverReachesTheSigner(t *testing.T) {
	signer := &recordingSigner{}
	useCase := application.NewSignFromDesktop(signer, func(string) bool { return true })

	intent := completeIntent()
	intent.KeyPath = ""

	_, err := useCase.Execute(context.Background(), intent)

	var problem domain.Problem
	if !errors.As(err, &problem) || problem.Code != domain.ProblemMissingKey {
		t.Fatalf("err = %v, want ProblemMissingKey", err)
	}
	if signer.calls != 0 {
		t.Errorf("signer was called %d times for an invalid intent", signer.calls)
	}
}

func TestASignerFailureIsReportedAsIs(t *testing.T) {
	signer := &recordingSigner{err: errors.New("signing failed: wrong passphrase")}
	useCase := application.NewSignFromDesktop(signer, func(string) bool { return true })

	_, err := useCase.Execute(context.Background(), completeIntent())

	if err == nil || err.Error() != "signing failed: wrong passphrase" {
		t.Fatalf("err = %v, want the signer's own explanation", err)
	}
}

func TestAReceiptWithoutAFileIsNotASuccess(t *testing.T) {
	signer := &recordingSigner{receipt: domain.Receipt{SignedPath: "/tmp/contratto_signed.pdf"}}
	useCase := application.NewSignFromDesktop(signer, func(string) bool { return false })

	_, err := useCase.Execute(context.Background(), completeIntent())

	var problem domain.Problem
	if !errors.As(err, &problem) || problem.Code != domain.ProblemNoOutput {
		t.Fatalf("err = %v, want ProblemNoOutput", err)
	}
	if problem.Detail != "/tmp/contratto_signed.pdf" {
		t.Errorf("detail = %q, want the missing path", problem.Detail)
	}
}

func TestASuccessfulSignatureHandsBackTheReceipt(t *testing.T) {
	want := domain.Receipt{SignedPath: "/tmp/contratto_signed.pdf", Standard: "PAdES-B-B", Signer: "MARIO ROSSI"}
	signer := &recordingSigner{receipt: want}
	useCase := application.NewSignFromDesktop(signer, func(path string) bool { return path == want.SignedPath })

	got, err := useCase.Execute(context.Background(), completeIntent())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got != want {
		t.Errorf("receipt = %+v, want %+v", got, want)
	}
}

func TestWithoutAnExistenceCheckTheReceiptIsTrusted(t *testing.T) {
	want := domain.Receipt{SignedPath: "/tmp/contratto_signed.pdf"}
	useCase := application.NewSignFromDesktop(&recordingSigner{receipt: want}, nil)

	got, err := useCase.Execute(context.Background(), completeIntent())
	if err != nil || got != want {
		t.Fatalf("got %+v, %v; want %+v", got, err, want)
	}
}
