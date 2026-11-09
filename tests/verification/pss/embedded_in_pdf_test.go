package pss_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// TestAnEnvelopeOfAnotherDocumentInAPDFIsNotItsSignature: a valid RSA-PSS
// envelope that carries its own document (pss-embedded.p7m signs
// documento.txt) put in a PDF's /Contents signs that document, not the
// PDF's byte ranges, and must not make the PDF look signed.
func TestAnEnvelopeOfAnotherDocumentInAPDFIsNotItsSignature(t *testing.T) {
	pdf, err := os.ReadFile(fixture(t, "pss-pades.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := os.ReadFile(fixture(t, "pss-embedded.p7m"))
	if err != nil {
		t.Fatal(err)
	}
	hole := regexp.MustCompile(`/Contents\s*<([0-9A-Fa-f]+)>`).FindSubmatchIndex(pdf)
	if hole == nil {
		t.Fatal("no /Contents")
	}
	replacement := hex.EncodeToString(foreign)
	width := hole[3] - hole[2]
	if len(replacement) > width {
		t.Skipf("the envelope (%d) does not fit the hole (%d)", len(replacement), width)
	}
	replacement += strings.Repeat("0", width-len(replacement))
	swapped := append(append(append([]byte{}, pdf[:hole[2]]...), replacement...), pdf[hole[3]:]...)
	path := filepath.Join(t.TempDir(), "swapped.pdf")
	os.WriteFile(path, swapped, 0o600)

	report := only(t, verificationinfra.NewPDFVerifier().WithAnchorCertificates(nil, nil, anchored(t)), path)
	if report.Integrity == domain.StatusGood {
		t.Errorf("another document's envelope makes the PDF look signed: %+v", report.Findings)
	}
}
