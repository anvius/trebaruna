package domain_test

import (
	"errors"
	"testing"

	"codeberg.org/simplicer/firma-it/src/signing/domain"
)

func TestSignedNameFollowsEstablishedConvention(t *testing.T) {
	cases := []struct {
		path   string
		format domain.Format
		want   string
	}{
		{"/tmp/contratto.docx", domain.Cades, "/tmp/contratto.docx.p7m"},
		{"/tmp/contratto.pdf", domain.Pades, "/tmp/contratto_signed.pdf"},
		{"/tmp/fattura.xml", domain.Xades, "/tmp/fattura_signed.xml"},
		{"/tmp/relazione.PDF", domain.Pades, "/tmp/relazione_signed.pdf"},
	}

	for _, testCase := range cases {
		document, err := domain.OpenDocument(testCase.path)
		if err != nil {
			t.Fatalf("OpenDocument(%q): %v", testCase.path, err)
		}
		if got := document.SignedName(testCase.format); got != testCase.want {
			t.Errorf("SignedName(%q, %s) = %q, want %q", testCase.path, testCase.format, got, testCase.want)
		}
	}
}

func TestOpenDocumentRejectsEmptyPath(t *testing.T) {
	_, err := domain.OpenDocument("   ")
	if err == nil {
		t.Fatal("expected an error for an empty path")
	}
}

func TestFormatExtensionAndStandard(t *testing.T) {
	expectations := map[domain.Format]struct{ extension, standard string }{
		domain.Cades: {".p7m", "ETSI EN 319 122-1"},
		domain.Pades: {".pdf", "ETSI EN 319 142-1"},
		domain.Xades: {".xml", "ETSI EN 319 132-1"},
	}
	for format, expected := range expectations {
		if format.Extension() != expected.extension {
			t.Errorf("%s.Extension() = %q, want %q", format, format.Extension(), expected.extension)
		}
		if format.Standard() != expected.standard {
			t.Errorf("%s.Standard() = %q, want %q", format, format.Standard(), expected.standard)
		}
	}
}

func TestParseFormatRejectsUnknown(t *testing.T) {
	if _, err := domain.ParseFormat("pkcs7"); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestLevelCapabilities(t *testing.T) {
	cases := []struct {
		level                         domain.Level
		timestamp, revision, archival bool
	}{
		{domain.BES, false, false, false},
		{domain.T, true, false, false},
		{domain.LT, true, true, false},
		{domain.LTA, true, true, true},
	}
	for _, testCase := range cases {
		if testCase.level.NeedsTimestamp() != testCase.timestamp {
			t.Errorf("%s.NeedsTimestamp() = %v", testCase.level, testCase.level.NeedsTimestamp())
		}
		if testCase.level.EmbedsRevocation() != testCase.revision {
			t.Errorf("%s.EmbedsRevocation() = %v", testCase.level, testCase.level.EmbedsRevocation())
		}
		if testCase.level.Archival() != testCase.archival {
			t.Errorf("%s.Archival() = %v", testCase.level, testCase.level.Archival())
		}
	}
}

func TestDocumentSupportsFormat(t *testing.T) {
	pdf, _ := domain.OpenDocument("atto.pdf")
	if !pdf.Supports(domain.Pades) {
		t.Error("a PDF should accept a PAdES signature")
	}
	if pdf.Supports(domain.Xades) {
		t.Error("a PDF should not accept XAdES")
	}
	xmlDocument, _ := domain.OpenDocument("atto.xml")
	if !xmlDocument.Supports(domain.Xades) {
		t.Error("an XML should accept XAdES")
	}
	if !pdf.Supports(domain.Cades) {
		t.Error("CAdES applies to any document")
	}
}

func TestPlaceSealValidatesGeometry(t *testing.T) {
	if _, err := domain.PlaceSeal(0, 0, 0, 10, 10); err == nil {
		t.Error("page 0 must be rejected")
	}
	if _, err := domain.PlaceSeal(1, 100, 100, 50, 100); err == nil {
		t.Error("upperRightX below lowerLeftX must be rejected")
	}
	if _, err := domain.PlaceSeal(1, 100, 100, 200, 50); err == nil {
		t.Error("upperRightY below lowerLeftY must be rejected")
	}
	if _, err := domain.PlaceSeal(1, -5, 0, 100, 50); err == nil {
		t.Error("negative coordinates must be rejected")
	}

	placement, err := domain.PlaceSeal(2, 100, 600, 300, 700)
	if err != nil {
		t.Fatalf("valid placement rejected: %v", err)
	}
	if placement.Width() != 200 || placement.Height() != 100 {
		t.Errorf("width/height = %v/%v, want 200/100", placement.Width(), placement.Height())
	}
	if placement.Page() != 2 {
		t.Errorf("page = %d, want 2", placement.Page())
	}
}

func TestDefaultSealFitsAnA4Page(t *testing.T) {
	placement := domain.DefaultSeal(1)
	lowerLeftX, lowerLeftY, upperRightX, upperRightY := placement.Box()
	if lowerLeftX < 0 || lowerLeftY < 0 || upperRightX > 595.28 || upperRightY > 841.89 {
		t.Errorf("default seal falls outside A4: (%v,%v)-(%v,%v)", lowerLeftX, lowerLeftY, upperRightX, upperRightY)
	}
}

func TestSignerNeedsName(t *testing.T) {
	_, err := domain.NewSigner("", domain.FromP12, domain.WithKeyMaterial([]byte("x")))
	if !errors.Is(err, domain.ErrSignerWithoutName) {
		t.Fatalf("err = %v, want ErrSignerWithoutName", err)
	}
}

func TestSignerP12NeedsContent(t *testing.T) {
	_, err := domain.NewSigner("Mario", domain.FromP12)
	if !errors.Is(err, domain.ErrP12WithoutContent) {
		t.Fatalf("err = %v, want ErrP12WithoutContent", err)
	}
}

func TestSignerTokenNeedsModule(t *testing.T) {
	_, err := domain.NewSigner("Mario", domain.FromToken, domain.WithToken("", "Carta", "1234"))
	if !errors.Is(err, domain.ErrTokenWithoutModule) {
		t.Fatalf("err = %v, want ErrTokenWithoutModule", err)
	}
}

func TestSignerAcceptsP12(t *testing.T) {
	signer, err := domain.NewSigner("Mario", domain.FromP12,
		domain.WithKeyMaterial([]byte("p12")), domain.WithPassphrase("secret"))
	if err != nil {
		t.Fatalf("valid signer rejected: %v", err)
	}
	if signer.KeySource() != domain.FromP12 {
		t.Errorf("source = %v", signer.KeySource())
	}
	if signer.Passphrase() != "secret" {
		t.Errorf("passphrase = %q", signer.Passphrase())
	}
}
