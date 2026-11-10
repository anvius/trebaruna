package infrastructure_test

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	"codeberg.org/simplicer/trebaruna/src/afirma/infrastructure"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verification "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// TestASiCSPagesGetAContainer: CAdES-ASiC-S and XAdES-ASiC-S answer with
// the container, the data named as AutoFirma names it, and it verifies.
func TestASiCSPagesGetAContainer(t *testing.T) {
	cases := []struct {
		format     string
		properties map[string]string
		data       []byte
		entries    string
	}{
		{"CAdES-ASiC-S", map[string]string{}, []byte("%PDF-1.4\n%solicitud\n"), "mimetype dataobject.pdf META-INF/signature.p7s"},
		{"XAdES-ASiC-S", map[string]string{"asicsFilename": "solicitud.xml"}, []byte("<solicitud/>"), "mimetype solicitud.xml META-INF/signatures.xml"},
		{"XAdES-ASiC-S", map[string]string{}, []byte("texto"), "mimetype dataobject.txt META-INF/signatures.xml"},
	}
	for _, entry := range cases {
		signed, err := signPage(t, entry.format, entry.properties, entry.data)
		if err != nil {
			t.Fatalf("%s: %v", entry.format, err)
		}
		archive, err := zip.NewReader(bytes.NewReader(signed.Signature), int64(len(signed.Signature)))
		if err != nil {
			t.Fatalf("%s: not a ZIP: %v", entry.format, err)
		}
		var names []string
		for _, file := range archive.File {
			names = append(names, file.Name)
		}
		if strings.Join(names, " ") != entry.entries {
			t.Errorf("%s: %v, want %s", entry.format, names, entry.entries)
		}
		path := filepath.Join(t.TempDir(), "firma.asics")
		if err := os.WriteFile(path, signed.Signature, 0o600); err != nil {
			t.Fatal(err)
		}
		reports, err := verification.NewAsicVerifier(verification.NewCadesVerifier(), verification.NewXadesVerifier()).Extract(path)
		if err != nil || len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %+v, %v", entry.format, reports, err)
		}
	}
	_, err := signPage(t, "XAdES-ASiC-S", map[string]string{"asicsFilename": "../evil.xml"}, []byte("<a/>"))
	wantFailure(t, err, domain.Params, "asicsFilename with a path")
}

// TestAnODFPageGetsItsDocumentSigned inside itself.
func TestAnODFPageGetsItsDocumentSigned(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", "verification", "odf", "testdata", "unsigned.odt"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signPage(t, "ODF (Open Document Format)", map[string]string{}, document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "firmado.odt")
	os.WriteFile(path, signed.Signature, 0o600)
	reports, err := verification.NewOdfVerifier(verification.NewXadesVerifier()).Extract(path)
	if err != nil || len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
		t.Errorf("%+v %v", reports, err)
	}
	_, err = signPage(t, "ODF", map[string]string{}, []byte("%PDF-1.4"))
	wantFailure(t, err, domain.InvalidData, "a PDF as ODF")
}

// TestAnOOXMLPageGetsItsDocumentSigned inside itself, as AutoFirma's OOXML
// signer does.
func TestAnOOXMLPageGetsItsDocumentSigned(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", "verification", "ooxml", "testdata", "unsigned.docx"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signPage(t, "OOXML (Office Open XML)", map[string]string{}, document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "firmado.docx")
	os.WriteFile(path, signed.Signature, 0o600)
	reports, err := verification.NewOoxmlVerifier(verification.NewXadesVerifier()).Extract(path)
	if err != nil || len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
		t.Errorf("%+v %v", reports, err)
	}
	_, err = signPage(t, "OOXML", map[string]string{}, []byte("%PDF-1.4"))
	wantFailure(t, err, domain.InvalidData, "a PDF as OOXML")
}

// TestASiCSPagesCosignTheContainer: a cosign page that sends a container
// gets it back with one more signature of the kind it holds, both of which
// verify; a countersign page gets the signature counter-signed inside it;
// data that is no container is refused.
func TestASiCSPagesCosignTheContainer(t *testing.T) {
	juan, _ := identity(t, "JUAN PEREZ", 22)
	for _, name := range []string{"CAdES-ASiC-S", "XAdES-ASiC-S"} {
		first, err := signPage(t, name, map[string]string{"asicsFilename": "solicitud.xml"}, []byte("<solicitud/>"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cosigned, err := infrastructure.NewNativePageSigner().Sign(context.Background(), application.PageSignature{
			Crypto: domain.Cosign, Format: format(t, name), Algorithm: "SHA256", Data: first.Signature, Key: juan})
		if err != nil {
			t.Fatalf("%s cosign: %v", name, err)
		}
		path := filepath.Join(t.TempDir(), "firma.asics")
		if err := os.WriteFile(path, cosigned.Signature, 0o600); err != nil {
			t.Fatal(err)
		}
		reports, err := verification.NewAsicVerifier(verification.NewCadesVerifier(), verification.NewXadesVerifier()).Extract(path)
		if err != nil || len(reports) != 2 {
			t.Fatalf("%s: %+v, %v", name, reports, err)
		}
		signers := map[string]bool{}
		for _, report := range reports {
			if report.Integrity != verificationdomain.StatusGood {
				t.Errorf("%s: %s %s %+v", name, report.SignerName, report.Integrity, report.Findings)
			}
			signers[report.SignerName] = true
		}
		if !signers["MARIA GARCIA"] || !signers["JUAN PEREZ"] {
			t.Errorf("%s: signers %v", name, signers)
		}

		countersigned, err := infrastructure.NewNativePageSigner().Sign(context.Background(), application.PageSignature{
			Crypto: domain.Countersign, Format: format(t, name), Algorithm: "SHA256", Data: first.Signature, Key: juan})
		if err != nil {
			t.Fatalf("%s countersign: %v", name, err)
		}
		if err := os.WriteFile(path, countersigned.Signature, 0o600); err != nil {
			t.Fatal(err)
		}
		reports, err = verification.NewAsicVerifier(verification.NewCadesVerifier(), verification.NewXadesVerifier()).Extract(path)
		if err != nil || len(reports) != 2 || reports[1].SignerName != "JUAN PEREZ" || reports[1].Countersigns == "" {
			t.Fatalf("%s counter-signed: %+v, %v", name, reports, err)
		}
		for _, report := range reports {
			if report.Integrity != verificationdomain.StatusGood {
				t.Errorf("%s counter-signed: %s %s %+v", name, report.SignerName, report.Integrity, report.Findings)
			}
		}
		_, err = infrastructure.NewNativePageSigner().Sign(context.Background(), application.PageSignature{
			Crypto: domain.Cosign, Format: format(t, name), Algorithm: "SHA256", Data: []byte("<solicitud/>"), Key: juan})
		wantFailure(t, err, domain.NoSignData, name+" without a container")
	}
}
