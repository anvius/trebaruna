package remote_test

// Remote signing through the CSC API v2 (ADR-0014), against the service in
// tests/support/csc: the key never leaves it, the hash is authorised with
// the PIN where the credential asks, and the signatures verify with
// independent tools.

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/tests/support/csc"
)

func remoteSigner(t *testing.T, service domain.RemoteService) domain.Signer {
	t.Helper()
	signer, err := domain.NewSigner(domain.NameFromCertificate, domain.FromRemote, domain.WithRemoteService(service))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// TestACadesSignedRemotelyVerifiesInOpenSSL: explicit credential, PIN,
// rsaEncryption with a separate hash, the CA's chain.
func TestACadesSignedRemotelyVerifiesInOpenSSL(t *testing.T) {
	server := csc.Start(t)
	signer := remoteSigner(t, domain.RemoteService{Address: server.URL, Credential: "rsa-explicit", Token: csc.Token, PIN: csc.PIN})
	content := []byte("solicitud firmada a distancia\n")
	signed, err := infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{Content: content, Signer: signer, Level: domain.BES})
	if err != nil {
		t.Fatalf("SignCades: %v", err)
	}
	calls := server.Calls()
	if !slices.Contains(calls, "credentials/authorize") || !slices.Contains(calls, "signatures/signHash") {
		t.Errorf("calls %v", calls)
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed")
	}
	directory := t.TempDir()
	envelope := filepath.Join(directory, "solicitud.p7m")
	ca := filepath.Join(directory, "ca.pem")
	os.WriteFile(envelope, signed, 0o600)
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.CA.Raw}), 0o600)
	output, err := exec.Command("openssl", "cms", "-verify", "-inform", "DER", "-in", envelope, "-CAfile", ca, "-purpose", "any", "-cades", "-out", os.DevNull).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "Verification successful") {
		t.Fatalf("openssl: %v\n%s", err, output)
	}
}

// TestAnImplicitCredentialSignsPadesAndXadesWithoutAuthorising: ECDSA r||s
// becomes the DER crypto.Signer promises.
func TestAnImplicitCredentialSignsPadesAndXadesWithoutAuthorising(t *testing.T) {
	server := csc.Start(t)
	signer := remoteSigner(t, domain.RemoteService{Address: server.URL, Credential: "ecdsa-implicit", User: csc.User, Password: csc.Password})
	pdf := blankPDF()
	signedPDF, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{Content: pdf, Signer: signer, Level: domain.BES})
	if err != nil {
		t.Fatalf("SignPades: %v", err)
	}
	if slices.Contains(server.Calls(), "credentials/authorize") {
		t.Error("an implicit credential is not authorised per signature")
	}
	if !slices.Contains(server.Calls(), "auth/login") {
		t.Error("user and password sign in through auth/login")
	}
	if _, err := exec.LookPath("pdfsig"); err == nil {
		path := filepath.Join(t.TempDir(), "remote.pdf")
		os.WriteFile(path, signedPDF, 0o600)
		output, _ := exec.Command("pdfsig", path).CombinedOutput()
		if !strings.Contains(string(output), "Signature is Valid") {
			t.Errorf("pdfsig: %s", output)
		}
	}
	signedXML, err := infrastructure.NewXadesSigner(nil).SignXades(context.Background(), application.XadesRequest{
		Content: []byte("<acta/>"), Signer: signer, Level: domain.BES})
	if err != nil {
		t.Fatalf("SignXades: %v", err)
	}
	if !bytes.Contains(signedXML, []byte("ecdsa-sha256")) {
		t.Error("the XML signature names ECDSA")
	}
}

// TestRemoteFailuresSayWhy, before any document is signed where possible.
func TestRemoteFailuresSayWhy(t *testing.T) {
	server := csc.Start(t)
	cases := []struct {
		service domain.RemoteService
		says    string
	}{
		{domain.RemoteService{Address: server.URL, Credential: "rsa-explicit", Token: csc.Token, PIN: "000000"}, "invalid_pin"},
		{domain.RemoteService{Address: server.URL, Credential: "rsa-explicit", Token: csc.Token}, "TREBARUNA_PIN"},
		{domain.RemoteService{Address: server.URL, Credential: "rsa-explicit", Token: "wrong"}, "invalid_token"},
		{domain.RemoteService{Address: server.URL, Token: csc.Token, PIN: csc.PIN}, "ecdsa-implicit, rsa-explicit"},
		{domain.RemoteService{Address: server.URL, Credential: "rsa-explicit"}, "TREBARUNA_CSC_TOKEN"},
	}
	for index, entry := range cases {
		signer := remoteSigner(t, entry.service)
		_, err := infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{Content: []byte("x"), Signer: signer, Level: domain.BES})
		if err == nil || !strings.Contains(err.Error(), entry.says) {
			t.Errorf("case %d: %v, want it to say %q", index, err, entry.says)
		}
	}
	if _, err := domain.NewSigner("x", domain.FromRemote, domain.WithRemoteService(domain.RemoteService{Address: "http://provider.example/csc/v2"})); err == nil {
		t.Error("plain HTTP to another computer must be refused")
	}
}

// blankPDF is a one-page PDF.
func blankPDF() []byte {
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>"}
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for index, object := range objects {
		offsets[index] = pdf.Len()
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return pdf.Bytes()
}
