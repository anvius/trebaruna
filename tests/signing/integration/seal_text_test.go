package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// TestTheSealIsSetInWinAnsiWithItsOwnMetrics: the visible seal's text is
// written by trebaruna in the standard Helvetica faces, WinAnsi encoded,
// with no widths table, so readers use the fonts' own metrics. The PDF
// library this replaced set every glyph 500 units wide and wrote UTF-8
// into WinAnsi strings: "MARI O  ROSSI", "TINIT-… Â· 09/11/2026".
func TestTheSealIsSetInWinAnsiWithItsOwnMetrics(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7),
		Subject:   pkix.Name{CommonName: "MARIO ROSSI", SerialNumber: "TINIT-RSSMRA80A01H501U", Country: []string{"IT"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	signer := buildPemSigner(t, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content: blankPDFBytes(), Signer: signer, Level: domain.BES, SignedAt: timeNow(),
		Placements: []domain.SealPlacement{mustPlacement(t, 1, 60, 60, 300, 170)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed, []byte("20B720")) || bytes.Contains(signed, []byte("C2B7")) {
		t.Error(`"·" between the identifier and the date is not one WinAnsi byte`)
	}
	if !bytes.Contains(signed, []byte("/BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding")) || bytes.Contains(signed, []byte("/Widths")) {
		t.Error("the seal's fonts are not the standard faces with their own metrics")
	}
	if reports := verifyPDF(t, newLocalTSA(t), signed); len(reports) != 1 || reports[0].Integrity != "good" {
		t.Errorf("%+v", reports)
	}
}
