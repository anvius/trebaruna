package application_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/encryption/application"
	encryption "codeberg.org/simplicer/trebaruna/src/encryption/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

type memoryFiles map[string][]byte

func (m memoryFiles) Read(path string) ([]byte, error) {
	content, ok := m[path]
	if !ok {
		return nil, errors.New("no such file")
	}
	return content, nil
}
func (m memoryFiles) Exists(path string) bool                 { _, ok := m[path]; return ok }
func (m memoryFiles) Write(path string, content []byte) error { m[path] = content; return nil }

type recordingSealer struct{ recipients int }

func (r *recordingSealer) Seal(content []byte, recipients []*x509.Certificate, _ bool) ([]byte, error) {
	r.recipients = len(recipients)
	return append([]byte("sealed:"), content...), nil
}

type fixedOpener struct{ content []byte }

func (f fixedOpener) Open([]byte, signing.Signer) ([]byte, error) { return f.content, nil }

func recipientCertificate(t *testing.T, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "LUCA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: usage}
	raw, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certificate, _ := x509.ParseCertificate(raw)
	return certificate
}

func TestAnEnvelopeIsWrittenBesideTheDocumentForItsRecipients(t *testing.T) {
	files := memoryFiles{"/d/offerta.pdf": []byte("offerta")}
	sealer := &recordingSealer{}
	use := application.NewEncryptDocument(files, sealer, time.Now)

	envelope, err := use.Execute(context.Background(), application.EncryptRequest{
		Document: "/d/offerta.pdf", Recipients: []*x509.Certificate{recipientCertificate(t, x509.KeyUsageKeyEncipherment)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Path != "/d/offerta.pdf.p7e" || string(files[envelope.Path]) != "sealed:offerta" || sealer.recipients != 1 {
		t.Errorf("envelope %+v", envelope)
	}
	if _, err := use.Execute(context.Background(), application.EncryptRequest{
		Document: "/d/offerta.pdf", Recipients: []*x509.Certificate{recipientCertificate(t, x509.KeyUsageKeyEncipherment)},
	}); !errors.Is(err, application.ErrWouldOverwrite) {
		t.Errorf("an existing envelope must not be overwritten: %v", err)
	}
}

func TestNoEnvelopeIsMadeForAnUnfitRecipient(t *testing.T) {
	files := memoryFiles{"/d/a.txt": []byte("a")}
	sealer := &recordingSealer{}
	use := application.NewEncryptDocument(files, sealer, time.Now)

	if _, err := use.Execute(context.Background(), application.EncryptRequest{Document: "/d/a.txt"}); !errors.Is(err, encryption.ErrNoRecipients) {
		t.Errorf("no recipients: %v", err)
	}
	_, err := use.Execute(context.Background(), application.EncryptRequest{
		Document: "/d/a.txt", Recipients: []*x509.Certificate{recipientCertificate(t, x509.KeyUsageContentCommitment)},
	})
	if !errors.Is(err, encryption.ErrCannotReceive) || sealer.recipients != 0 || files.Exists("/d/a.txt.p7e") {
		t.Errorf("a signing-only certificate must stop before anything is written: %v", err)
	}
}

func TestTheDocumentComesOutBesideItsEnvelope(t *testing.T) {
	files := memoryFiles{"/d/offerta.pdf.p7e": []byte("envelope")}
	use := application.NewDecryptDocument(files, fixedOpener{content: []byte("offerta")})

	decrypted, err := use.Execute(context.Background(), application.DecryptRequest{Envelope: "/d/offerta.pdf.p7e"})
	if err != nil || decrypted.Path != "/d/offerta.pdf" || string(files["/d/offerta.pdf"]) != "offerta" {
		t.Fatalf("decrypted %+v, %v", decrypted, err)
	}
	if _, err := use.Execute(context.Background(), application.DecryptRequest{Envelope: "/d/offerta.pdf.p7e"}); !errors.Is(err, application.ErrWouldOverwrite) {
		t.Errorf("the document must not be overwritten: %v", err)
	}
}
