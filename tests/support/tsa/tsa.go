// Package tsa is an RFC 3161 timestamp authority for tests: real tokens,
// signed in process, served over a loopback HTTP server, so no test needs the
// network and every token still parses as one from a real authority.
package tsa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
)

var oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

// Authority signs timestamp tokens with a throwaway CA.
type Authority struct {
	Certificate *x509.Certificate
	CA          *x509.Certificate
	key         *rsa.PrivateKey

	mu       sync.Mutex
	requests int
}

// New builds the CA and the timestamping certificate.
func New(t *testing.T) *Authority {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(900),
		Subject:               pkix.Name{CommonName: "Test TSA CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	template := &x509.Certificate{
		SerialNumber: big.NewInt(901),
		Subject:      pkix.Name{CommonName: "Test TSA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// ETSI EN 319 412-4: the timeStamping purpose is critical.
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	return &Authority{Certificate: certificate, CA: ca, key: key}
}

// Requests counts the tokens issued.
func (a *Authority) Requests() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests
}

// Token builds a TimeStampResp over digest, echoing nonce when given.
func (a *Authority) Token(_ context.Context, digest, nonce []byte) ([]byte, error) {
	a.mu.Lock()
	a.requests++
	a.mu.Unlock()

	info := struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint struct {
			HashAlgorithm struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			HashedMessage []byte
		}
		SerialNumber *big.Int
		GenTime      time.Time `asn1:"generalized"`
		Nonce        *big.Int  `asn1:"optional"`
	}{Version: 1, Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, SerialNumber: big.NewInt(1), GenTime: time.Now().UTC()}
	if len(nonce) > 0 {
		info.Nonce = new(big.Int).SetBytes(nonce)
	}
	info.MessageImprint.HashAlgorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	info.MessageImprint.HashedMessage = append([]byte{}, digest...)

	encoded, err := asn1.Marshal(info)
	if err != nil {
		return nil, err
	}
	signature, err := cms.Sign(cms.Request{
		Content: encoded, Certificate: a.Certificate, Chain: []*x509.Certificate{a.CA},
		Signer: a.key, EmbeddedContent: true, ContentType: oidTSTInfo,
	})
	if err != nil {
		return nil, err
	}
	granted := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	body := append(granted, signature.DER...)
	return sequence(body), nil
}

// URL serves the authority over loopback HTTP until the test ends.
func (a *Authority) URL(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		digest, nonce := parseRequest(body)
		if len(digest) == 0 {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := a.Token(request.Context(), digest, nonce)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = writer.Write(response)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// parseRequest reads the imprint and the nonce of a TimeStampReq.
func parseRequest(der []byte) (digest, nonce []byte) {
	var request struct {
		Version        int
		MessageImprint struct {
			HashAlgorithm pkix.AlgorithmIdentifier
			HashedMessage []byte
		}
		Policy    asn1.ObjectIdentifier `asn1:"optional"`
		Nonce     *big.Int              `asn1:"optional"`
		CertReq   bool                  `asn1:"optional,default:false"`
		Extension asn1.RawValue         `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &request); err != nil {
		return nil, nil
	}
	if request.Nonce != nil {
		nonce = request.Nonce.Bytes()
	}
	return request.MessageImprint.HashedMessage, nonce
}

func sequence(body []byte) []byte {
	out := []byte{0x30}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}
