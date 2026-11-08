package integration_test

// Revocation is tested against a real OCSP responder, served locally so the test
// is deterministic and offline. The responder signs its answers with a real CA
// key and the client parses them with the real parser: every step except the
// network hop is production code.
//
// The distinction these tests protect is the one a boolean loses: "the responder
// says it is fine" and "nobody answered" must never look the same.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"codeberg.org/anvius/trebaruna/src/verification/domain"
	"codeberg.org/anvius/trebaruna/src/verification/infrastructure"
	"golang.org/x/crypto/ocsp"
)

// ocspFixture is a CA, a leaf, and the responder that answers for them.
type ocspFixture struct {
	ca        *x509.Certificate
	caKey     *rsa.PrivateKey
	leaf      *x509.Certificate
	responder *httptest.Server
}

// ocspAnswer is what the test responder should say.
type ocspAnswer struct {
	status     int
	revokedAt  time.Time
	thisUpdate time.Time
	nextUpdate time.Time
	httpCode   int
}

// newOCSPFixture builds the PKI and starts a responder answering with the given
// verdict. Every query is counted so a test can prove the checker did not call.
func newOCSPFixture(t *testing.T, answer ocspAnswer) *ocspFixture {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(900),
		Subject:               pkix.Name{CommonName: "Revocation Test CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(901),
		Subject:      pkix.Name{CommonName: "Revocation Test Leaf"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if answer.httpCode != 0 && answer.httpCode != http.StatusOK {
			writer.WriteHeader(answer.httpCode)
			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		parsed, err := ocsp.ParseRequest(body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		template := ocsp.Response{
			Status:       answer.status,
			SerialNumber: parsed.SerialNumber,
			ThisUpdate:   answer.thisUpdate,
			NextUpdate:   answer.nextUpdate,
		}
		if !answer.revokedAt.IsZero() {
			template.RevokedAt = answer.revokedAt
			template.RevocationReason = ocsp.KeyCompromise
		}

		der, err := ocsp.CreateResponse(ca, ca, template, caKey)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		writer.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = writer.Write(der)
	}))
	t.Cleanup(server.Close)

	return &ocspFixture{ca: ca, caKey: caKey, leaf: leaf, responder: server}
}

// withResponder points the leaf at the test responder.
func (f *ocspFixture) withResponder(t *testing.T) *x509.Certificate {
	t.Helper()

	clone := *f.leaf
	clone.OCSPServer = []string{f.responder.URL}
	return &clone
}

// check runs the production checker against the fixture.
func check(t *testing.T, certificate *x509.Certificate, issuer *x509.Certificate, now time.Time) domain.Revocation {
	t.Helper()

	checker := infrastructure.NewOCSPChecker()
	checker.Now = now
	return checker.Check(context.Background(), certificate, issuer)
}

// TestOCSPGoodIsCheckedNotAssumed is the positive case: an answer of "good" must
// be reported as checked, with its source.
func TestOCSPGoodIsCheckedNotAssumed(t *testing.T) {
	now := time.Now()
	fixture := newOCSPFixture(t, ocspAnswer{
		status:     ocsp.Good,
		thisUpdate: now.Add(-time.Hour),
		nextUpdate: now.Add(24 * time.Hour),
	})

	got := check(t, fixture.withResponder(t), fixture.ca, now)
	if got.Status != domain.RevocationGood {
		t.Fatalf("status = %s, want good; reason: %s", got.Status, got.Reason)
	}
	if !got.WasChecked() {
		t.Error("an answered query must count as checked")
	}
	if got.Source != "ocsp" {
		t.Errorf("source = %q, want ocsp", got.Source)
	}
}

// TestOCSPRevokedIsReportedWithItsDate: a revocation carries the moment, which is
// what decides whether it invalidates this signature.
func TestOCSPRevokedIsReportedWithItsDate(t *testing.T) {
	now := time.Now()
	revokedAt := now.Add(-48 * time.Hour)

	fixture := newOCSPFixture(t, ocspAnswer{
		status:     ocsp.Revoked,
		revokedAt:  revokedAt,
		thisUpdate: now.Add(-time.Hour),
		nextUpdate: now.Add(24 * time.Hour),
	})

	got := check(t, fixture.withResponder(t), fixture.ca, now)
	if !got.IsRevoked() {
		t.Fatalf("status = %s, want revoked", got.Status)
	}
	if difference := got.RevokedAt.Sub(revokedAt); difference > time.Second || difference < -time.Second {
		t.Errorf("revoked at %s, want %s", got.RevokedAt, revokedAt)
	}
	if !got.FatalAtSigning(now) {
		t.Error("revoked before signing spoils the signature")
	}
	if got.FatalAtSigning(now.Add(-72 * time.Hour)) {
		t.Error("a signature made before the revocation is unaffected")
	}
}

// TestOCSPUnreachableIsUnknownNotGood is the failure that matters: a responder
// that returns 500 must not be read as "not revoked".
func TestOCSPUnreachableIsUnknownNotGood(t *testing.T) {
	now := time.Now()
	fixture := newOCSPFixture(t, ocspAnswer{httpCode: http.StatusInternalServerError})

	got := check(t, fixture.withResponder(t), fixture.ca, now)
	if got.Status != domain.RevocationUnknown {
		t.Fatalf("status = %s, want unknown: an error is not an answer", got.Status)
	}
	if got.WasChecked() {
		t.Error("a failed query must not count as checked")
	}
	if got.IsRevoked() {
		t.Error("a failure is not a revocation either")
	}
	if got.Reason == "" {
		t.Error("an unknown status must say why")
	}
}

// TestOCSPStaleResponseIsRejected: an answer about a moment that has passed is
// not evidence about now.
func TestOCSPStaleResponseIsRejected(t *testing.T) {
	now := time.Now()
	fixture := newOCSPFixture(t, ocspAnswer{
		status:     ocsp.Good,
		thisUpdate: now.Add(-10 * 24 * time.Hour),
		nextUpdate: now.Add(-5 * 24 * time.Hour),
	})

	got := check(t, fixture.withResponder(t), fixture.ca, now)
	if got.Status != domain.RevocationUnknown {
		t.Errorf("status = %s, want unknown: the response is expired", got.Status)
	}
}

// TestNoResponderIsUnsupportedNotUnknown keeps the two non-answers apart: a
// certificate with no endpoint cannot be checked in principle, which is a
// different statement from "we tried and failed".
func TestNoResponderIsUnsupportedNotUnknown(t *testing.T) {
	fixture := newOCSPFixture(t, ocspAnswer{status: ocsp.Good})

	// The original leaf publishes no responder; only the clone points at one.
	got := check(t, fixture.leaf, fixture.ca, time.Now())
	if got.Status != domain.RevocationUnsupported {
		t.Errorf("status = %s, want unsupported", got.Status)
	}
	if got.WasChecked() {
		t.Error("no endpoint means nothing was checked")
	}
}

// TestMissingIssuerIsUnknown: the request cannot be built without it.
func TestMissingIssuerIsUnknown(t *testing.T) {
	fixture := newOCSPFixture(t, ocspAnswer{status: ocsp.Good})

	got := check(t, fixture.withResponder(t), nil, time.Now())
	if got.Status != domain.RevocationUnknown {
		t.Errorf("status = %s, want unknown", got.Status)
	}
	if got.Reason == "" {
		t.Error("the report must explain the missing issuer")
	}
}

// TestRevocationStatusNeverCollapsesToABoolean guards the vocabulary itself.
func TestRevocationStatusNeverCollapsesToABoolean(t *testing.T) {
	statuses := []domain.RevocationStatus{
		domain.RevocationGood,
		domain.RevocationRevoked,
		domain.RevocationUnknown,
		domain.RevocationUnsupported,
	}

	seen := map[domain.RevocationStatus]bool{}
	for _, status := range statuses {
		if seen[status] {
			t.Errorf("status %q is not distinct", status)
		}
		seen[status] = true
	}
	if len(seen) != 4 {
		t.Errorf("distinct statuses = %d, want 4", len(seen))
	}
}

// TestOCSPRequestIsPostedAsTheProtocolRequires pins the wire format: RFC 6960
// sends the DER request in the body of a POST.
func TestOCSPRequestIsPostedAsTheProtocolRequires(t *testing.T) {
	now := time.Now()

	var (
		method      string
		contentType string
		hadBody     bool
	)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Wire CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Wire Leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		method = request.Method
		contentType = request.Header.Get("Content-Type")
		hadBody = request.ContentLength > 0
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	clone := *leaf
	clone.OCSPServer = []string{server.URL}

	checker := infrastructure.NewOCSPChecker()
	checker.Now = now
	checker.Check(context.Background(), &clone, ca)

	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	if contentType != "application/ocsp-request" {
		t.Errorf("Content-Type = %q, want application/ocsp-request", contentType)
	}
	if !hadBody {
		t.Error("the DER request must travel in the body")
	}
}
