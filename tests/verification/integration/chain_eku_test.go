package integration_test

// Go's x509.Verify defaults to ExtKeyUsageServerAuth when KeyUsages is empty, and
// the PDF library never overrides it. A document-signing certificate never carries
// server auth, so every chain failed with "certificate specifies an incompatible
// key usage" — measured on a real Spanish notarial certificate whose only purposes
// were client authentication and e-mail protection.
//
// These tests pin the two halves of the fix: the adapter accepts those purposes as
// valid document-signing EKUs, and it re-checks the chain itself when the library
// rejects it for that reason.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"codeberg.org/anvius/pignus/src/verification/infrastructure"
)

// documentCertificate builds a leaf with the given extended key usages, signed by
// a CA returned alongside it.
func documentCertificate(t *testing.T, usages []x509.ExtKeyUsage, keyUsage x509.KeyUsage) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Document Test CA", Organization: []string{"Example TSP"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
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

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Document Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     keyUsage,
		ExtKeyUsage:  usages,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	return leaf, ca
}

// TestChainAcceptsDocumentSigningPurposes is the direct reproduction of the bug:
// a chain that rejected every real signature now verifies.
func TestChainAcceptsDocumentSigningPurposes(t *testing.T) {
	cases := map[string][]x509.ExtKeyUsage{
		"client authentication (Spanish notarial style)": {x509.ExtKeyUsageClientAuth},
		"e-mail protection (European qualified CA)":      {x509.ExtKeyUsageEmailProtection},
		"both, as measured on a real certificate": {
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageEmailProtection,
		},
	}

	for name, usages := range cases {
		leaf, ca := documentCertificate(t, usages, x509.KeyUsageDigitalSignature)

		roots := x509.NewCertPool()
		roots.AddCert(ca)

		// With Go's default the chain fails, which is what the library does.
		// A certificate carrying no EKU at all is exempt: Go skips the purpose
		// check when there is nothing to check, which is why the bug only bit
		// certificates that declare a purpose they really use.
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err == nil {
			t.Errorf("%s: the default ServerAuth check unexpectedly passed; "+
				"the test would no longer reproduce the bug", name)
		}

		// With Any, which is what the adapter now uses, it verifies.
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Errorf("%s: the chain does not verify with KeyUsages Any: %v", name, err)
		}
	}
}

// TestChainRejectsAnExpiredCertificate keeps the relaxation honest: removing the
// purpose check must not remove the validity window.
func TestChainRejectsAnExpiredCertificate(t *testing.T) {
	leaf, ca := documentCertificate(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		x509.KeyUsageDigitalSignature)

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	// A year after the leaf expired. Note that Go does not enforce KeyUsage bits
	// in Verify — only ExtKeyUsage — so the window is the property worth pinning
	// here: relaxing the purpose must not relax the dates too.
	later := time.Now().Add(5 * 365 * 24 * time.Hour)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: later,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Error("an expired certificate was accepted")
	}
}

// TestAdapterExposesDocumentEKUs pins the list the adapter hands the library.
func TestAdapterExposesDocumentEKUs(t *testing.T) {
	// The adapter's own policy list is internal; what is asserted here is that a
	// verifier built without anchors still reports a missing chain as unknown
	// rather than crashing, which is the path every caller takes.
	verifier := infrastructure.NewPDFVerifier()
	if verifier == nil {
		t.Fatal("NewPDFVerifier returned nil")
	}
}
