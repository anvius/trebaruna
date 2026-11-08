package integration_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/anvius/trebaruna/src/signing/application"
	signingdomain "codeberg.org/anvius/trebaruna/src/signing/domain"
	signinginfra "codeberg.org/anvius/trebaruna/src/signing/infrastructure"
	verificationdomain "codeberg.org/anvius/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/anvius/trebaruna/src/verification/infrastructure"
)

// TestCadesChainsToAnExternalRoot covers the same ground as its XAdES twin,
// for the container format that carries the chain inside the CMS.
//
// The point of the test is the anchor. The trust list publishes the authority
// that issues qualified certificates, and that authority is normally an
// intermediate, not a root. A verifier that only ever compares against a pool
// of roots will call every such document untrusted.
//
// The intermediate here is published as the anchor and the leaf is signed by it,
// so the container carries no path of its own.
func TestCadesChainsToAnExternalRoot(t *testing.T) {
	directory := t.TempDir()

	// The anchor is the intermediate: the trust list vouches for it, and it is
	// the one that signed the leaf.
	anchorCert, anchorKey := generateSelfSignedCA(t, "Trebaruna Test Authority")
	leafCert, leafKey := generateLeaf(t, anchorCert, anchorKey, "Maria Lopez Garcia")

	bundle := pemBundle(t, leafCert, leafKey)
	signer, err := signingdomain.NewSigner("Maria Lopez Garcia", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	adapter := signinginfra.NewCadesSigner(nil)
	signed, err := adapter.SignCades(t.Context(), application.CadesRequest{
		Content: []byte("contenido"),
		Signer:  signer,
		Level:   signingdomain.BES,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	path := filepath.Join(directory, "signed.p7m")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(anchorCert)

	verifier := verificationinfra.NewCadesVerifier()
	extractor := verifier.WithAnchorCertificates(roots, nil, []*x509.Certificate{anchorCert})

	reports, err := extractor.Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(reports))
	}
	report := reports[0]

	if report.Integrity != "good" {
		t.Fatalf("integrity = %s, want good (findings %+v)", report.Integrity, report.Findings)
	}
	if report.Trust != verificationdomain.TrustAdvanced {
		t.Errorf("trust = %s, want advanced: the leaf must chain to the published anchor", report.Trust)
	}
	if report.CertificateStatus != "good" {
		t.Errorf("certificate status = %s, want good", report.CertificateStatus)
	}
}

// TestCadesWithoutTheAnchorIsUntrusted is the other side of the same coin.
//
// The same container, verified without the anchor, must not read as advanced. A
// verifier that trusted the container's own certificate would be trusting the
// document to vouch for itself.
func TestCadesWithoutTheAnchorIsUntrusted(t *testing.T) {
	directory := t.TempDir()

	anchorCert, anchorKey := generateSelfSignedCA(t, "Trebaruna Test Authority")
	leafCert, leafKey := generateLeaf(t, anchorCert, anchorKey, "Maria Lopez Garcia")

	bundle := pemBundle(t, leafCert, leafKey)
	signer, err := signingdomain.NewSigner("Maria Lopez Garcia", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	adapter := signinginfra.NewCadesSigner(nil)
	signed, err := adapter.SignCades(t.Context(), application.CadesRequest{
		Content: []byte("contenido"),
		Signer:  signer,
		Level:   signingdomain.BES,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	path := filepath.Join(directory, "signed.p7m")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// No anchors at all: the system pool knows nothing about this authority.
	verifier := verificationinfra.NewCadesVerifier()
	reports, err := verifier.Extract(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if reports[0].Trust == verificationdomain.TrustAdvanced {
		t.Error("a container with no published anchor must not read as advanced")
	}
}
