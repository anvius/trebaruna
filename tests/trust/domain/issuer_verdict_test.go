package domain_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/trust/domain"
)

// issue makes a certificate, self-signed without a parent.
func issue(t *testing.T, name string, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

// TestEveryIssuerVerdictCarriesItsCode: the code, not the English reason,
// is what a translated report reads.
func TestEveryIssuerVerdictCarriesItsCode(t *testing.T) {
	root, rootKey := issue(t, "Root CA", true, nil, nil)
	leaf, _ := issue(t, "MARIA GARCIA", false, root, rootKey)
	stranger, strangerKey := issue(t, "Other CA", true, nil, nil)
	unlisted, _ := issue(t, "LUIS PEREZ", false, stranger, strangerKey)
	selfSigned, _ := issue(t, "PROPIO", false, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	qualified := domain.TrustList{Territory: "ES", Services: []domain.TrustService{{ServiceType: "CA/QC", Status: domain.StatusGranted,
		Qualified: true, Certificates: []*x509.Certificate{root}}}}

	for name, check := range map[string]struct {
		certificate *x509.Certificate
		roots       *x509.CertPool
		list        domain.TrustList
		want        domain.IssuerCode
	}{
		"no certificate": {nil, roots, domain.TrustList{}, domain.IssuerNone},
		"self-signed":    {selfSigned, roots, qualified, domain.IssuerSelfSigned},
		"qualified":      {leaf, nil, qualified, domain.IssuerQualified},
		"no roots":       {leaf, nil, domain.TrustList{}, domain.IssuerNoRoots},
		"recognised":     {leaf, roots, domain.TrustList{}, domain.IssuerRecognised},
		"unlisted":       {unlisted, roots, qualified, domain.IssuerUnlisted},
	} {
		if verdict := domain.EvaluateIssuer(check.certificate, check.roots, check.list); verdict.Code != check.want || verdict.Reason == "" {
			t.Errorf("%s: %s (%q), want %s", name, verdict.Code, verdict.Reason, check.want)
		}
	}
}
