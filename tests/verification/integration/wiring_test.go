package integration_test

// Wiring guard: the use case only hands trust anchors to an extractor that
// satisfies application.AnchorAware. A mismatched method signature compiles
// fine and silently disables every trust list, which is how a fully authenticated
// Italian list still reported qualified signatures as untrusted.

import (
	"crypto/x509"
	"testing"

	"codeberg.org/anvius/trebaruna/src/verification/application"
	verificationinfra "codeberg.org/anvius/trebaruna/src/verification/infrastructure"
)

func TestExtractorsAcceptTrustAnchors(t *testing.T) {
	anchors := x509.NewCertPool()

	verifiers := map[string]interface{}{
		"PDF":   verificationinfra.NewPDFVerifier(),
		"CAdES": verificationinfra.NewCadesVerifier(),
		"XAdES": verificationinfra.NewXadesVerifier(),
	}

	for name, verifier := range verifiers {
		aware, ok := verifier.(application.AnchorAware)
		if !ok {
			t.Errorf("%s verifier does not satisfy application.AnchorAware: anchors would be dropped", name)
			continue
		}
		if aware.WithAnchors(anchors, anchors) == nil {
			t.Errorf("%s verifier returned no extractor when given anchors", name)
		}
	}
}
