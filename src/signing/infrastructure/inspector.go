package infrastructure

import (
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// CertificateInspector reports who will sign and whether the certificate is
// self-signed, without producing any signature.
type CertificateInspector struct{}

// Resolve loads the key material and returns the certificate facts.
//
// It deliberately does not sign: reporting trust facts must never require a
// private key operation, especially with a smartcard where every operation can
// ask for a PIN.
func (CertificateInspector) Resolve(signer domain.Signer) (application.Identity, error) {
	keyPair, err := LoadKeyPair(signer)
	if err != nil {
		return application.Identity{}, fmt.Errorf("inspect signer %q: %w", signer.Name(), err)
	}

	return application.Identity{
		Subject:    keyPair.Certificate.Subject.String(),
		Issuer:     keyPair.Certificate.Issuer.String(),
		SelfSigned: keyPair.SelfSigned,
		KeySource:  keyPair.KeySource,
	}, nil
}

// compile-time check.
var _ application.IdentityResolver = CertificateInspector{}
