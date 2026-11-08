//go:build cgo

package infrastructure

import (
	"crypto"
	"fmt"

	"codeberg.org/anvius/trebaruna/src/signing/domain"
	"github.com/eclipse-keypont/crypto11"
)

// pkcs11Context adapts crypto11.Context to our tokenContext port.
type pkcs11Context struct {
	inner *crypto11.Context
}

// Pairs maps the library's tls.Certificate list onto our neutral type.
func (p pkcs11Context) Pairs() ([]tokenPair, error) {
	certificates, err := p.inner.FindAllPairedCertificates()
	if err != nil {
		return nil, err
	}

	pairs := make([]tokenPair, 0, len(certificates))
	for _, certificate := range certificates {
		signer, ok := certificate.PrivateKey.(crypto.Signer)
		if !ok {
			continue
		}
		if len(certificate.Certificate) == 0 {
			continue
		}
		pairs = append(pairs, tokenPair{
			Certificate: certificate.Certificate[0],
			Chain:       certificate.Certificate[1:],
			Signer:      signer,
		})
	}
	return pairs, nil
}

// Close releases the PKCS#11 session.
func (p pkcs11Context) Close() error { return p.inner.Close() }

// openToken connects to the smartcard through crypto11.
//
// Guarded by the cgo build tag: the static binary (P12/PEM only) omits it.
func openToken(signer domain.Signer) (tokenContext, error) {
	config := &crypto11.Config{
		Path:       signer.PKCS11Module(),
		TokenLabel: signer.PKCS11Token(),
		Pin:        signer.PKCS11PIN(),
	}
	context, err := crypto11.Configure(config)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot open PKCS#11 token %q with module %s: %w\n"+
				"  check: systemctl status pcscd ; pcsc_scan ; pkcs11-tool -L",
			signer.PKCS11Token(), signer.PKCS11Module(), err,
		)
	}
	return pkcs11Context{inner: context}, nil
}
