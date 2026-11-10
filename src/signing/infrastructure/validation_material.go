package infrastructure

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// validationMaterial is what a long-term signature carries so that it can
// be checked once the responders are gone (EN 319 122-1 and EN 319 132-1
// at B-LT, ISO 32000-2's document security store): the certificates of
// the signer's chain and of each timestamp authority's, and an OCSP answer
// for every one of them but the roots. A validator such as EU DSS rates a
// signature without its authorities' material at T, however much it holds
// about the signer.
type validationMaterial struct {
	// signerChain is the signer's certificate and its issuers.
	signerChain []*x509.Certificate
	// authorities are the certificates of the timestamp authorities'
	// chains the signer's chain does not already hold.
	authorities []*x509.Certificate
	// responses are the OCSP answers as the responders sent them.
	responses [][]byte
}

// certificates is every certificate of the material, the signer's chain
// first.
func (m validationMaterial) certificates() []*x509.Certificate {
	return append(append([]*x509.Certificate{}, m.signerChain...), m.authorities...)
}

// gatherValidationMaterial asks the responders about the signer's chain
// and about the chain of the authority behind each timestamp token. A
// revoked certificate refuses the signature. The signer's chain must give
// at least one answer, or the level could not claim to carry any; without
// one the error says that incomplete names what is left incomplete. An
// authority whose certificates name no responder, or whose issuer its
// token leaves out, adds what it can.
func gatherValidationMaterial(ctx context.Context, keyPair KeyPair, tokens [][]byte, incomplete string) (validationMaterial, error) {
	chain := keyPair.Certificates()
	if len(chain) == 0 {
		return validationMaterial{}, fmt.Errorf("the signer carries no certificate chain to embed")
	}
	checker := verificationinfra.NewOCSPChecker()
	material := validationMaterial{signerChain: chain}
	asked := map[string]bool{}
	var warnings []string
	ask := func(certificate, issuer *x509.Certificate, whose string) error {
		asked[string(certificate.Raw)] = true
		status := checker.Check(ctx, certificate, issuer)
		switch {
		case status.IsRevoked():
			return fmt.Errorf("refusing to sign: %s %q is revoked since %s",
				whose, certificate.Subject.CommonName, status.RevokedAt.Format(time.RFC3339))
		case status.Status == verificationdomain.RevocationGood && len(status.RawResponse) > 0:
			material.responses = append(material.responses, status.RawResponse)
		default:
			warnings = append(warnings, fmt.Sprintf("%s: %s", certificate.Subject.CommonName, status.Reason))
		}
		return nil
	}

	for index := 0; index+1 < len(chain); index++ {
		if err := ask(chain[index], chain[index+1], "the certificate for"); err != nil {
			return validationMaterial{}, err
		}
	}
	if len(material.responses) == 0 {
		return validationMaterial{}, fmt.Errorf("no revocation answer could be obtained, so %s:\n  %s",
			incomplete, strings.Join(warnings, "\n  "))
	}

	held := map[string]bool{}
	for _, certificate := range chain {
		held[string(certificate.Raw)] = true
	}
	for _, token := range tokens {
		authority := authorityChain(token, chain)
		for index, certificate := range authority {
			if !held[string(certificate.Raw)] {
				held[string(certificate.Raw)] = true
				material.authorities = append(material.authorities, certificate)
			}
			if index+1 < len(authority) && !asked[string(certificate.Raw)] {
				if err := ask(certificate, authority[index+1], "the timestamp authority's certificate"); err != nil {
					return validationMaterial{}, err
				}
			}
		}
	}
	return material, nil
}

// authorityChain is the chain of the authority that signed a timestamp
// token: its certificate, the one the timeStamping purpose names, and the
// issuers found among the token's certificates and the signer's chain,
// each checked to have signed the one below. Empty when the token carries
// no certificate.
func authorityChain(token []byte, signerChain []*x509.Certificate) []*x509.Certificate {
	encoded, err := cms.Certificates(token)
	if err != nil {
		return nil
	}
	var pool []*x509.Certificate
	var leaf *x509.Certificate
	for _, der := range encoded {
		certificate, err := brainpool.ParseCertificate(der)
		if err != nil {
			continue
		}
		pool = append(pool, certificate)
		for _, usage := range certificate.ExtKeyUsage {
			if usage == x509.ExtKeyUsageTimeStamping && leaf == nil {
				leaf = certificate
			}
		}
	}
	if leaf == nil {
		return nil
	}
	pool = append(pool, signerChain...)
	chain := []*x509.Certificate{leaf}
	for current := leaf; len(chain) < 8 && !bytes.Equal(current.RawIssuer, current.RawSubject); {
		var issuer *x509.Certificate
		for _, candidate := range pool {
			if bytes.Equal(candidate.RawSubject, current.RawIssuer) && !candidate.Equal(current) &&
				brainpool.CheckSignatureFrom(current, candidate) == nil {
				issuer = candidate
				break
			}
		}
		if issuer == nil {
			break
		}
		chain = append(chain, issuer)
		current = issuer
	}
	return chain
}
