package infrastructure

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signinfra "codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// signBare makes NONE's signature, as AutoFirma's AOPkcs1Signer does: the
// data hashed with the algorithm's digest and signed as they are, PKCS#1
// v1.5 for RSA and ASN.1 for ECDSA, then checked against the certificate.
// A bare signature has nothing to co- or counter-sign.
func signBare(request application.PageSignature) ([]byte, error) {
	if request.Crypto != domain.Sign {
		return nil, domain.Failure{Code: domain.UnsupportedOperation, Cause: "a bare signature (NONE) has no co- or counter-signatures"}
	}
	hash, known := digestHash(domain.DigestOf(request.Algorithm))
	if !known {
		return nil, domain.Failure{Code: domain.Params, Cause: request.Algorithm}
	}
	pair, err := signinfra.LoadKeyPair(request.Key)
	if err != nil {
		return nil, domain.Failure{Code: domain.CannotAccessKeystore, Cause: err.Error()}
	}
	defer pair.Close()
	hasher := hash.New()
	hasher.Write(request.Data)
	digest := hasher.Sum(nil)
	signature, err := pair.Signer.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: err.Error()}
	}
	if !verifies(pair.Certificate.PublicKey, hash, digest, signature) {
		return nil, domain.Failure{Code: domain.SignatureFailed, Cause: "the signature does not verify with the key's certificate"}
	}
	return signature, nil
}

// verifies checks a bare signature with an RSA or ECDSA public key.
func verifies(key crypto.PublicKey, hash crypto.Hash, digest, signature []byte) bool {
	switch public := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(public, hash, digest, signature) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(public, digest, signature)
	}
	return false
}
