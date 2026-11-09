package infrastructure

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/publickey"
)

// errUnsupportedSignature marks a CMS signature made with something
// trebaruna does not implement: its integrity is unknown, not bad
// (ADR-0005).
var errUnsupportedSignature = errors.New("the signature uses an algorithm trebaruna cannot check")

// oidMGF1 is the mask generation function RSASSA-PSS uses (RFC 8017).
var oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

// sha1Identifier is the digest RSASSA-PSS-params default to (RFC 4055).
var sha1Identifier = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}

// pssParameters are RSASSA-PSS-params (RFC 4055, 3.1).
type pssParameters struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGen      pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength   int                      `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// isPSS reports a SignerInfo signed with RSASSA-PSS, which the CMS library
// does not implement.
func isPSS(algorithm pkix.AlgorithmIdentifier) bool {
	return algorithm.Algorithm.Equal(publickey.OIDRSASSAPSS)
}

// checkSignerSignature checks a SignerInfo's signature over its signed
// attributes (the DER SET) with the certificate's key.
func checkSignerSignature(certificate *x509.Certificate, algorithm pkix.AlgorithmIdentifier, digest crypto.Hash, attributes, signature []byte) error {
	if isPSS(algorithm) {
		return checkPSS(certificate, algorithm.Parameters.FullBytes, attributes, signature)
	}
	known, ok := signatureAlgorithm(algorithm.Algorithm, digest)
	if !ok {
		return fmt.Errorf("%w: %v", errUnsupportedSignature, algorithm.Algorithm)
	}
	if key, isBrainpool := certificate.PublicKey.(*brainpool.PublicKey); isBrainpool {
		if err := key.CheckSignature(known, attributes, signature); err != nil {
			return fmt.Errorf("the %s signature does not verify", key.Curve.Name)
		}
		return nil
	}
	err := certificate.CheckSignature(known, attributes, signature)
	if errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		return fmt.Errorf("%w: %v", errUnsupportedSignature, err)
	}
	return err
}

// checkPSS checks an RSASSA-PSS signature with its parameters: the digest,
// MGF1 over the same digest (the only mask crypto/rsa implements), the salt
// length and the trailer 0xBC.
func checkPSS(certificate *x509.Certificate, encoded, signed, signature []byte) error {
	parameters := pssParameters{Hash: sha1Identifier, SaltLength: 20, TrailerField: 1}
	if len(encoded) > 0 {
		if rest, err := asn1.Unmarshal(encoded, &parameters); err != nil || len(rest) > 0 {
			return fmt.Errorf("%w: unreadable RSASSA-PSS parameters", errUnsupportedSignature)
		}
	}
	if len(parameters.Hash.Algorithm) == 0 {
		parameters.Hash = sha1Identifier
	}
	hash, ok := digestFromOID(parameters.Hash.Algorithm)
	if !ok {
		return fmt.Errorf("%w: RSASSA-PSS over %v", errUnsupportedSignature, parameters.Hash.Algorithm)
	}
	maskHash := sha1Identifier
	if len(parameters.MaskGen.Algorithm) > 0 {
		if !parameters.MaskGen.Algorithm.Equal(oidMGF1) {
			return fmt.Errorf("%w: mask generation %v", errUnsupportedSignature, parameters.MaskGen.Algorithm)
		}
		if _, err := asn1.Unmarshal(parameters.MaskGen.Parameters.FullBytes, &maskHash); err != nil {
			return fmt.Errorf("%w: unreadable MGF1 digest", errUnsupportedSignature)
		}
	}
	if !maskHash.Algorithm.Equal(parameters.Hash.Algorithm) || parameters.TrailerField != 1 || parameters.SaltLength < 0 {
		return fmt.Errorf("%w: RSASSA-PSS with MGF1 over %v, trailer %d", errUnsupportedSignature, maskHash.Algorithm, parameters.TrailerField)
	}
	key, ok := publickey.Of(certificate).(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: RSASSA-PSS with a key that is not RSA", errUnsupportedSignature)
	}
	digest := hash.New()
	digest.Write(signed)
	// A salt length of 0 reads, in crypto/rsa, as "any": the signature still
	// has to verify under the key.
	if err := rsa.VerifyPSS(key, hash, digest.Sum(nil), signature, &rsa.PSSOptions{SaltLength: parameters.SaltLength, Hash: hash}); err != nil {
		return fmt.Errorf("the RSASSA-PSS signature does not verify: %w", err)
	}
	return nil
}

// unsupportedByLibrary reports a CMS or PDF library error that means "not
// implemented", not "does not match": the libraries say so only in their
// messages, which the PDF library also wraps in its own.
func unsupportedByLibrary(err error) bool {
	message := err.Error()
	return errors.Is(err, x509.ErrUnsupportedAlgorithm) ||
		strings.Contains(message, "pkcs7: unsupported algorithm") ||
		strings.Contains(message, x509.ErrUnsupportedAlgorithm.Error())
}
