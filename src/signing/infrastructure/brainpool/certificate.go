package brainpool

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ParseCertificate reads a certificate whose key may be on a Brainpool
// curve. Go's parser reads everything but such a key, so the key is
// swapped for a placeholder while it reads; the certificate returned has
// its own bytes back and the Brainpool key as its PublicKey. Any other
// certificate is Go's, unchanged.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(der)
	if err == nil {
		return certificate, nil
	}
	parsed, swapErr := parseSwapped(der)
	if swapErr != nil {
		return nil, err
	}
	return parsed, nil
}

// ErrKeyInFile means a certificate whose key is on a Brainpool curve came
// with its private key in a file: Go has no arithmetic to sign with such a
// key, which trebaruna uses on a card only.
var ErrKeyInFile = errors.New("trebaruna signs with a Brainpool key on a card only, not from a file")

// KeyInFile is ErrKeyInFile, naming the curve, when the certificate's key
// is on a Brainpool curve; nil for any other certificate.
func KeyInFile(der []byte) error {
	certificate, err := parseSwapped(der)
	if err != nil {
		return nil
	}
	return fmt.Errorf("%w: the certificate's key is on %s", ErrKeyInFile, certificate.PublicKey.(*PublicKey).Curve.Name)
}

// placeholderKey is P-256's base point as a SubjectPublicKeyInfo: a key Go
// reads, standing in while it parses the rest.
var placeholderKey = func() []byte {
	params := elliptic.P256().Params()
	point := append([]byte{4}, append(params.Gx.FillBytes(make([]byte, 32)), params.Gy.FillBytes(make([]byte, 32))...)...)
	encoded, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkixAlgorithm(oidPublicKeyECDSA, asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
		PublicKey: asn1.BitString{Bytes: point, BitLength: 8 * len(point)},
	})
	if err != nil {
		panic(err)
	}
	return encoded
}()

func parseSwapped(der []byte) (*x509.Certificate, error) {
	var outer []asn1.RawValue
	if err := readSequence(der, &outer); err != nil || len(outer) != 3 {
		return nil, errors.New("brainpool: not a certificate")
	}
	var fields []asn1.RawValue
	if err := readSequence(outer[0].FullBytes, &fields); err != nil {
		return nil, err
	}
	keyAt := 5
	if len(fields) > 0 && fields[0].Class == asn1.ClassContextSpecific && fields[0].Tag == 0 {
		keyAt = 6
	}
	if len(fields) <= keyAt {
		return nil, errors.New("brainpool: a certificate without its key")
	}
	key, err := ParsePublicKey(fields[keyAt].FullBytes)
	if err != nil {
		return nil, err
	}
	originalKey := fields[keyAt].FullBytes
	fields[keyAt].FullBytes = placeholderKey
	tbs, err := writeSequence(fields)
	if err != nil {
		return nil, err
	}
	rebuilt, err := writeSequence([]asn1.RawValue{{FullBytes: tbs}, outer[1], outer[2]})
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(rebuilt)
	if err != nil {
		return nil, err
	}
	certificate.Raw = der
	certificate.RawTBSCertificate = outer[0].FullBytes
	certificate.RawSubjectPublicKeyInfo = originalKey
	certificate.PublicKey, certificate.PublicKeyAlgorithm = key, x509.ECDSA
	return certificate, nil
}

// readSequence splits a SEQUENCE into its elements, as they are.
func readSequence(der []byte, elements *[]asn1.RawValue) error {
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &sequence); err != nil || len(rest) > 0 || sequence.Tag != asn1.TagSequence {
		return errors.New("brainpool: not a SEQUENCE")
	}
	for rest := sequence.Bytes; len(rest) > 0; {
		var element asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &element); err != nil {
			return err
		}
		*elements = append(*elements, element)
	}
	return nil
}

// writeSequence joins elements into a SEQUENCE.
func writeSequence(elements []asn1.RawValue) ([]byte, error) {
	var content []byte
	for _, element := range elements {
		content = append(content, element.FullBytes...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
}

// hashes are the ECDSA certificate signatures this package checks.
var hashes = map[x509.SignatureAlgorithm]crypto.Hash{
	x509.ECDSAWithSHA256: crypto.SHA256, x509.ECDSAWithSHA384: crypto.SHA384, x509.ECDSAWithSHA512: crypto.SHA512,
}

// CheckSignature checks an ECDSA signature by the key over signed.
func (k *PublicKey) CheckSignature(algorithm x509.SignatureAlgorithm, signed, signature []byte) error {
	hash, known := hashes[algorithm]
	if !known {
		return fmt.Errorf("brainpool: %v is not an ECDSA signature this package checks", algorithm)
	}
	hasher := hash.New()
	hasher.Write(signed)
	if !k.Verify(hasher.Sum(nil), signature) {
		return x509.ErrUnsupportedAlgorithm
	}
	return nil
}

// ErrNotIssuer means the parent certificate may not issue certificates.
var ErrNotIssuer = errors.New("brainpool: the issuer may not sign certificates")

// CheckSignatureFrom checks that parent signed child: by this package when
// the parent's key is a Brainpool one, by Go otherwise.
func CheckSignatureFrom(child, parent *x509.Certificate) error {
	key, ok := parent.PublicKey.(*PublicKey)
	if !ok {
		return child.CheckSignatureFrom(parent)
	}
	// As Go's CheckSignatureFrom: a version 3 issuer must say it is an
	// authority, and its key usage, when declared, must allow it.
	if (parent.Version == 3 && !parent.BasicConstraintsValid) || (parent.BasicConstraintsValid && !parent.IsCA) ||
		(parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0) {
		return ErrNotIssuer
	}
	if err := key.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
		return fmt.Errorf("brainpool: the issuer's signature does not verify")
	}
	return nil
}
