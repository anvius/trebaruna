package brainpool

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// PublicKey is an ECDSA public key on a Brainpool curve.
type PublicKey struct {
	Curve *Curve
	X, Y  *big.Int
}

var (
	// ErrUnknownCurve means a key on a curve this package does not know.
	ErrUnknownCurve = errors.New("brainpool: not a Brainpool curve")
	// ErrBadKey means a key that is not a point of its curve.
	ErrBadKey = errors.New("brainpool: the public key is not a point of its curve")
)

// oidPublicKeyECDSA is id-ecPublicKey (RFC 5480).
var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// subjectPublicKeyInfo is RFC 5280's, its parameters kept raw.
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ParsePublicKey reads a SubjectPublicKeyInfo holding an ECDSA key on a
// Brainpool curve: an uncompressed point that lies on it.
func ParsePublicKey(spki []byte) (*PublicKey, error) {
	var info subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(spki, &info); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("brainpool: unreadable SubjectPublicKeyInfo: %v", err)
	}
	if !info.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, ErrUnknownCurve
	}
	var named asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &named); err != nil {
		return nil, ErrUnknownCurve
	}
	curve := curveFor(named)
	if curve == nil {
		return nil, ErrUnknownCurve
	}
	size := (curve.P.BitLen() + 7) / 8
	data := info.PublicKey.RightAlign()
	if len(data) != 1+2*size || data[0] != 4 {
		return nil, ErrBadKey
	}
	x, y := new(big.Int).SetBytes(data[1:1+size]), new(big.Int).SetBytes(data[1+size:])
	if !curve.onCurve(x, y) {
		return nil, ErrBadKey
	}
	return &PublicKey{Curve: curve, X: x, Y: y}, nil
}

// Verify checks an ECDSA signature (ASN.1 r, s) over a digest, as FIPS
// 186-4, 6.4.2 does: the digest's leftmost bits as wide as N.
func (k *PublicKey) Verify(digest, signature []byte) bool {
	var values struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(signature, &values); err != nil || len(rest) > 0 {
		return false
	}
	curve := k.Curve
	r, s := values.R, values.S
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(curve.N) >= 0 || s.Cmp(curve.N) >= 0 {
		return false
	}
	e := new(big.Int).SetBytes(digest)
	if excess := len(digest)*8 - curve.N.BitLen(); excess > 0 {
		e.Rsh(e, uint(excess))
	}
	w := new(big.Int).ModInverse(s, curve.N)
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, curve.N)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, curve.N)
	sum := curve.add(curve.multiply(point{curve.Gx, curve.Gy}, u1), curve.multiply(point{k.X, k.Y}, u2))
	if sum.infinite() {
		return false
	}
	return new(big.Int).Mod(sum.x, curve.N).Cmp(r) == 0
}

func pkixAlgorithm(algorithm, parameter asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	encoded, _ := asn1.Marshal(parameter)
	return pkix.AlgorithmIdentifier{Algorithm: algorithm, Parameters: asn1.RawValue{FullBytes: encoded}}
}
