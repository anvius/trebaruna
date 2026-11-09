// Package brainpool verifies ECDSA signatures on the Brainpool curves of
// RFC 5639 (brainpoolP256r1, P384r1, P512r1), which German health
// professionals' cards and their authorities use and Go does not have. It
// only verifies: nothing secret goes through it, so its arithmetic needs no
// constant time, and it is the plain affine one, kept small enough to read.
package brainpool

import (
	"encoding/asn1"
	"math/big"
)

// Curve is a short Weierstrass curve y² = x³ + ax + b over the prime field
// of P, with base point G of order N.
type Curve struct {
	Name   string
	OID    asn1.ObjectIdentifier
	P      *big.Int
	A, B   *big.Int
	Gx, Gy *big.Int
	N      *big.Int
}

func hexInt(text string) *big.Int {
	value, ok := new(big.Int).SetString(text, 16)
	if !ok {
		panic("brainpool: bad constant " + text)
	}
	return value
}

// The r1 curves of RFC 5639, 3.4, 3.6 and 3.7.
var (
	P256r1 = &Curve{
		Name: "brainpoolP256r1", OID: asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7},
		P:  hexInt("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"),
		A:  hexInt("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"),
		B:  hexInt("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"),
		Gx: hexInt("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"),
		Gy: hexInt("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"),
		N:  hexInt("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
	}
	P384r1 = &Curve{
		Name: "brainpoolP384r1", OID: asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11},
		P:  hexInt("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53"),
		A:  hexInt("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826"),
		B:  hexInt("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"),
		Gx: hexInt("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E"),
		Gy: hexInt("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315"),
		N:  hexInt("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"),
	}
	P512r1 = &Curve{
		Name: "brainpoolP512r1", OID: asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13},
		P:  hexInt("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3"),
		A:  hexInt("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA"),
		B:  hexInt("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723"),
		Gx: hexInt("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822"),
		Gy: hexInt("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892"),
		N:  hexInt("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"),
	}
)

// Curves are the curves this package knows.
var Curves = []*Curve{P256r1, P384r1, P512r1}

// curveFor finds a curve by its identifier.
func curveFor(oid asn1.ObjectIdentifier) *Curve {
	for _, curve := range Curves {
		if curve.OID.Equal(oid) {
			return curve
		}
	}
	return nil
}

// point is an affine point; nil coordinates are the point at infinity.
type point struct{ x, y *big.Int }

func (p point) infinite() bool { return p.x == nil }

// onCurve reports y² = x³ + ax + b (mod P) for a point inside the field.
func (c *Curve) onCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(c.P) >= 0 || y.Sign() < 0 || y.Cmp(c.P) >= 0 {
		return false
	}
	left := new(big.Int).Mul(y, y)
	left.Mod(left, c.P)
	right := new(big.Int).Mul(x, x)
	right.Mul(right, x)
	right.Add(right, new(big.Int).Mul(c.A, x))
	right.Add(right, c.B)
	right.Mod(right, c.P)
	return left.Cmp(right) == 0
}

// add returns p + q.
func (c *Curve) add(p, q point) point {
	switch {
	case p.infinite():
		return q
	case q.infinite():
		return p
	}
	var slope *big.Int
	if p.x.Cmp(q.x) == 0 {
		if new(big.Int).Add(p.y, q.y).Mod(new(big.Int).Add(p.y, q.y), c.P).Sign() == 0 {
			return point{}
		}
		// Doubling: (3x² + a) / 2y.
		numerator := new(big.Int).Mul(p.x, p.x)
		numerator.Mul(numerator, big.NewInt(3))
		numerator.Add(numerator, c.A)
		denominator := new(big.Int).Lsh(p.y, 1)
		slope = numerator.Mul(numerator, denominator.ModInverse(denominator, c.P))
	} else {
		numerator := new(big.Int).Sub(q.y, p.y)
		denominator := new(big.Int).Sub(q.x, p.x)
		denominator.Mod(denominator, c.P)
		slope = numerator.Mul(numerator, denominator.ModInverse(denominator, c.P))
	}
	slope.Mod(slope, c.P)
	x := new(big.Int).Mul(slope, slope)
	x.Sub(x, p.x)
	x.Sub(x, q.x)
	x.Mod(x, c.P)
	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, slope)
	y.Sub(y, p.y)
	y.Mod(y, c.P)
	return point{x, y}
}

// multiply returns k·p, double and add.
func (c *Curve) multiply(p point, k *big.Int) point {
	result := point{}
	for bit := k.BitLen() - 1; bit >= 0; bit-- {
		result = c.add(result, result)
		if k.Bit(bit) == 1 {
			result = c.add(result, p)
		}
	}
	return result
}
