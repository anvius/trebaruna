package domain

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

var (
	// ErrUnknownPolicy means a policy name trebaruna does not know.
	ErrUnknownPolicy = errors.New("unknown signature policy")
	// ErrInvalidPolicy means a policy given by its parts is incomplete.
	ErrInvalidPolicy = errors.New("invalid signature policy")
	// ErrPolicyNotForFormat means the policy cannot go in this format: a
	// policy named by a URL (FacturaE's) only fits XAdES.
	ErrPolicyNotForFormat = errors.New("this signature policy does not apply to the format")
	// ErrInvalidRole means a role the policy does not allow.
	ErrInvalidRole = errors.New("invalid claimed role")
)

// SignaturePolicy is the policy an EPES signature declares (ETSI EN 319
// 122/132): the policy's identifier, the digest of its document, and where
// to read it. Validators compare the digest with the policy they know.
type SignaturePolicy struct {
	identifier    string
	hashAlgorithm string
	hash          []byte
	qualifier     string
}

// Spanish and FacturaE policies, as AutoFirma 1.9 declares them
// (docs/afirma-protocol.md, F). The AGE 1.9 digest equals the SHA-1 of the
// document published at its qualifier (checked 2026-11-09). The FacturaE 3.1
// digest is the historical value validators expect; the PDF served today at
// that address was re-issued and hashes differently.
const (
	ageOID19     = "2.16.724.1.3.1.1.2.1.9"
	ageOID18     = "2.16.724.1.3.1.1.2.1.8"
	ageQualifier = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf"
	age18Address = "https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf"
	facturaE31   = "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf"
	facturaE30   = "http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf"
)

// NamedPolicy returns a known policy for a signature format (cades, pades,
// xades): age (AGE 1.9), age18, facturae (3.1) and facturae30.
func NamedPolicy(name string, format Format) (SignaturePolicy, error) {
	xades := format == Xades
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "age", "firmaage", "age19", "firmaage19":
		return policy(ageOID19, "SHA1", "G7roucf600+f03r/o0bAOQ6WAs0=", ageQualifier), nil
	case "age18", "firmaage18":
		hash := "7SxX3erFuH31TvAw9LZ70N7p1vA="
		if xades {
			hash = "V8lVVNGDCPen6VELRD1Ja8HARFk="
		}
		return policy(ageOID18, "SHA1", hash, age18Address), nil
	case "facturae", "facturae31":
		return policy(facturaE31, "SHA1", "Ohixl6upD6av8N7pEvDABhEL6hM=", ""), nil
	case "facturae30":
		return policy(facturaE30, "SHA1", "xmfh8D/Ec/hHeE1IB4zPd61zHIY=", ""), nil
	}
	return SignaturePolicy{}, fmt.Errorf("%w %q: age, age18, facturae, facturae30", ErrUnknownPolicy, name)
}

func policy(identifier, algorithm, hash, qualifier string) SignaturePolicy {
	decoded, _ := base64.StdEncoding.DecodeString(hash)
	return SignaturePolicy{identifier: identifier, hashAlgorithm: algorithm, hash: decoded, qualifier: qualifier}
}

// NewSignaturePolicy builds a policy from its parts: an OID (bare or
// urn:oid:) or a URL, the digest algorithm (SHA1, SHA-256, …, or an XMLDSig
// URI), the digest in Base64 and an optional qualifier URL.
func NewSignaturePolicy(identifier, algorithm, hash, qualifier string) (SignaturePolicy, error) {
	identifier = strings.TrimPrefix(strings.TrimSpace(identifier), "urn:oid:")
	if identifier == "" {
		return SignaturePolicy{}, fmt.Errorf("%w: no identifier", ErrInvalidPolicy)
	}
	name, known := digestName(algorithm)
	if !known {
		return SignaturePolicy{}, fmt.Errorf("%w: unknown digest algorithm %q", ErrInvalidPolicy, algorithm)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(hash))
	if err != nil || len(decoded) == 0 {
		return SignaturePolicy{}, fmt.Errorf("%w: the policy digest must be Base64", ErrInvalidPolicy)
	}
	if len(decoded) != digestSizes[name] {
		return SignaturePolicy{}, fmt.Errorf("%w: a %s digest is %d bytes, not %d", ErrInvalidPolicy, name, digestSizes[name], len(decoded))
	}
	if qualifier != "" {
		if parsed, err := url.Parse(qualifier); err != nil || parsed.Scheme == "" {
			return SignaturePolicy{}, fmt.Errorf("%w: the qualifier must be a URL", ErrInvalidPolicy)
		}
	}
	return SignaturePolicy{identifier: identifier, hashAlgorithm: name, hash: decoded, qualifier: qualifier}, nil
}

// digestSizes are the lengths of the digests, in bytes.
var digestSizes = map[string]int{"SHA1": 20, "SHA256": 32, "SHA384": 48, "SHA512": 64}

// digestName normalises a digest algorithm name.
func digestName(algorithm string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "sha1", "sha-1", "http://www.w3.org/2000/09/xmldsig#sha1":
		return "SHA1", true
	case "sha256", "sha-256", "http://www.w3.org/2001/04/xmlenc#sha256":
		return "SHA256", true
	case "sha384", "sha-384", "http://www.w3.org/2001/04/xmldsig-more#sha384":
		return "SHA384", true
	case "sha512", "sha-512", "http://www.w3.org/2001/04/xmlenc#sha512":
		return "SHA512", true
	}
	return "", false
}

// IsZero reports no policy.
func (p SignaturePolicy) IsZero() bool { return p.identifier == "" }

// Identifier is the policy's OID or URL.
func (p SignaturePolicy) Identifier() string { return p.identifier }

// OID returns the identifier as an object identifier, which CAdES and PAdES
// need; a policy named by a URL has none.
func (p SignaturePolicy) OID() (asn1.ObjectIdentifier, bool) {
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(p.identifier, ".") {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, false
		}
		oid = append(oid, value)
	}
	return oid, len(oid) >= 2
}

// HashAlgorithm is the digest algorithm's name: SHA1, SHA256, SHA384, SHA512.
func (p SignaturePolicy) HashAlgorithm() string { return p.hashAlgorithm }

// Hash is the digest of the policy document.
func (p SignaturePolicy) Hash() []byte { return p.hash }

// Qualifier is the URL of the policy document, empty when none is declared.
func (p SignaturePolicy) Qualifier() string { return p.qualifier }

// FitsFormat refuses a policy the format cannot carry: XMLDSig has no
// signed properties to declare one in.
func (p SignaturePolicy) FitsFormat(format Format) error {
	if p.IsZero() || format == Xades {
		return nil
	}
	if format == Xmldsig {
		return fmt.Errorf("%w: XMLDSig signatures have no signed properties to declare a policy in", ErrPolicyNotForFormat)
	}
	if _, ok := p.OID(); !ok {
		return fmt.Errorf("%w: %s is named by a URL, which only XAdES carries", ErrPolicyNotForFormat, p.identifier)
	}
	return nil
}

// Equal reports the same policy: identifier, digest and qualifier.
func (p SignaturePolicy) Equal(other SignaturePolicy) bool {
	return p.identifier == other.identifier && p.hashAlgorithm == other.hashAlgorithm &&
		bytes.Equal(p.hash, other.hash) && p.qualifier == other.qualifier
}

// IsFacturaE reports one of FacturaE's policies, which only sign FacturaE
// invoices, enveloped.
func (p SignaturePolicy) IsFacturaE() bool {
	return p.identifier == facturaE31 || p.identifier == facturaE30
}

// ErrNotFacturaE means a FacturaE policy was asked for a document that is not
// a FacturaE invoice, or one already signed.
var ErrNotFacturaE = errors.New("FacturaE policies sign unsigned FacturaE invoices")

// AcceptsInvoice checks a FacturaE policy's document: the root element is
// Facturae and it carries no signature yet (AutoFirma's SAF_32 and SAF_38).
func (p SignaturePolicy) AcceptsInvoice(content []byte) error {
	if !p.IsFacturaE() {
		return nil
	}
	root, found := rootElement(content)
	switch {
	case !found:
		return fmt.Errorf("%w: no XML root", ErrNotFacturaE)
	case root != "Facturae":
		return fmt.Errorf("%w: the root is %s", ErrNotFacturaE, root)
	case bytes.Contains(content, []byte("http://www.w3.org/2000/09/xmldsig#")) && bytes.Contains(content, []byte("SignatureValue")):
		return fmt.Errorf("%w: the invoice is already signed", ErrNotFacturaE)
	}
	return nil
}

// IsFacturaEInvoice reports an XML whose root is Facturae, signed or not:
// AutoFirma's auto format hands it to the FacturaE signer.
func IsFacturaEInvoice(content []byte) bool {
	root, found := rootElement(content)
	return found && root == "Facturae"
}

// rootElement is the local name of an XML document's root element.
func rootElement(content []byte) (string, bool) {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}
		if start, ok := token.(xml.StartElement); ok {
			return start.Name.Local, true
		}
	}
}

// FacturaEPolicy is the policy a FacturaE invoice is signed with: 3.1 unless
// the request names 3.0 or 3.1 exactly, as AutoFirma's FacturaE signer does.
func FacturaEPolicy(requested SignaturePolicy) (SignaturePolicy, error) {
	if requested.IsZero() {
		return NamedPolicy("facturae", Xades)
	}
	for _, name := range []string{"facturae", "facturae30"} {
		if known, _ := NamedPolicy(name, Xades); requested.Equal(known) {
			return known, nil
		}
	}
	return SignaturePolicy{}, fmt.Errorf("%w: FacturaE invoices are signed with FacturaE's policy 3.0 or 3.1", ErrInvalidPolicy)
}

// facturaERoles are the roles FacturaE's policy names, in Spanish and English.
var facturaERoles = []string{"emisor", "receptor", "tercero", "supplier", "customer", "third party"}

// FacturaERoles checks the roles a FacturaE signature claims; none means the
// issuer, emisor.
func FacturaERoles(claimed []string) ([]string, error) {
	if len(claimed) == 0 {
		return []string{"emisor"}, nil
	}
	for _, role := range claimed {
		allowed := slices.ContainsFunc(facturaERoles, func(known string) bool {
			return strings.EqualFold(known, strings.TrimSpace(role))
		})
		if !allowed {
			return nil, fmt.Errorf("%w: %q is not a FacturaE role (emisor, receptor, tercero)", ErrInvalidRole, role)
		}
	}
	return claimed, nil
}
