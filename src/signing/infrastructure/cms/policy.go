package cms

import (
	"encoding/asn1"
	"fmt"
)

// Signature policy attribute (ETSI EN 319 122-1, 5.2.9; RFC 5126, 5.8.1).
var (
	OIDSignaturePolicy = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}
	oidPolicyURI       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 1}
	oidSHA1            = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// policyDigests are the digest algorithms a policy's digest may use.
var policyDigests = map[string]asn1.ObjectIdentifier{"SHA1": oidSHA1, "SHA256": OIDSHA256, "SHA384": oidSHA384, "SHA512": oidSHA512}

// PolicyAttribute builds the signed attribute declaring a signature policy:
// SignaturePolicyId { sigPolicyId, sigPolicyHash, sigPolicyQualifiers }, the
// qualifier being the policy document's URI when one is given.
func PolicyAttribute(policy asn1.ObjectIdentifier, hashAlgorithm string, hash []byte, qualifier string) (Attribute, error) {
	algorithm, known := policyDigests[hashAlgorithm]
	if !known {
		return Attribute{}, fmt.Errorf("cms: unknown policy digest %q", hashAlgorithm)
	}
	d := &der{}
	elements := [][]byte{
		d.oid(policy),
		d.seq(d.seq(d.oid(algorithm)), d.octetString(hash)), // OtherHashAlgAndValue
	}
	if qualifier != "" {
		uri, err := asn1.MarshalWithParams(qualifier, "ia5")
		if err != nil {
			return Attribute{}, fmt.Errorf("cms: the policy qualifier must be ASCII: %w", err)
		}
		elements = append(elements, d.seq(d.seq(d.oid(oidPolicyURI), uri)))
	}
	return Attribute{Type: OIDSignaturePolicy, Value: d.seq(elements...)}, nil
}
