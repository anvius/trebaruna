package domain

import "strings"

// Declarations are what a signature declares in its signed attributes or
// properties. They are the signer's statements, covered by the signature,
// not facts trebaruna checked: a policy named is not a policy followed.
type Declarations struct {
	// Policy is the signature policy's identifier: an OID, or a URL in XAdES.
	Policy string
	// Roles are the roles the signer claims (XAdES ClaimedRole).
	Roles []string
	// Place is where the signature says it was made.
	Place string
	// Reason is why, as a PDF signature says it (/Reason).
	Reason string
}

// knownPolicies are the policies trebaruna signs with, by identifier.
var knownPolicies = map[string]string{
	"2.16.724.1.3.1.1.2.1.9": "AGE 1.9",
	"2.16.724.1.3.1.1.2.1.8": "AGE 1.8",
	"http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf": "FacturaE 3.1",
	"http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf": "FacturaE 3.0",
}

// PolicyIdentifier is the policy's identifier, an OID without its urn:oid:.
func (d Declarations) PolicyIdentifier() string {
	return strings.TrimPrefix(strings.TrimSpace(d.Policy), "urn:oid:")
}

// PolicyName is the common name of a policy trebaruna knows, or empty.
func (d Declarations) PolicyName() string {
	return knownPolicies[d.PolicyIdentifier()]
}

// PolicyText is how a report shows the policy: its name and identifier,
// or the identifier alone.
func (d Declarations) PolicyText() string {
	if name := d.PolicyName(); name != "" {
		return name + " (" + d.PolicyIdentifier() + ")"
	}
	return d.PolicyIdentifier()
}

// Empty reports a signature that declares none of them.
func (d Declarations) Empty() bool {
	return d.Policy == "" && len(d.Roles) == 0 && d.Place == ""
}
