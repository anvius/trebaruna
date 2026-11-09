package infrastructure

import (
	"encoding/asn1"
	"strings"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// oidSignaturePolicy is signature-policy-identifier (RFC 5126, 5.8.1).
var oidSignaturePolicy = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}

// cmsPolicy is the policy a CMS SignerInfo declares in its signed
// attributes, by its OID; empty for none, or for an implied policy.
func cmsPolicy(signedAttrs asn1.RawValue) string {
	for _, value := range attributeValues(signedAttrs, oidSignaturePolicy) {
		var policy struct {
			Identifier asn1.ObjectIdentifier
			Rest       asn1.RawValue `asn1:"optional"`
			More       asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(value, &policy); err == nil && len(policy.Identifier) > 0 {
			return policy.Identifier.String()
		}
	}
	return ""
}

// pdfDeclarations are a PDF signature's: the policy of its CMS envelope and
// the place its dictionary names (/Location).
func pdfDeclarations(signedAttrs asn1.RawValue, location, reason string) domain.Declarations {
	return domain.Declarations{Policy: cmsPolicy(signedAttrs), Place: strings.TrimSpace(location), Reason: strings.TrimSpace(reason)}
}

// xadesDeclarations reads what a XAdES signature declares in its own
// SignedSignatureProperties: the policy, the claimed roles (SignerRole or
// SignerRoleV2) and the production place (SignatureProductionPlace or V2).
func xadesDeclarations(signature *etree.Element) domain.Declarations {
	properties := signature.FindElement("./Object/QualifyingProperties/SignedProperties/SignedSignatureProperties")
	if properties == nil {
		return domain.Declarations{}
	}
	var declared domain.Declarations
	if identifier := properties.FindElement("./SignaturePolicyIdentifier/SignaturePolicyId/SigPolicyId/Identifier"); identifier != nil {
		declared.Policy = strings.TrimSpace(identifier.Text())
	}
	for _, path := range []string{"./SignerRole/ClaimedRoles/ClaimedRole", "./SignerRoleV2/ClaimedRoles/ClaimedRole"} {
		for _, role := range properties.FindElements(path) {
			if text := strings.TrimSpace(role.Text()); text != "" {
				declared.Roles = append(declared.Roles, text)
			}
		}
	}
	for _, name := range []string{"SignatureProductionPlace", "SignatureProductionPlaceV2"} {
		place := properties.SelectElement(name)
		if place == nil {
			continue
		}
		var parts []string
		for _, part := range []string{"StreetAddress", "City", "StateOrProvince", "PostalCode", "CountryName"} {
			if element := place.SelectElement(part); element != nil && strings.TrimSpace(element.Text()) != "" {
				parts = append(parts, strings.TrimSpace(element.Text()))
			}
		}
		declared.Place = strings.Join(parts, ", ")
	}
	return declared
}
