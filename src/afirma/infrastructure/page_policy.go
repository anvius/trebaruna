package infrastructure

import (
	"maps"
	"strings"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// largeCAdESData is where AutoFirma's AGE expansion stops carrying the data
// inside a CAdES signature: from 1 MiB, mode=explicit.
const largeCAdESData = 1 << 20

// withPolicy reads the signature policy a page asks for (docs/afirma-protocol.md,
// F): AutoFirma's expPolicy shorthand, which also fixes how the data is
// packaged, or the policy's parts. A FacturaE invoice always carries one of
// FacturaE's policies.
func withPolicy(request application.PageSignature, family string) (application.PageSignature, signing.SignaturePolicy, error) {
	if name := request.Properties["expPolicy"]; name != "" {
		return expandPolicy(request, family, name)
	}

	requested, err := explicitPolicy(request.Properties, family)
	if err != nil {
		return request, signing.SignaturePolicy{}, err
	}
	if family != "facturae" {
		return request, requested, nil
	}
	policy, err := signing.FacturaEPolicy(requested)
	if err != nil {
		return request, signing.SignaturePolicy{}, invalidPolicy(err)
	}
	return request, policy, nil
}

// expandPolicy applies expPolicy (F.1): FirmaAGE (AGE 1.9) or FirmaAGE18,
// for CAdES, XAdES and PAdES. CAdES carries the data below 1 MiB unless the
// page says otherwise; XAdES is detached unless the page asked for enveloped.
func expandPolicy(request application.PageSignature, family, name string) (application.PageSignature, signing.SignaturePolicy, error) {
	var set string
	switch {
	case strings.EqualFold(name, "FirmaAGE"):
		set = "age"
	case strings.EqualFold(name, "FirmaAGE18"):
		set = "age18"
	default:
		// AutoFirma lists FirmaAGE19 too but refuses it, and so does this.
		return request, signing.SignaturePolicy{}, domain.Failure{Code: domain.InvalidPolicy, Cause: "expPolicy " + name}
	}

	request.Properties = maps.Clone(request.Properties)
	var format signing.Format
	switch family {
	case "cades":
		format = signing.Cades
		if request.Properties["mode"] == "" {
			request.Properties["mode"] = "implicit"
			if len(request.Data) >= largeCAdESData {
				request.Properties["mode"] = "explicit"
			}
		}
	case "xades":
		format = signing.Xades
		if xadesPackaging(request) != "enveloped" {
			request.Format.Packaging = "detached"
		}
	case "pades":
		if set != "age" {
			return request, signing.SignaturePolicy{}, domain.Failure{Code: domain.InvalidPolicy, Cause: "PDF signatures take FirmaAGE only"}
		}
		format = signing.Pades
	default:
		return request, signing.SignaturePolicy{}, domain.Failure{Code: domain.InvalidPolicy, Cause: "expPolicy applies to CAdES, XAdES and PAdES"}
	}
	policy, err := signing.NamedPolicy(set, format)
	if err != nil {
		return request, signing.SignaturePolicy{}, invalidPolicy(err)
	}
	return request, policy, nil
}

// explicitPolicy reads policyIdentifier and its digest (F.2); none when the
// page names no policy. AutoFirma downloads the policy when the page gives no
// digest; trebaruna does not fetch what the page points at, so the digest is
// required.
func explicitPolicy(properties map[string]string, family string) (signing.SignaturePolicy, error) {
	if properties["policyIdentifier"] == "" {
		return signing.SignaturePolicy{}, nil
	}
	hash := strings.TrimSpace(properties["policyIdentifierHash"])
	if hash == "" || hash == "0" {
		return signing.SignaturePolicy{}, domain.Failure{Code: domain.InvalidPolicy,
			Cause: "the page gave no policyIdentifierHash, and trebaruna does not download policies"}
	}
	algorithm := properties["policyIdentifierHashAlgorithm"]
	if algorithm == "" {
		return signing.SignaturePolicy{}, domain.Failure{Code: domain.InvalidPolicy, Cause: "policyIdentifierHashAlgorithm is missing"}
	}
	policy, err := signing.NewSignaturePolicy(properties["policyIdentifier"], algorithm, hash, properties["policyQualifier"])
	if err != nil {
		return signing.SignaturePolicy{}, invalidPolicy(err)
	}
	if err := policy.FitsFormat(formatOf(family)); err != nil {
		return signing.SignaturePolicy{}, invalidPolicy(err)
	}
	return policy, nil
}

// formatOf is the signature format of a family; FacturaE is XAdES.
func formatOf(family string) signing.Format {
	switch family {
	case "cades":
		return signing.Cades
	case "pades":
		return signing.Pades
	case "xmldsig":
		return signing.Xmldsig
	}
	return signing.Xades
}

// invalidPolicy is AutoFirma's SAF_23 with the reason.
func invalidPolicy(err error) error {
	return domain.Failure{Code: domain.InvalidPolicy, Cause: err.Error()}
}
