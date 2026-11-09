package domain

import "strings"

// ClaimedRoles reads signerClaimedRoles, several separated by "|".
func ClaimedRoles(properties map[string]string) []string {
	var roles []string
	for _, role := range strings.Split(properties["signerClaimedRoles"], "|") {
		if role = strings.TrimSpace(role); role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}

// DeclaredPolicy is the policy a page asks the signature to declare, as
// the person reads it: AGE's by name (expPolicy), any other by its
// identifier; empty for none.
func DeclaredPolicy(properties map[string]string) string {
	switch strings.ToLower(strings.TrimSpace(properties["expPolicy"])) {
	case "firmaage", "firmaage19":
		return "AGE 1.9"
	case "firmaage18":
		return "AGE 1.8"
	}
	return strings.TrimPrefix(strings.TrimSpace(properties["policyIdentifier"]), "urn:oid:")
}

// ProductionPlace is the place a page asks the signature to declare:
// signatureProductionCity, …Province, …PostalCode and …Country.
func ProductionPlace(properties map[string]string) (city, province, postalCode, country string) {
	value := func(key string) string { return strings.TrimSpace(properties[key]) }
	return value("signatureProductionCity"), value("signatureProductionProvince"),
		value("signatureProductionPostalCode"), value("signatureProductionCountry")
}

// DeclaredPlace is that place as one line.
func DeclaredPlace(properties map[string]string) string {
	city, province, postalCode, country := ProductionPlace(properties)
	var parts []string
	for _, part := range []string{city, province, postalCode, country} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ", ")
}
