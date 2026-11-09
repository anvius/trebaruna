package domain

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

// ldapAttributes maps the attribute names filters use onto their OIDs.
var ldapAttributes = map[string]string{
	"cn": "2.5.4.3", "commonname": "2.5.4.3", "sn": "2.5.4.4", "surname": "2.5.4.4",
	"serialnumber": "2.5.4.5", "c": "2.5.4.6", "l": "2.5.4.7", "st": "2.5.4.8", "s": "2.5.4.8",
	"street": "2.5.4.9", "o": "2.5.4.10", "ou": "2.5.4.11", "t": "2.5.4.12", "title": "2.5.4.12",
	"description": "2.5.4.13", "givenname": "2.5.4.42", "g": "2.5.4.42", "pseudonym": "2.5.4.65",
	"organizationidentifier": "2.5.4.97", "e": "1.2.840.113549.1.9.1", "emailaddress": "1.2.840.113549.1.9.1",
	"uid": "0.9.2342.19200300.100.1.1", "dc": "0.9.2342.19200300.100.1.25",
}

// ldapCondition compiles an RFC 2254 filter over a distinguished name.
func ldapCondition(filter string, name func(*x509.Certificate) []byte) (condition, bool) {
	matcher, rest, ok := parseLDAP(strings.TrimSpace(filter))
	if !ok || strings.TrimSpace(rest) != "" {
		return nil, false
	}
	return func(certificate *x509.Certificate, _ scope) bool {
		var sequence pkix.RDNSequence
		if _, err := asn1.Unmarshal(name(certificate), &sequence); err != nil {
			return false
		}
		attributes := map[string][]string{}
		for _, set := range sequence {
			for _, attribute := range set {
				attributes[attribute.Type.String()] = append(attributes[attribute.Type.String()], fmt.Sprint(attribute.Value))
			}
		}
		return matcher(attributes)
	}, true
}

// ldapMatcher evaluates a filter against attribute values by OID.
type ldapMatcher func(map[string][]string) bool

// parseLDAP reads "(&…)", "(|…)", "(!…)" or "(attr=value)" with "*" wildcards.
func parseLDAP(text string) (ldapMatcher, string, bool) {
	if !strings.HasPrefix(text, "(") || len(text) < 3 {
		return nil, text, false
	}
	body := text[1:]
	switch body[0] {
	case '&', '|':
		operator := body[0]
		rest := strings.TrimSpace(body[1:])
		var parts []ldapMatcher
		for strings.HasPrefix(rest, "(") {
			part, remaining, ok := parseLDAP(rest)
			if !ok {
				return nil, text, false
			}
			parts = append(parts, part)
			rest = strings.TrimSpace(remaining)
		}
		if !strings.HasPrefix(rest, ")") || len(parts) == 0 {
			return nil, text, false
		}
		return func(attributes map[string][]string) bool {
			for _, part := range parts {
				if part(attributes) != (operator == '&') {
					return operator != '&'
				}
			}
			return operator == '&'
		}, rest[1:], true
	case '!':
		part, rest, ok := parseLDAP(strings.TrimSpace(body[1:]))
		rest = strings.TrimSpace(rest)
		if !ok || !strings.HasPrefix(rest, ")") {
			return nil, text, false
		}
		return func(attributes map[string][]string) bool { return !part(attributes) }, rest[1:], true
	}

	end := strings.Index(body, ")")
	if end < 0 {
		return nil, text, false
	}
	attribute, pattern, found := strings.Cut(body[:end], "=")
	if !found || attribute == "" {
		return nil, text, false
	}
	attribute = strings.ToLower(strings.TrimSpace(attribute))
	if attribute == "objectclass" {
		return func(map[string][]string) bool { return true }, body[end+1:], true
	}
	oid, known := ldapAttributes[attribute]
	if !known {
		if !strings.ContainsAny(attribute, "0123456789") || strings.Trim(attribute, "0123456789.") != "" {
			return nil, text, false
		}
		oid = attribute
	}
	return func(attributes map[string][]string) bool {
		for _, value := range attributes[oid] {
			if wildcardMatch(strings.ToLower(pattern), strings.ToLower(value)) {
				return true
			}
		}
		return false
	}, body[end+1:], true
}

// wildcardMatch matches "*" anywhere in the pattern.
func wildcardMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	for _, middle := range parts[1 : len(parts)-1] {
		at := strings.Index(value, middle)
		if at < 0 {
			return false
		}
		value = value[at+len(middle):]
	}
	return strings.HasSuffix(value, parts[len(parts)-1])
}
