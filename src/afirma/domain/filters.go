package domain

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CertificateFilter is the page's choice of acceptable certificates (A.7):
// alternatives (filters.1, filters.2, …), any of which may match, each a list
// of conditions that must all hold.
type CertificateFilter struct {
	alternatives [][]condition
	expressions  []string
	// Unsupported lists conditions trebaruna cannot evaluate; an alternative
	// holding one matches nothing, so no certificate the page did not mean is
	// ever offered.
	Unsupported []string
	// pairs marks ssl: and qualified:, which look at the store's other
	// certificates.
	pairs bool
}

// condition is one test on a certificate.
type condition func(certificate *x509.Certificate, in scope) bool

// scope is what a condition sees besides the certificate: the time, and the
// other certificates of its store, which ssl: and qualified: pair it with.
type scope struct {
	now        time.Time
	neighbours []*x509.Certificate
}

// FilterFrom reads filter, filters and filters.N from the properties. With
// no filter at all, expired certificates are hidden.
func FilterFrom(properties map[string]string) CertificateFilter {
	var expressions []string
	for _, key := range []string{"filter", "filters"} {
		if value := strings.TrimSpace(properties[key]); value != "" {
			expressions = append(expressions, value)
		}
	}
	for index := 1; ; index++ {
		value, present := properties["filters."+strconv.Itoa(index)]
		if !present {
			break
		}
		if strings.TrimSpace(value) != "" {
			expressions = append(expressions, strings.TrimSpace(value))
		}
	}
	filter := CertificateFilter{expressions: expressions}
	if len(expressions) == 0 {
		filter.alternatives = [][]condition{{notExpired}}
		return filter
	}
	for _, expression := range expressions {
		var conditions []condition
		for _, part := range strings.Split(expression, ";") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			parsed, ok := parseCondition(strings.TrimSpace(part))
			filter.pairs = filter.pairs || ok && pairing(part)
			if !ok {
				filter.Unsupported = append(filter.Unsupported, strings.TrimSpace(part))
				parsed = func(*x509.Certificate, scope) bool { return false }
			}
			conditions = append(conditions, parsed)
		}
		filter.alternatives = append(filter.alternatives, conditions)
	}
	return filter
}

// Accepts reports whether the certificate may be offered. Its neighbours
// are the other certificates of its store, such as a card's other identity;
// only ssl: and qualified: look at them.
func (f CertificateFilter) Accepts(certificate *x509.Certificate, neighbours []*x509.Certificate, now time.Time) bool {
	in := scope{now: now, neighbours: neighbours}
	for _, conditions := range f.alternatives {
		matched := true
		for _, test := range conditions {
			if !test(certificate, in) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// Expressions are the page's filters as written, to show the person.
func (f CertificateFilter) Expressions() []string { return f.expressions }

// Pairs reports a filter that needs the store's other certificates.
func (f CertificateFilter) Pairs() bool { return f.pairs }

func notExpired(certificate *x509.Certificate, in scope) bool {
	return !in.now.After(certificate.NotAfter) && !in.now.Before(certificate.NotBefore)
}

// parseCondition reads one condition; prefixes are case-insensitive.
func parseCondition(text string) (condition, bool) {
	lower := strings.ToLower(text)
	after := func(prefix string) string { return text[len(prefix):] }
	switch {
	case lower == "nonexpired:" || lower == "nonexpired:true":
		return notExpired, true
	case lower == "nonexpired:false":
		return func(*x509.Certificate, scope) bool { return true }, true
	case strings.HasPrefix(lower, "subject.rfc2254:"):
		return ldapCondition(after("subject.rfc2254:"), func(c *x509.Certificate) []byte { return c.RawSubject })
	case strings.HasPrefix(lower, "issuer.rfc2254.recurse:"):
		return ldapCondition(after("issuer.rfc2254.recurse:"), func(c *x509.Certificate) []byte { return c.RawIssuer })
	case strings.HasPrefix(lower, "issuer.rfc2254:"):
		return ldapCondition(after("issuer.rfc2254:"), func(c *x509.Certificate) []byte { return c.RawIssuer })
	case strings.HasPrefix(lower, "subject.contains:"):
		needle := strings.ToLower(after("subject.contains:"))
		return func(c *x509.Certificate, _ scope) bool {
			return strings.Contains(strings.ToLower(c.Subject.String()), needle)
		}, true
	case strings.HasPrefix(lower, "issuer.contains:"):
		needle := strings.ToLower(after("issuer.contains:"))
		return func(c *x509.Certificate, _ scope) bool {
			return strings.Contains(strings.ToLower(c.Issuer.String()), needle)
		}, true
	case strings.HasPrefix(lower, "keyusage."):
		return keyUsageCondition(lower[len("keyusage."):])
	case strings.HasPrefix(lower, "thumbprint:"):
		return thumbprintCondition(after("thumbprint:"))
	case strings.HasPrefix(lower, "encodedcert:"):
		encoded, err := DecodeBase64(after("encodedcert:"))
		if err != nil {
			return nil, false
		}
		return func(c *x509.Certificate, _ scope) bool { return bytes.Equal(c.Raw, encoded) }, true
	case strings.HasPrefix(lower, "policyid:"):
		var wanted []string
		for _, oid := range strings.Split(after("policyid:"), ",") {
			wanted = append(wanted, strings.TrimSpace(oid))
		}
		return func(c *x509.Certificate, _ scope) bool {
			declared := make([]string, 0, len(c.Policies)+len(c.PolicyIdentifiers))
			for _, policy := range c.Policies {
				declared = append(declared, policy.String())
			}
			for _, policy := range c.PolicyIdentifiers {
				declared = append(declared, policy.String())
			}
			for _, policy := range declared {
				for _, oid := range wanted {
					if policy == oid {
						return true
					}
				}
			}
			return false
		}, true
	case lower == "signingcert:" || lower == "signingcert":
		return func(c *x509.Certificate, _ scope) bool { return c.KeyUsage&x509.KeyUsageContentCommitment != 0 }, true
	case lower == "authcert:" || lower == "authcert":
		return func(c *x509.Certificate, _ scope) bool {
			return c.KeyUsage&x509.KeyUsageDigitalSignature != 0 && c.KeyUsage&x509.KeyUsageContentCommitment == 0
		}, true
	case lower == "dnie:" || lower == "dnie":
		return func(c *x509.Certificate, _ scope) bool {
			return strings.Contains(strings.ToUpper(c.Issuer.String()), "DIRECCION GENERAL DE LA POLICIA") &&
				c.KeyUsage&x509.KeyUsageContentCommitment != 0
		}, true
	case strings.HasPrefix(lower, "pseudonym:"):
		value := after("pseudonym:")
		return func(c *x509.Certificate, _ scope) bool {
			for _, attribute := range c.Subject.Names {
				if attribute.Type.String() == "2.5.4.65" {
					return value == "" || strings.EqualFold(fmt.Sprint(attribute.Value), value)
				}
			}
			return false
		}, true
	case lower == "sscd:" || lower == "sscd":
		return func(c *x509.Certificate, _ scope) bool { return hasQcSSCD(c) }, true
	case strings.HasPrefix(lower, "ssl:"):
		return sslCondition(after("ssl:"))
	case strings.HasPrefix(lower, "qualified:"):
		return qualifiedCondition(after("qualified:"))
	case lower == "disableopeningexternalstores":
		return func(*x509.Certificate, scope) bool { return true }, true
	}
	return nil, false
}

// keyUsageCondition reads keyusage.<bit>:true|false|null.
func keyUsageCondition(text string) (condition, bool) {
	name, value, found := strings.Cut(text, ":")
	if !found {
		return nil, false
	}
	bits := map[string]x509.KeyUsage{
		"digitalsignature": x509.KeyUsageDigitalSignature, "nonrepudiation": x509.KeyUsageContentCommitment,
		"keyencipherment": x509.KeyUsageKeyEncipherment, "dataencipherment": x509.KeyUsageDataEncipherment,
		"keyagreement": x509.KeyUsageKeyAgreement, "keycertsign": x509.KeyUsageCertSign, "crlsign": x509.KeyUsageCRLSign,
		"encipheronly": x509.KeyUsageEncipherOnly, "decipheronly": x509.KeyUsageDecipherOnly,
	}
	bit, known := bits[name]
	if !known {
		return nil, false
	}
	switch value {
	case "null":
		return func(*x509.Certificate, scope) bool { return true }, true
	case "true", "false":
		wanted := value == "true"
		return func(c *x509.Certificate, _ scope) bool { return (c.KeyUsage&bit != 0) == wanted }, true
	}
	return nil, false
}

// thumbprintCondition reads thumbprint:<algorithm>:<hex>.
func thumbprintCondition(text string) (condition, bool) {
	algorithm, digest, found := strings.Cut(text, ":")
	if !found {
		return nil, false
	}
	wanted, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(digest), ":", ""))
	if err != nil {
		return nil, false
	}
	hashes := map[string]func([]byte) []byte{
		"sha1":    func(b []byte) []byte { sum := sha1.Sum(b); return sum[:] },
		"sha-1":   func(b []byte) []byte { sum := sha1.Sum(b); return sum[:] },
		"sha256":  func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] },
		"sha-256": func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] },
		"sha512":  func(b []byte) []byte { sum := sha512.Sum512(b); return sum[:] },
		"sha-512": func(b []byte) []byte { sum := sha512.Sum512(b); return sum[:] },
	}
	hash, known := hashes[strings.ToLower(algorithm)]
	if !known {
		return nil, false
	}
	return func(c *x509.Certificate, _ scope) bool { return bytes.Equal(hash(c.Raw), wanted) }, true
}

// hasQcSSCD reports the QcStatement saying the key is in a qualified device.
func hasQcSSCD(certificate *x509.Certificate) bool {
	qcStatements := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	sscd := asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(qcStatements) {
			continue
		}
		var statements []asn1.RawValue
		if _, err := asn1.Unmarshal(extension.Value, &statements); err != nil {
			return false
		}
		for _, statement := range statements {
			var id asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(statement.Bytes, &id); err == nil && id.Equal(sscd) {
				return true
			}
		}
	}
	return false
}
