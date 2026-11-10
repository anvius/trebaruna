package pdffield

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"

	"github.com/digitorus/pdf"
)

// SubFilters trebaruna writes: a CMS envelope over the byte range, in the
// PAdES form or the older Adobe one.
const (
	SubFilterCAdES = "ETSI.CAdES.detached"
	SubFilterPKCS7 = "adbe.pkcs7.detached"
)

// SeedValues are what a signature field asks of the signature made in it
// (its /SV, ISO 32000-1 12.7.4.5, table 234): each constraint is advice
// unless its bit in the flags makes it required.
type SeedValues struct {
	Filter                   string
	FilterRequired           bool
	SubFilters               []string
	SubFilterRequired        bool
	DigestMethods            []string
	DigestMethodRequired     bool
	Reasons                  []string
	ReasonsRequired          bool
	LegalAttestationRequired bool
	AddRevInfoRequired       bool
	// Certification is the DocMDP permissions of the certification
	// signature the field asks for, 0 for an approval one.
	Certification     int
	TimeStampURL      string
	TimeStampRequired bool
	Certificate       CertificateSeed
}

// CertificateSeed is what the field asks of the signer's certificate
// (table 235); only the constraints its flags require are checked.
type CertificateSeed struct {
	Subjects          [][]byte
	SubjectRequired   bool
	Issuers           [][]byte
	IssuerRequired    bool
	Policies          []string
	PolicyRequired    bool
	SubjectDNs        []map[string]string
	SubjectDNRequired bool
	KeyUsages         []string
	KeyUsageRequired  bool
}

// Seeds reads the field's seed values; zero when it has none.
func (f Field) Seeds() SeedValues {
	seed := f.field.Key("SV")
	flags := seed.Key("Ff").Int64()
	certificate := seed.Key("Cert")
	certificateFlags := certificate.Key("Ff").Int64()
	values := SeedValues{
		Filter: seed.Key("Filter").Name(), FilterRequired: flags&1 != 0,
		SubFilters: names(seed.Key("SubFilter")), SubFilterRequired: flags&2 != 0,
		Reasons: texts(seed.Key("Reasons")), ReasonsRequired: flags&8 != 0,
		LegalAttestationRequired: flags&16 != 0 && seed.Key("LegalAttestation").Len() > 0,
		AddRevInfoRequired:       flags&32 != 0 && seed.Key("AddRevInfo").Bool(),
		DigestMethods:            names(seed.Key("DigestMethod")), DigestMethodRequired: flags&64 != 0,
		Certification: int(seed.Key("MDP").Key("P").Int64()),
		TimeStampURL:  seed.Key("TimeStamp").Key("URL").Text(), TimeStampRequired: seed.Key("TimeStamp").Key("Ff").Int64()&1 != 0,
		Certificate: CertificateSeed{
			Subjects: rawStrings(certificate.Key("Subject")), SubjectRequired: certificateFlags&1 != 0,
			Issuers: rawStrings(certificate.Key("Issuer")), IssuerRequired: certificateFlags&2 != 0,
			Policies: texts(certificate.Key("OID")), PolicyRequired: certificateFlags&4 != 0,
			KeyUsages: texts(certificate.Key("KeyUsage")), KeyUsageRequired: certificateFlags&32 != 0,
			SubjectDNRequired: certificateFlags&8 != 0,
		},
	}
	distinguished := certificate.Key("SubjectDN")
	for index := 0; index < distinguished.Len(); index++ {
		entry := distinguished.Index(index)
		attributes := map[string]string{}
		for _, key := range entry.Keys() {
			attributes[key] = entry.Key(key).Text()
		}
		values.Certificate.SubjectDNs = append(values.Certificate.SubjectDNs, attributes)
	}
	return values
}

// SubFilter is the encoding to sign with: the first of the field's that
// trebaruna writes, or ETSI.CAdES.detached when it names none of them,
// which a field that requires its own refuses.
func (v SeedValues) SubFilter() (string, error) {
	for _, asked := range v.SubFilters {
		if asked == SubFilterCAdES || asked == SubFilterPKCS7 {
			return asked, nil
		}
	}
	if v.SubFilterRequired && len(v.SubFilters) > 0 {
		return "", fmt.Errorf("%w: the field requires a signature encoded as %s, which trebaruna does not write",
			ErrUnsupported, strings.Join(v.SubFilters, " or "))
	}
	return SubFilterCAdES, nil
}

// Admit checks what the field requires against the signature about to be
// made: the signer's chain (its certificate first), the reason given, and
// the timestamp authority used ("" for none). A requirement trebaruna
// cannot meet refuses the signature, saying what the form asks.
func (v SeedValues) Admit(chain []*x509.Certificate, reason, timestampURL string) error {
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: the field requires "+format, append([]any{ErrUnsupported}, arguments...)...)
	}
	switch {
	case v.FilterRequired && v.Filter != "" && v.Filter != "Adobe.PPKLite":
		return refuse("the signature handler %s; trebaruna's is Adobe.PPKLite", v.Filter)
	case v.DigestMethodRequired && len(v.DigestMethods) > 0 && !slices.ContainsFunc(v.DigestMethods, func(method string) bool {
		return strings.EqualFold(method, "SHA256")
	}):
		return refuse("a digest by %s; trebaruna signs with SHA256", strings.Join(v.DigestMethods, " or "))
	case v.Certification > 0:
		return refuse("a certification signature (DocMDP %d), which trebaruna does not make", v.Certification)
	case v.LegalAttestationRequired:
		return refuse("legal attestations, which trebaruna does not write")
	case v.AddRevInfoRequired:
		return refuse("revocation information inside the signature (adbe-revocationInfoArchival), which trebaruna does not write")
	case v.TimeStampRequired && strings.TrimSpace(timestampURL) != strings.TrimSpace(v.TimeStampURL):
		return refuse("a timestamp from %s: sign at level T with --tsa %s", v.TimeStampURL, v.TimeStampURL)
	}
	if v.ReasonsRequired && len(v.Reasons) > 0 {
		if slices.Equal(v.Reasons, []string{"."}) && reason != "" {
			return refuse("no reason")
		}
		if !slices.Equal(v.Reasons, []string{"."}) && !slices.Contains(v.Reasons, reason) {
			return refuse("one of these reasons, given with --reason: %s", strings.Join(v.Reasons, "; "))
		}
	}
	if len(chain) == 0 {
		return nil
	}
	return v.Certificate.admit(chain)
}

// admit checks the signer's certificate against the required constraints.
func (c CertificateSeed) admit(chain []*x509.Certificate) error {
	signer := chain[0]
	refuse := func(what string) error {
		return fmt.Errorf("%w: the field requires a certificate %s, and the signer's is not", ErrUnsupported, what)
	}
	if c.SubjectRequired && len(c.Subjects) > 0 && !slices.ContainsFunc(c.Subjects, func(raw []byte) bool {
		return string(raw) == string(signer.Raw)
	}) {
		return refuse("among the ones it names")
	}
	if c.IssuerRequired && len(c.Issuers) > 0 && !issuedByOneOf(chain, c.Issuers) {
		return refuse("issued by one of the authorities it names")
	}
	if c.PolicyRequired && len(c.Policies) > 0 && !slices.ContainsFunc(signer.PolicyIdentifiers, func(policy asn1.ObjectIdentifier) bool {
		return slices.Contains(c.Policies, policy.String())
	}) {
		return refuse("under one of the policies " + strings.Join(c.Policies, ", "))
	}
	if c.SubjectDNRequired && len(c.SubjectDNs) > 0 && !slices.ContainsFunc(c.SubjectDNs, func(attributes map[string]string) bool {
		return subjectHas(signer, attributes)
	}) {
		return refuse("whose holder's name matches one it describes")
	}
	if c.KeyUsageRequired && len(c.KeyUsages) > 0 && !slices.ContainsFunc(c.KeyUsages, func(pattern string) bool {
		return keyUsageMatches(signer.KeyUsage, pattern)
	}) {
		return refuse("with the key usage " + strings.Join(c.KeyUsages, " or "))
	}
	return nil
}

// issuedByOneOf reports a chain one of whose certificates is, or was
// issued by, one of the authorities given (directly or through the chain).
func issuedByOneOf(chain []*x509.Certificate, authorities [][]byte) bool {
	for _, raw := range authorities {
		authority, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		for _, certificate := range chain {
			if certificate.Equal(authority) || certificate.CheckSignatureFrom(authority) == nil {
				return true
			}
		}
	}
	return false
}

// distinguishedNames maps a SubjectDN key to its attribute type.
var distinguishedNames = map[string]string{
	"CN": "2.5.4.3", "SN": "2.5.4.4", "SERIALNUMBER": "2.5.4.5", "C": "2.5.4.6", "L": "2.5.4.7", "ST": "2.5.4.8",
	"O": "2.5.4.10", "OU": "2.5.4.11", "T": "2.5.4.12", "GN": "2.5.4.42", "E": "1.2.840.113549.1.9.1",
}

// subjectHas reports a holder's name with every attribute described; a key
// trebaruna does not know matches nothing.
func subjectHas(certificate *x509.Certificate, attributes map[string]string) bool {
	for key, value := range attributes {
		kind, known := distinguishedNames[strings.ToUpper(key)]
		if !known || !slices.ContainsFunc(certificate.Subject.Names, func(name pkix.AttributeTypeAndValue) bool {
			return name.Type.String() == kind && fmt.Sprint(name.Value) == value
		}) {
			return false
		}
	}
	return true
}

// keyUsageMatches reads a key usage pattern: one character per bit, from
// digitalSignature to decipherOnly, 1 set, 0 clear, X either.
func keyUsageMatches(usage x509.KeyUsage, pattern string) bool {
	for bit, character := range pattern {
		set := usage&(1<<bit) != 0
		if (character == '1' && !set) || (character == '0' && set) {
			return false
		}
	}
	return true
}

func names(array pdf.Value) []string {
	var found []string
	for index := 0; index < array.Len(); index++ {
		found = append(found, array.Index(index).Name())
	}
	return found
}

func texts(array pdf.Value) []string {
	var found []string
	for index := 0; index < array.Len(); index++ {
		found = append(found, array.Index(index).Text())
	}
	return found
}

func rawStrings(array pdf.Value) [][]byte {
	var found [][]byte
	for index := 0; index < array.Len(); index++ {
		found = append(found, []byte(array.Index(index).RawString()))
	}
	return found
}
