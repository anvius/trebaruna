// Package infrastructure reads qualified-certificate statements from X.509.
//
// The statements live in the qcStatements extension (OID 1.3.6.1.5.5.7.1.3),
// whose value is a SEQUENCE of QCStatement ::= SEQUENCE { statementId OID,
// statementInfo ANY DEFINED BY statementId OPTIONAL }.
//
// Go's x509 package exposes extensions as raw DER, so this is parsed by hand.
// A library would be one more dependency for 40 lines of ASN.1, and the OIDs are
// fixed by RFC 3739 / ETSI EN 319 412-5.
package infrastructure

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Object identifiers of the QC statements this tool can act on.
var (
	// oidQCStatements is the extension that carries every statement below.
	oidQCStatements = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

	// oidQcCompliance (0.4.0.1862.1.1) states the certificate is a qualified
	// certificate issued in accordance with the Regulation.
	oidQcCompliance = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}

	// oidQcSSCD (0.4.0.1862.1.4) states the private key is held in an SSCD.
	// ETSI EN 319 412-5 keeps the SSCD name; eIDAS renamed the device to QSCD,
	// and the certificate statement still says SSCD.
	oidQcSSCD = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}

	// oidQcType (0.4.0.1862.1.6) lists the certificate types. Its value is a
	// SEQUENCE of OIDs; 0.4.0.1862.1.6.1 is "electronic signature".
	oidQcType = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}

	// oidQcTypeEsign is the QcType entry for an electronic-signature certificate.
	oidQcTypeEsign = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}
)

// qcStatement mirrors the ASN.1 SEQUENCE.
type qcStatement struct {
	ID   asn1.ObjectIdentifier
	Info asn1.RawValue `asn1:"optional"`
}

// QualifiedStatements is what the certificate itself claims.
//
// Claims, not proofs: a certificate can say it is qualified and be issued by
// nobody in particular. The trust list supplies the other half.
type QualifiedStatements struct {
	// Compliant reports the QcCompliance statement.
	Compliant bool
	// SSCD reports the QcSSCD statement: key held in a secure device.
	SSCD bool
	// TypeDeclared reports that a QcType statement was published at all.
	//
	// This distinction is load-bearing. QcType is optional in ETSI EN 319 412-5:
	// a certificate that omits it says nothing about what it is for. Treating
	// silence as "seal" would refuse to qualify perfectly valid European
	// signature certificates, a false negative measured on real documents
	// (UANATACA, C=ES, qcStatements = compliance + retention + PDS, no QcType).
	TypeDeclared bool
	// SignatureCertificate reports a QcType entry for electronic signatures.
	SignatureCertificate bool
	// Recognised reports that the extension was present and parseable at all.
	Recognised bool
}

// ReadQualifiedStatements extracts the QC statements from a certificate.
//
// A certificate without the extension, or with a statement this code does not
// know, simply reports false: absence of evidence must not become evidence of
// qualification.
func ReadQualifiedStatements(certificate *x509.Certificate) QualifiedStatements {
	var result QualifiedStatements
	if certificate == nil {
		return result
	}

	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidQCStatements) {
			continue
		}

		var statements []qcStatement
		rest, err := asn1.Unmarshal(extension.Value, &statements)
		if err != nil || len(rest) > 0 {
			// A malformed extension is reported as unrecognised rather than
			// guessed at: half-parsed qualification is worse than none.
			return QualifiedStatements{}
		}

		result.Recognised = true
		for _, statement := range statements {
			switch {
			case statement.ID.Equal(oidQcCompliance):
				result.Compliant = true
			case statement.ID.Equal(oidQcSSCD):
				result.SSCD = true
			case statement.ID.Equal(oidQcType):
				result.TypeDeclared = true
				result.SignatureCertificate = hasSignatureType(statement.Info)
			}
		}
		return result
	}

	return result
}

// hasSignatureType decodes the QcType SEQUENCE of OIDs.
func hasSignatureType(info asn1.RawValue) bool {
	if len(info.FullBytes) == 0 {
		return false
	}
	var types []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info.FullBytes, &types); err != nil {
		return false
	}
	for _, entry := range types {
		if entry.Equal(oidQcTypeEsign) {
			return true
		}
	}
	return false
}

// DescribeQualifiedStatements renders the claims for a log line.
func DescribeQualifiedStatements(statements QualifiedStatements) string {
	if !statements.Recognised {
		return "no qcStatements extension"
	}
	return fmt.Sprintf("compliant=%t sscd=%t type-declared=%t signature-type=%t",
		statements.Compliant, statements.SSCD, statements.TypeDeclared, statements.SignatureCertificate)
}
