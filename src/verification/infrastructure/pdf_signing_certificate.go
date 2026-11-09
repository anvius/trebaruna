package infrastructure

import (
	"encoding/asn1"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/verify"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// signatureEnvelopes reads the CMS envelope of every signature field of a
// PDF (its /V /Contents), which the PDF verifier does not hand back.
func signatureEnvelopes(path string) []signatureTree {
	reader, err := pdf.Open(path)
	if err != nil {
		return nil
	}
	defer reader.Close()
	var envelopes []signatureTree
	var visit func(fields pdf.Value, depth int)
	visit = func(fields pdf.Value, depth int) {
		if depth > 16 {
			return
		}
		for index := 0; index < fields.Len(); index++ {
			field := fields.Index(index)
			if value := field.Key("V"); value.Kind() == pdf.Dict {
				if contents := []byte(value.Key("Contents").RawString()); len(contents) > 0 {
					// /Contents is padded with zeros after the DER.
					var envelope asn1.RawValue
					if _, err := asn1.Unmarshal(contents, &envelope); err == nil {
						if tree, err := parseSignatureTree(envelope.FullBytes, nil); err == nil {
							envelopes = append(envelopes, tree)
						}
					}
				}
			}
			visit(field.Key("Kids"), depth+1)
		}
	}
	visit(reader.Trailer().Key("Root").Key("AcroForm").Key("Fields"), 0)
	return envelopes
}

// bindPDFCertificate checks a PDF signature's signing-certificate attribute
// against the certificate the verifier resolved, in the envelope whose
// signer answers to that certificate.
func bindPDFCertificate(envelopes []signatureTree, signer *verify.Signer, report *domain.SignerReport) {
	if len(signer.Certificates) == 0 || signer.Certificates[0].Certificate == nil {
		return
	}
	leaf := signer.Certificates[0].Certificate
	for _, envelope := range envelopes {
		for _, info := range envelope.signers {
			for _, candidate := range envelope.certificatesFor(info.SID) {
				if candidate.Equal(leaf) {
					describeESSCertificate(essCertificateDigests(info.SignedAttrs), leaf, report)
					return
				}
			}
		}
	}
}
