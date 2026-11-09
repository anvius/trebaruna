package infrastructure

import (
	"encoding/asn1"
	"fmt"
	"os"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/verify"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

// pdfEnvelope is the CMS envelope of a PDF signature field (its /V
// /Contents), which the PDF verifier does not hand back, with what it signs.
type pdfEnvelope struct {
	tree signatureTree
	der  []byte
	// byteRange is the /ByteRange: offset and length pairs of the file.
	byteRange []int64
	// name is the signature's /Name, as the PDF verifier reports it.
	name string
}

// signedBytes reads the parts of the file the signature covers.
func (e pdfEnvelope) signedBytes(path string) ([]byte, error) {
	if len(e.byteRange) == 0 || len(e.byteRange)%2 != 0 {
		return nil, fmt.Errorf("the signature has no usable /ByteRange")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var signed []byte
	for index := 0; index < len(e.byteRange); index += 2 {
		offset, length := e.byteRange[index], e.byteRange[index+1]
		if offset < 0 || length < 0 || length > maxSignedRange-int64(len(signed)) {
			return nil, fmt.Errorf("the /ByteRange is out of bounds")
		}
		part := make([]byte, length)
		if _, err := file.ReadAt(part, offset); err != nil {
			return nil, fmt.Errorf("read the /ByteRange: %w", err)
		}
		signed = append(signed, part...)
	}
	return signed, nil
}

// maxSignedRange bounds what a /ByteRange makes this read into memory.
const maxSignedRange = 1 << 30

// signatureEnvelopes reads the envelope of every signature field of a PDF.
func signatureEnvelopes(path string) []pdfEnvelope {
	reader, err := pdf.Open(path)
	if err != nil {
		return nil
	}
	defer reader.Close()
	var envelopes []pdfEnvelope
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
							byteRange := value.Key("ByteRange")
							found := pdfEnvelope{tree: tree, der: envelope.FullBytes, name: value.Key("Name").Text()}
							for index := 0; index < byteRange.Len(); index++ {
								found.byteRange = append(found.byteRange, byteRange.Index(index).Int64())
							}
							envelopes = append(envelopes, found)
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
// signer answers to that certificate, and reads what the signature
// declares: the envelope's policy, the dictionary's /Location.
func bindPDFCertificate(envelopes []pdfEnvelope, signer *verify.Signer, report *domain.SignerReport) {
	report.Declared.Place = signer.Location
	if len(signer.Certificates) == 0 || signer.Certificates[0].Certificate == nil {
		return
	}
	leaf := signer.Certificates[0].Certificate
	for _, envelope := range envelopes {
		for _, info := range envelope.tree.signers {
			for _, candidate := range envelope.tree.certificatesFor(info.SID) {
				if candidate.Equal(leaf) {
					describeESSCertificate(essCertificateDigests(info.SignedAttrs), leaf, report)
					report.Declared = pdfDeclarations(info.SignedAttrs, signer.Location)
					return
				}
			}
		}
	}
}
