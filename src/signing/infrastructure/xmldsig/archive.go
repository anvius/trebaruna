package xmldsig

import (
	"bytes"
	"fmt"

	"github.com/beevik/etree"
)

// ArchiveTimeStampInput is what a XAdES archive timestamp covers (ETSI EN
// 319 132-1, 5.5.2): every SignedInfo reference processed as XML-Signature
// processes it, then SignedInfo, SignatureValue and KeyInfo, then the
// unsigned signature properties in document order up to the archive
// timestamp itself (stop; nil takes them all, as the signer does before
// adding it), then the ds:Object elements that hold no
// QualifyingProperties, each canonicalised with algorithm. The signer
// timestamps it; the verifier recomputes it to check the token's imprint.
func ArchiveTimeStampInput(document *etree.Document, signature *etree.Element, resolve Resolver, algorithm string, stop *etree.Element) ([]byte, error) {
	var input bytes.Buffer
	signedInfo := child(signature, "SignedInfo")
	if signedInfo == nil {
		return nil, fmt.Errorf("the signature has no SignedInfo")
	}
	for _, reference := range children(signedInfo, "Reference") {
		processed, err := ReferenceData(document, signature, reference, resolve)
		if err != nil {
			return nil, fmt.Errorf("archive timestamp: reference %q: %w", reference.SelectAttrValue("URI", ""), err)
		}
		input.Write(processed)
	}
	write := func(element *etree.Element) error {
		canonical, err := Canonicalize(element, algorithm, "")
		if err != nil {
			return fmt.Errorf("canonicalise for the archive timestamp: %w", err)
		}
		input.Write(canonical)
		return nil
	}
	for _, name := range []string{"SignedInfo", "SignatureValue", "KeyInfo"} {
		if element := child(signature, name); element != nil {
			if err := write(element); err != nil {
				return nil, err
			}
		}
	}
	if unsigned := descendant(signature, "UnsignedSignatureProperties"); unsigned != nil {
		for _, property := range unsigned.ChildElements() {
			if property == stop {
				break
			}
			if err := write(property); err != nil {
				return nil, err
			}
		}
	}
	for _, object := range children(signature, "Object") {
		if descendant(object, "QualifyingProperties") != nil {
			continue
		}
		if err := write(object); err != nil {
			return nil, err
		}
	}
	return input.Bytes(), nil
}

// descendant finds the first element with a tag under an element, itself
// included.
func descendant(element *etree.Element, tag string) *etree.Element {
	var found *etree.Element
	walkElements(element, func(candidate *etree.Element) {
		if found == nil && candidate.Tag == tag {
			found = candidate
		}
	})
	return found
}
