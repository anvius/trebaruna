package infrastructure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/publickey"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/xmldsig"
)

// typeCountersignedSignature marks the reference of a counter-signature:
// it signs another signature's value (XAdES 1.3.2, 7.2.4).
const typeCountersignedSignature = "http://uri.etsi.org/01903#CountersignedSignature"

// countersignXades counter-signs the XAdES signatures of a signed XML
// document: the ones nobody counter-signed yet ("leaves"), or every one
// ("all"). Each counter-signature is a XAdES signature over the
// countersigned signature's SignatureValue, inside that signature's
// UnsignedSignatureProperties as xades:CounterSignature. A signature that
// held before must hold after, or nothing is written.
func (s *XadesSigner) countersignXades(ctx context.Context, request application.XadesRequest, keyPair KeyPair) ([]byte, error) {
	if request.Level.EmbedsRevocation() {
		return nil, fmt.Errorf("XAdES counter-signatures support levels B and T; %s is not available for them yet", request.Level)
	}
	tree, err := parseDocument(request.Content)
	if err != nil {
		return nil, err
	}
	holding := holdingSignatures(tree)
	targets := countersignTargets(tree, request.Countersign)
	if len(targets) == 0 {
		return nil, fmt.Errorf("the document carries no XAdES signature to counter-sign")
	}

	var added []string
	for _, target := range targets {
		qualifying := findQualifyingProperties(target)
		value := target.SelectElement("SignatureValue")
		if value == nil {
			return nil, fmt.Errorf("signature %q has no SignatureValue", target.SelectAttrValue("Id", ""))
		}
		valueID := value.SelectAttrValue("Id", "")
		if valueID == "" {
			// The counter-signature names the value by its Id. One given now
			// changes the value's canonical form, which the signature's own
			// timestamps sealed: it would lose them.
			if sealsItsValue(target) {
				return nil, fmt.Errorf("signature %q is timestamped over a value with no Id for a counter-signature to name; "+
					"giving it one would break that timestamp, so nothing was written", target.SelectAttrValue("Id", ""))
			}
			valueID = idBeside(target, "signature-value")
			value.CreateAttr("Id", valueID)
		}
		ids, err := newSignatureIDs()
		if err != nil {
			return nil, err
		}
		certificateDigest := sha256.Sum256(keyPair.Certificate.Raw)
		signedProperties := buildSignedProperties(ids,
			base64.StdEncoding.EncodeToString(certificateDigest[:]),
			time.Now().UTC().Format(time.RFC3339), "",
			policyProperties(request.Policy)+placeProperties(request.Place)+roleProperties(request.ClaimedRoles))
		signature := buildSignature(ids,
			buildCounterSignedInfo(ids, valueID, keyPair.Certificate.PublicKeyAlgorithm == x509.ECDSA),
			placeholderDigest, base64.StdEncoding.EncodeToString(keyPair.Certificate.Raw), signedProperties, "", false)
		fragment, err := parseFragment(`<xades:CounterSignature xmlns:xades="` + namespaceXades + `">` + signature + `</xades:CounterSignature>`)
		if err != nil {
			return nil, err
		}
		unsignedSignatureProperties(target, qualifying).AddChild(fragment)
		added = append(added, ids.signature())
	}

	// As for a new signature: measured on the tree as it will be read back.
	serialised, err := tree.WriteToBytes()
	if err != nil {
		return nil, err
	}
	if tree, err = parseDocument(serialised); err != nil {
		return nil, err
	}
	for _, id := range added {
		counter := findByID(tree.Root(), id)
		if counter == nil {
			return nil, fmt.Errorf("the counter-signature cannot be located")
		}
		if err := s.completeCounterSignature(ctx, tree, counter, request, keyPair); err != nil {
			return nil, err
		}
	}
	after := holdingSignatures(tree)
	for value := range holding {
		if !after[value] {
			return nil, fmt.Errorf("counter-signing would break a signature of the document; nothing was written")
		}
	}

	final, err := tree.WriteToBytes()
	if err != nil {
		return nil, err
	}
	if !hasXMLDeclaration(final) {
		final = append([]byte(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"), final...)
	}
	return final, nil
}

// completeCounterSignature digests the counter-signature's references,
// signs its SignedInfo and, for level T, timestamps it.
func (s *XadesSigner) completeCounterSignature(ctx context.Context, tree *etree.Document, counter *etree.Element,
	request application.XadesRequest, keyPair KeyPair) error {
	signedInfo := counter.SelectElement("SignedInfo")
	for _, reference := range signedInfo.SelectElements("Reference") {
		data, err := xmldsig.ReferenceData(tree, counter, reference, nil)
		if err != nil {
			return fmt.Errorf("digest %s: %w", reference.SelectAttrValue("URI", ""), err)
		}
		digest := sha256.Sum256(data)
		setDigestValue(reference, digest[:])
	}
	signedInfoDigest, err := canonicalDigest(signedInfo)
	if err != nil {
		return err
	}
	value, err := keyPair.Signer.Sign(rand.Reader, signedInfoDigest, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("sign the counter-signature: %w", err)
	}
	if key, ok := keyPair.Certificate.PublicKey.(*ecdsa.PublicKey); ok {
		if value, err = xmldsigECDSA(key, value); err != nil {
			return err
		}
	}
	counter.SelectElement("SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))
	if request.Level.NeedsTimestamp() {
		return s.attachSignatureTimeStamp(ctx, counter, request)
	}
	return nil
}

// buildCounterSignedInfo references the countersigned SignatureValue and
// the counter-signature's own signed properties.
func buildCounterSignedInfo(ids signatureIDs, valueID string, ecdsa bool) string {
	method := algorithmRSASHA256
	if ecdsa {
		method = algorithmECDSASHA256
	}
	reference := func(attributes string) string {
		return `<ds:Reference ` + attributes + `><ds:Transforms><ds:Transform Algorithm="` + algorithmC14N + `"/></ds:Transforms>` +
			`<ds:DigestMethod Algorithm="` + algorithmSHA256 + `"/><ds:DigestValue>` + placeholderDigest + `</ds:DigestValue></ds:Reference>`
	}
	return `<ds:SignedInfo xmlns:ds="` + namespaceDS + `">` +
		`<ds:CanonicalizationMethod Algorithm="` + algorithmC14N + `"/>` +
		`<ds:SignatureMethod Algorithm="` + method + `"/>` +
		reference(`Id="`+ids.reference()+`" Type="`+typeCountersignedSignature+`" URI="#`+xmlEscape(valueID)+`"`) +
		reference(`Type="`+typeSignedProperties+`" URI="#`+ids.signedProperties()+`"`) +
		`</ds:SignedInfo>`
}

// sealsItsValue reports a signature whose own unsigned properties hold a
// timestamp over its value: a SignatureTimeStamp or an archive timestamp.
func sealsItsValue(signature *etree.Element) bool {
	qualifying := findQualifyingProperties(signature)
	if qualifying == nil {
		return false
	}
	for _, unsigned := range qualifying.FindElements("./UnsignedProperties/UnsignedSignatureProperties") {
		for _, property := range unsigned.ChildElements() {
			if property.Tag == "SignatureTimeStamp" || property.Tag == "ArchiveTimeStamp" {
				return true
			}
		}
	}
	return false
}

// countersignTargets are the XAdES signatures to counter-sign: those with
// no counter-signature of their own (leaves), or all of them. A plain
// XMLDSig signature has no properties to hold one.
func countersignTargets(tree *etree.Document, scope string) []*etree.Element {
	var targets []*etree.Element
	for _, signature := range xmldsig.Signatures(tree) {
		if findQualifyingProperties(signature) == nil {
			continue
		}
		if scope == "all" || len(ownCounterSignatures(signature)) == 0 {
			targets = append(targets, signature)
		}
	}
	return targets
}

// ownCounterSignatures are the counter-signatures a signature holds itself,
// not those its counter-signatures hold.
func ownCounterSignatures(signature *etree.Element) []*etree.Element {
	qualifying := findQualifyingProperties(signature)
	if qualifying == nil {
		return nil
	}
	return qualifying.FindElements("./UnsignedProperties/UnsignedSignatureProperties/CounterSignature")
}

// unsignedSignatureProperties is the signature's UnsignedSignatureProperties,
// made when it has none.
func unsignedSignatureProperties(signature, qualifying *etree.Element) *etree.Element {
	if found := qualifying.FindElement("./UnsignedProperties/UnsignedSignatureProperties"); found != nil {
		return found
	}
	// In the prefix the signature's properties already use.
	name := func(local string) string {
		if qualifying.Space == "" {
			return local
		}
		return qualifying.Space + ":" + local
	}
	unsigned := qualifying.FindElement("./UnsignedProperties")
	if unsigned == nil {
		unsigned = qualifying.CreateElement(name("UnsignedProperties"))
		unsigned.CreateAttr("Id", idBeside(signature, "unsigned-properties"))
	}
	return unsigned.CreateElement(name("UnsignedSignatureProperties"))
}

// holdingSignatures are the signatures of the document that verify with
// the certificate they carry, by their SignatureValue.
func holdingSignatures(tree *etree.Document) map[string]bool {
	return holdingSignaturesResolved(tree, nil)
}

// holdingSignaturesResolved is holdingSignatures with the documents outside
// the file that references point at.
func holdingSignaturesResolved(tree *etree.Document, resolve xmldsig.Resolver) map[string]bool {
	holding := map[string]bool{}
	for _, signature := range xmldsig.Signatures(tree) {
		certificateElement := signature.FindElement("./KeyInfo/X509Data/X509Certificate")
		value := signature.SelectElement("SignatureValue")
		if certificateElement == nil || value == nil {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(certificateElement.Text()), ""))
		if err != nil {
			continue
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if xmldsig.Check(tree, signature, publickey.Of(certificate), resolve) == nil {
			holding[strings.Join(strings.Fields(value.Text()), "")] = true
		}
	}
	return holding
}
