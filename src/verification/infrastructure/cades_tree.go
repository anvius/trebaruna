package infrastructure

// Envelopes with several signatures: parallel signatures over the same
// content, and counter-signatures over other signatures (RFC 5652 §11.4).
// Each node is checked on its own — its digest, its signature, its timestamp,
// its chain — so one bad signature never hides behind a good one, and one
// counter-signer's revoked card does not make the document look altered.

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/ber"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/publickey"
	"codeberg.org/simplicer/trebaruna/src/verification/domain"
)

var (
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttributeCountersign   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidAttributeTimestamp     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

type treeSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type treeSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type treeAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// signatureTree is a parsed envelope ready to be checked node by node.
type signatureTree struct {
	// der is the envelope, its BER made DER.
	der     []byte
	content []byte
	// contentType is the encapsulated content's type: id-data for a
	// document, id-ct-TSTInfo for a timestamp token.
	contentType  asn1.ObjectIdentifier
	certificates []*x509.Certificate
	signers      []treeSignerInfo
}

// oidTSTInfo is id-ct-TSTInfo (RFC 3161): the content of a timestamp token.
var oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

// parseSignatureTree reads an envelope; content is the document for a
// detached envelope.
func parseSignatureTree(envelope, detached []byte) (signatureTree, error) {
	normalised, err := ber.ToDER(envelope)
	if err != nil {
		return signatureTree{}, err
	}
	var contentInfo struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(normalised, &contentInfo); err != nil {
		return signatureTree{}, err
	}
	var signed treeSignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signed); err != nil {
		return signatureTree{}, err
	}

	tree := signatureTree{der: normalised, content: detached}
	var encapsulated struct {
		Type    asn1.ObjectIdentifier
		Content []byte `asn1:"optional,explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(signed.EncapContentInfo.FullBytes, &encapsulated); err == nil {
		tree.contentType = encapsulated.Type
		if len(encapsulated.Content) > 0 {
			tree.content = encapsulated.Content
		}
	}

	for rest := signed.Certificates.Bytes; len(rest) > 0; {
		var element asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &element); err != nil {
			return signatureTree{}, err
		}
		// Brainpool keys, which Go cannot read, come through the brainpool
		// package.
		if certificate, err := brainpool.ParseCertificate(element.FullBytes); err == nil {
			publickey.Complete(certificate)
			tree.certificates = append(tree.certificates, certificate)
		}
	}
	if tree.signers, err = signerInfosIn(signed.SignerInfos.Bytes); err != nil {
		return signatureTree{}, err
	}
	return tree, nil
}

func signerInfosIn(set []byte) ([]treeSignerInfo, error) {
	var signers []treeSignerInfo
	for rest := set; len(rest) > 0; {
		var signer treeSignerInfo
		var err error
		if rest, err = asn1.Unmarshal(rest, &signer); err != nil {
			return nil, fmt.Errorf("unreadable SignerInfo: %w", err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

// isTree reports whether the envelope needs the tree path: more than one
// signature, or any counter-signature.
func (t signatureTree) isTree() bool {
	if len(t.signers) != 1 {
		return true
	}
	return len(attributeValues(t.signers[0].UnsignedAttrs, oidAttributeCountersign)) > 0
}

// attributeValues returns the values of one attribute from a [0] or [1] set.
func attributeValues(set asn1.RawValue, wanted asn1.ObjectIdentifier) [][]byte {
	var values [][]byte
	for rest := set.Bytes; len(rest) > 0; {
		var attribute treeAttribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &attribute); err != nil {
			return values
		}
		if !attribute.Type.Equal(wanted) {
			continue
		}
		for inner := attribute.Values.Bytes; len(inner) > 0; {
			var value asn1.RawValue
			if inner, err = asn1.Unmarshal(inner, &value); err != nil {
				break
			}
			values = append(values, value.FullBytes)
		}
	}
	return values
}

// extractTree checks every node and reports them in document order: each
// signature over the content followed by its counter-signatures.
func (v *CadesVerifier) extractTree(tree signatureTree) ([]domain.SignerReport, error) {
	if len(tree.content) == 0 && !v.hasDetached() {
		// Without the document no node can be compared; ADR-0005.
		return nil, fmt.Errorf("detached envelope: the signed document is needed (--content)")
	}
	var reports []domain.SignerReport
	for index, signer := range tree.signers {
		field := fmt.Sprintf("CMS #%d", index+1)
		start := len(reports)
		reports = v.checkNode(tree, signer, tree.content, field, "", reports)
		describeArchiveTimeStamps(tree.der, index, signer.UnsignedAttrs, tree.content, &reports[start])
	}
	return reports, nil
}

// checkNode reports one signature and recurses into its counter-signatures.
func (v *CadesVerifier) checkNode(tree signatureTree, signer treeSignerInfo, signed []byte, field, countersigns string, reports []domain.SignerReport) []domain.SignerReport {
	report := domain.SignerReport{FieldName: field, Format: "CAdES", Countersigns: countersigns,
		Declared: domain.Declarations{Policy: cmsPolicy(signer.SignedAttrs)}}

	// Several carried certificates may answer to the same identifier (a
	// re-issued certificate keeps issuer and serial in careless PKIs); the one
	// whose key verifies is the signer's.
	// The one the signed ESS attribute names is preferred.
	named := essCertificateDigests(signer.SignedAttrs)
	certificate, err := chooseSigner(tree.certificatesFor(signer.SID), named, func(candidate *x509.Certificate) error {
		return verifyNode(signer, candidate, signed)
	})

	switch {
	case errors.Is(err, errUnsupportedSignature):
		report.Integrity = domain.StatusUnknown
		report.Findings = append(report.Findings, unverifiableFinding(err))
	case err != nil:
		report.Integrity = domain.StatusBad
		message := "the signed content does not match the signature"
		if countersigns != "" {
			message = "the counter-signature does not match the signature it counter-signs"
		}
		report.Findings = append(report.Findings, domain.Finding{
			Code: "signature.modified", Status: domain.StatusBad, Message: message, Detail: err.Error(),
		})
	default:
		report.Integrity = domain.StatusGood
		report.Findings = append(report.Findings, domain.Finding{
			Code: "signature.intact", Status: domain.StatusGood, Message: "the signed content is unaltered",
		})
	}

	describeESSCertificate(named, certificate, &report)
	describeCertificate(certificate, &report)
	report.Revocation.Certificate = certificate
	report.Revocation.Issuer = issuerFromSet(tree.certificates, certificate)

	for _, value := range attributeValues(signer.SignedAttrs, oidAttributeSigningTime) {
		var claimed time.Time
		if _, err := asn1.Unmarshal(value, &claimed); err == nil {
			report.SignedAt = claimed
		}
	}
	if tokens := attributeValues(signer.UnsignedAttrs, oidAttributeTimestamp); len(tokens) > 0 {
		describeToken(tokens[0], signer.Signature, &report)
	}

	if certificate != nil {
		switch {
		case report.SelfSigned:
			report.Findings = append(report.Findings, domain.Finding{
				Code: "certificate.self_signed", Status: domain.StatusWarn,
				Message: "the certificate is self-signed: valid cryptography, no third-party trust",
			})
		case v.chainOf(certificate, tree.certificates, chainInstant(&report, v.Now)) == nil:
			report.CertificateStatus = domain.StatusGood
			report.Findings = append(report.Findings, domain.Finding{
				Code: "certificate.trusted", Status: domain.StatusGood, Message: "the issuer is a recognised authority",
			})
		default:
			report.CertificateStatus = domain.StatusUnknown
			report.Findings = append(report.Findings, domain.Finding{
				Code: "certificate.untrusted_issuer", Status: domain.StatusUnknown, Message: "the issuer is not in any trusted list",
			})
		}
	}
	report.Trust = trustFromReport(report)
	reports = append(reports, report)

	children := attributeValues(signer.UnsignedAttrs, oidAttributeCountersign)
	for index, child := range children {
		var counter treeSignerInfo
		if _, err := asn1.Unmarshal(child, &counter); err != nil {
			continue
		}
		reports = v.checkNode(tree, counter, signer.Signature,
			fmt.Sprintf("%s › countersignature %d", field, index+1), field, reports)
	}
	return reports
}

// chainOf validates a certificate against the anchors at the given instant.
func (v *CadesVerifier) chainOf(certificate *x509.Certificate, carried []*x509.Certificate, at time.Time) error {
	publickey.Complete(carried...)
	intermediates := x509.NewCertPool()
	for _, candidate := range carried {
		intermediates.AddCert(candidate)
	}
	_, err := certificate.Verify(x509.VerifyOptions{
		Roots: v.rootsWithAnchors(), Intermediates: intermediates, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil && involvesBrainpool(append(append([]*x509.Certificate{certificate}, carried...), v.Anchors...)) {
		return brainpoolChainOf(certificate, carried, v.Anchors, at)
	}
	return err
}

// involvesBrainpool reports a Brainpool key among the certificates: Go's
// chain builder cannot check what such a key signs.
func involvesBrainpool(certificates []*x509.Certificate) bool {
	for _, certificate := range certificates {
		if _, ok := certificate.PublicKey.(*brainpool.PublicKey); ok {
			return true
		}
	}
	return false
}

// brainpoolChainOf walks from the certificate up through the carried ones
// to an anchor, each issuer's signature checked by the brainpool package
// and each certificate valid at the instant.
func brainpoolChainOf(certificate *x509.Certificate, carried, anchors []*x509.Certificate, at time.Time) error {
	current := certificate
	for depth := 0; depth < 10; depth++ {
		if at.Before(current.NotBefore) || at.After(current.NotAfter) {
			return fmt.Errorf("%s is not valid at %s", current.Subject.CommonName, at.Format(time.RFC3339))
		}
		for _, anchor := range anchors {
			if bytes.Equal(anchor.Raw, current.Raw) ||
				(bytes.Equal(anchor.RawSubject, current.RawIssuer) && brainpool.CheckSignatureFrom(current, anchor) == nil) {
				return nil
			}
		}
		var next *x509.Certificate
		for _, candidate := range carried {
			if !bytes.Equal(candidate.Raw, current.Raw) && bytes.Equal(candidate.RawSubject, current.RawIssuer) &&
				brainpool.CheckSignatureFrom(current, candidate) == nil {
				next = candidate
				break
			}
		}
		if next == nil {
			return fmt.Errorf("no chain from %s to a trusted authority", certificate.Subject.CommonName)
		}
		current = next
	}
	return fmt.Errorf("the chain from %s is too long", certificate.Subject.CommonName)
}

// certificatesFor finds the certificates a SignerInfo names.
func (t signatureTree) certificatesFor(sid asn1.RawValue) []*x509.Certificate {
	var found []*x509.Certificate
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, certificate := range t.certificates {
			if bytes.Equal(certificate.SubjectKeyId, sid.Bytes) {
				found = append(found, certificate)
			}
		}
		return found
	}
	var issuerAndSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	if _, err := asn1.Unmarshal(sid.FullBytes, &issuerAndSerial); err != nil {
		return nil
	}
	for _, certificate := range t.certificates {
		if certificate.SerialNumber.Cmp(issuerAndSerial.Serial) == 0 && bytes.Equal(certificate.RawIssuer, issuerAndSerial.Issuer.FullBytes) {
			found = append(found, certificate)
		}
	}
	return found
}

// verifyNode checks that the node's messageDigest is the digest of what it
// signs and that its signature over the signed attributes verifies.
func verifyNode(signer treeSignerInfo, certificate *x509.Certificate, signed []byte) error {
	if certificate == nil {
		return fmt.Errorf("the signing certificate is not in the envelope")
	}
	hash, ok := digestFromOID(signer.DigestAlgorithm.Algorithm)
	if !ok {
		return fmt.Errorf("unsupported digest algorithm %v", signer.DigestAlgorithm.Algorithm)
	}
	if len(signer.SignedAttrs.FullBytes) == 0 {
		return fmt.Errorf("signatures without signed attributes are not supported")
	}

	digests := attributeValues(signer.SignedAttrs, oidAttributeMessageDigest)
	if len(digests) != 1 {
		return fmt.Errorf("expected one messageDigest attribute, found %d", len(digests))
	}
	var recorded []byte
	if _, err := asn1.Unmarshal(digests[0], &recorded); err != nil {
		return fmt.Errorf("unreadable messageDigest: %w", err)
	}
	hasher := hash.New()
	hasher.Write(signed)
	if !bytes.Equal(hasher.Sum(nil), recorded) {
		return fmt.Errorf("messageDigest does not match")
	}

	// The signature covers the attributes as a DER SET, not as the [0] they
	// are written with.
	attributes := append([]byte{}, signer.SignedAttrs.FullBytes...)
	attributes[0] = 0x31
	return checkSignerSignature(certificate, signer.SignatureAlgorithm, hash, attributes, signer.Signature)
}

func digestFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}):
		return crypto.SHA1, true
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}):
		return crypto.SHA256, true
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}):
		return crypto.SHA384, true
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}):
		return crypto.SHA512, true
	}
	return 0, false
}

// signatureAlgorithm maps a CMS signature algorithm and its digest onto Go's.
// CMS writes RSA as rsaEncryption plus a separate digest; the explicit OIDs
// are accepted too.
func signatureAlgorithm(oid asn1.ObjectIdentifier, hash crypto.Hash) (x509.SignatureAlgorithm, bool) {
	rsa := map[crypto.Hash]x509.SignatureAlgorithm{crypto.SHA1: x509.SHA1WithRSA, crypto.SHA256: x509.SHA256WithRSA, crypto.SHA384: x509.SHA384WithRSA, crypto.SHA512: x509.SHA512WithRSA}
	ecdsa := map[crypto.Hash]x509.SignatureAlgorithm{crypto.SHA1: x509.ECDSAWithSHA1, crypto.SHA256: x509.ECDSAWithSHA256, crypto.SHA384: x509.ECDSAWithSHA384, crypto.SHA512: x509.ECDSAWithSHA512}
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}),
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}),
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}),
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}),
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}):
		algorithm, ok := rsa[hash]
		return algorithm, ok
	case len(oid) >= 6 && oid[:6].Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3}),
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}),
		oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}):
		algorithm, ok := ecdsa[hash]
		return algorithm, ok
	}
	return 0, false
}
