package infrastructure

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/digitorus/timestamp"
)

// parseTimeStamp reads an RFC 3161 token and checks its signature: through
// the timestamp library or, for a token its authority signed with
// RSASSA-PSS, which the library's CMS code does not implement, here, the
// SignerInfo checked over the TSTInfo as any CMS signature (verifyNode).
func parseTimeStamp(der []byte) (*timestamp.Timestamp, error) {
	token, err := timestamp.Parse(der)
	if err == nil || !unsupportedByLibrary(err) {
		return token, err
	}
	tree, treeErr := parseSignatureTree(der, nil)
	if treeErr != nil || len(tree.signers) != 1 || !isPSS(tree.signers[0].SignatureAlgorithm) {
		return nil, err
	}
	signer := tree.signers[0]
	if !slices.ContainsFunc(tree.certificatesFor(signer.SID), func(certificate *x509.Certificate) bool {
		return verifyNode(signer, certificate, tree.content) == nil
	}) {
		return nil, fmt.Errorf("the timestamp's RSASSA-PSS signature does not verify")
	}
	return readTSTInfo(der, tree)
}

// tstInfo is RFC 3161's TSTInfo, as far as a report reads it.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	SerialNumber *big.Int
	Time         time.Time        `asn1:"generalized"`
	Accuracy     asn1.RawValue    `asn1:"optional"`
	Ordering     bool             `asn1:"optional,default:false"`
	Nonce        *big.Int         `asn1:"optional"`
	TSA          asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions   []pkix.Extension `asn1:"optional,tag:1"`
}

// readTSTInfo reads a token's TSTInfo, its encapsulated content, once its
// signature is checked.
func readTSTInfo(der []byte, tree signatureTree) (*timestamp.Timestamp, error) {
	var info tstInfo
	if _, err := asn1.Unmarshal(tree.content, &info); err != nil {
		return nil, fmt.Errorf("unreadable TSTInfo: %w", err)
	}
	hash, ok := digestFromOID(info.MessageImprint.HashAlgorithm.Algorithm)
	if !ok || len(info.MessageImprint.HashedMessage) == 0 {
		return nil, fmt.Errorf("the timestamp's imprint is unreadable")
	}
	return &timestamp.Timestamp{RawToken: der, HashAlgorithm: hash, HashedMessage: info.MessageImprint.HashedMessage,
		Time: info.Time, SerialNumber: info.SerialNumber, Policy: info.Policy, Ordering: info.Ordering, Nonce: info.Nonce,
		Certificates: tree.certificates, Extensions: info.Extensions}, nil
}
