package infrastructure

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

//go:embed officialjournal/C-2026-1944.pem
var officialJournalPEM []byte

// OfficialJournalAnnouncement is the address, as the EU list of the lists
// names it, of the Official Journal notice that announced the certificates
// the Commission signs that list with (officialjournal/PROVENANCE.md).
const OfficialJournalAnnouncement = "https://eur-lex.europa.eu/eli/C/2026/1944/oj"

// OfficialJournalAnchors are the certificates that notice announced: the
// root of trust of every list trebaruna syncs, published outside the list
// so that the list cannot vouch for itself.
func OfficialJournalAnchors() []*x509.Certificate {
	var anchors []*x509.Certificate
	for rest := officialJournalPEM; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return anchors
		}
		if certificate, err := x509.ParseCertificate(block.Bytes); err == nil {
			anchors = append(anchors, certificate)
		}
	}
}
