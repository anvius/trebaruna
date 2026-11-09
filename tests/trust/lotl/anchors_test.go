package lotl_test

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	trustinfra "codeberg.org/simplicer/trebaruna/src/trust/infrastructure"
)

// TestTheAnchorsAreTheOfficialJournals: the six certificates of notice
// C/2026/1944, by fingerprint (officialjournal/PROVENANCE.md), among them
// the one that signed the list on 9 November 2026.
func TestTheAnchorsAreTheOfficialJournals(t *testing.T) {
	want := []string{
		"c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
		"e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
		"df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
		"b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
		"236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b",
		"d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474",
	}
	var got []string
	for _, certificate := range trustinfra.OfficialJournalAnchors() {
		digest := sha256.Sum256(certificate.Raw)
		got = append(got, hex.EncodeToString(digest[:]))
	}
	if !slices.Equal(got, want) {
		t.Errorf("anchors %v", got)
	}
	if trustinfra.OfficialJournalAnnouncement != "https://eur-lex.europa.eu/eli/C/2026/1944/oj" {
		t.Errorf("announcement %s", trustinfra.OfficialJournalAnnouncement)
	}
}
