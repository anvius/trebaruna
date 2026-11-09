package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/tests/support/tsa"
)

// TestAPAdESTimestampFromAnUnknownAuthorityIsStillATimestamp: a PAdES-T
// whose authority is on no trusted list is timestamped, bound to the
// signature, with its authority unproven, as CAdES-T and XAdES-T from the
// same authority are. It was reported as not timestamped at all.
func TestAPAdESTimestampFromAnUnknownAuthorityIsStillATimestamp(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	authority := tsa.New(t)
	document := writeOnePagePDF(t)

	stdout, stderr, code := run("sign", document, "--p12", key, "--level", "t", "--tsa", authority.URL(t), "--invisible", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var receipt struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatal(err)
	}

	verified, _, _ := run("verify", receipt.Path, "--json")
	var result struct {
		Signers []struct {
			Integrity   string `json:"integrity"`
			Timestamped bool   `json:"timestamped"`
			Authority   string `json:"timestamp_authority"`
			Timestamp   *struct {
				Bound bool `json:"bound"`
			} `json:"timestamp"`
			Findings []struct {
				Code string `json:"code"`
			} `json:"findings"`
		} `json:"signers"`
	}
	if err := json.Unmarshal([]byte(verified), &result); err != nil || len(result.Signers) != 1 {
		t.Fatalf("verify: %s %v", verified, err)
	}
	signer := result.Signers[0]
	var codes []string
	for _, finding := range signer.Findings {
		codes = append(codes, finding.Code)
	}
	joined := strings.Join(codes, " ")
	if signer.Integrity != "good" || !signer.Timestamped || !strings.Contains(joined, "timestamp.bound") ||
		!strings.Contains(joined, "timestamp.untrusted_authority") || strings.Contains(joined, "signing_time.claimed") {
		t.Errorf("integrity %s, timestamped %v, findings %s", signer.Integrity, signer.Timestamped, joined)
	}
	if signer.Authority != "Test TSA" || signer.Timestamp == nil || !signer.Timestamp.Bound {
		t.Errorf("the timestamp authority is not named: %s", verified)
	}
}
