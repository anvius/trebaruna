package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/verification/messaging"
)

// TestTheCertificateIsDescribedInOneLanguage: labels, state and the trust
// note all come from the reader's language, none left in another.
func TestTheCertificateIsDescribedInOneLanguage(t *testing.T) {
	path := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	for _, lang := range []string{"es", "it", "pl", "en", "ca", "gl", "eu"} {
		stdout, stderr, code := run("certificate", path, "--lang", lang, "--territory", "EU")
		if code != 0 {
			t.Fatalf("%s: exit %d, %s", lang, code, stderr)
		}
		catalogue := messaging.For(lang)
		for _, expected := range []string{catalogue.LabelIssuer, catalogue.LabelValidPeriod, catalogue.LabelState,
			catalogue.LabelTrust, catalogue.Issuers["issuer.self_signed"]} {
			if !strings.Contains(stdout, expected) {
				t.Errorf("%s: no %q in\n%s", lang, expected, stdout)
			}
		}
		if lang != "en" && (strings.Contains(stdout, "self-signed") || strings.Contains(stdout, "issuer")) {
			t.Errorf("%s: English left in\n%s", lang, stdout)
		}
	}

	stdout, _, _ := run("certificate", path, "--json", "--territory", "EU")
	var described struct {
		Certificates []struct {
			Code string `json:"verdict_code"`
			Note string `json:"verdict_note"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal([]byte(stdout), &described); err != nil || len(described.Certificates) != 1 ||
		described.Certificates[0].Code != "issuer.self_signed" || described.Certificates[0].Note == "" {
		t.Errorf("the JSON names the verdict's code: %s", stdout)
	}
}
