package cli_test

// What verify prints of a PDF signed twice: each signature by its field's
// name, the reason the signature gives, no warning line without words,
// and one time zone per output (UTC in JSON, local for a person) whatever
// the format.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyNamesFieldsAndSpeaksInOneZone(t *testing.T) {
	key := writeIdentityP12(t, "segreto", "MARIA GARCIA", 37)
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeOnePagePDF(t)
	once := strings.TrimSuffix(document, ".pdf") + "_once.pdf"
	twice := strings.TrimSuffix(document, ".pdf") + "_twice.pdf"
	if _, stderr, code := run("sign", document, "--p12", key, "--invisible", "--reason", "Conformidad con el contrato", "--out", once); code != 0 {
		t.Fatalf("first signature: %s", stderr)
	}
	if _, stderr, code := run("sign", once, "--p12", key, "--box", "300,60,520,120", "--out", twice); code != 0 {
		t.Fatalf("second signature: %s", stderr)
	}

	stdout, _, _ := run("verify", twice, "--json")
	var report struct {
		Signers []struct {
			Field    string `json:"field"`
			SignedAt string `json:"signed_at"`
		} `json:"signers"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || len(report.Signers) != 2 {
		t.Fatalf("%v: %s", err, stdout)
	}
	if report.Signers[0].Field != "Signature 1" || report.Signers[1].Field != "Signature 2" {
		t.Errorf("the fields are named by the signer: %+v", report.Signers)
	}
	for _, signer := range report.Signers {
		if !strings.HasSuffix(signer.SignedAt, "Z") {
			t.Errorf("JSON time %q is not UTC", signer.SignedAt)
		}
	}

	human, _, _ := run("verify", twice, "--lang", "es")
	if !strings.Contains(human, "Motivo") || !strings.Contains(human, "Conformidad con el contrato") {
		t.Errorf("the reason is not shown:\n%s", human)
	}
	for _, line := range strings.Split(human, "\n") {
		if strings.TrimSpace(line) == "! aviso del verificador" {
			t.Errorf("a warning without words:\n%s", human)
		}
	}
	offset := time.Now().Format("-07:00")
	if !strings.Contains(human, offset) {
		t.Errorf("the times are not local (%s):\n%s", offset, human)
	}

	cades := document + ".p7m"
	if _, stderr, code := run("sign", document, "--p12", key, "--format", "cades"); code != 0 {
		t.Fatalf("CAdES: %s", stderr)
	}
	stdout, _, _ = run("verify", cades, "--json")
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || !strings.HasSuffix(report.Signers[0].SignedAt, "Z") {
		t.Errorf("CAdES JSON time: %v %s", err, stdout)
	}
	if human, _, _ := run("verify", cades, "--lang", "es"); !strings.Contains(human, offset) {
		t.Errorf("CAdES human time is not local:\n%s", human)
	}
}
