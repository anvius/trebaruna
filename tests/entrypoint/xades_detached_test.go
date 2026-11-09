package cli_test

import (
	"os"
	"strings"
	"testing"
)

// TestADetachedXadesTravelsBesideItsDocument, like a .p7s: the document is
// untouched, verify finds it by the name the signature gives, and tells a
// changed document (broken) from a missing one (unknown).
func TestADetachedXadesTravelsBesideItsDocument(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	original := "%PDF-1.4\n%acta del pleno\n"
	document := writeDocument(t, "acta del pleno.pdf", original)

	if _, stderr, code := run("sign", document, "--p12", key, "--format", "xades", "--detached"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	signature := document + ".xsig"
	if raw, err := os.ReadFile(signature); err != nil || strings.Contains(string(raw), "acta del pleno\n") {
		t.Fatalf("the .xsig must exist and not carry the document (%v)", err)
	}
	if raw, _ := os.ReadFile(document); string(raw) != original {
		t.Fatal("the document must stay untouched")
	}

	result := verifyJSON(t, signature)
	if result.Signers[0].Integrity != "good" || !hasCode(result.Signers[0].Findings, "content.detached") {
		t.Errorf("with the document beside it: %+v", result.Signers[0])
	}
	other := writeDocument(t, "otro.pdf", "%PDF-1.4\n%otro\n")
	if result := verifyJSON(t, signature, "--content", other); result.Verdict != "broken" {
		t.Errorf("with another document: verdict %s, want broken", result.Verdict)
	}
	if err := os.WriteFile(document, []byte(original+"%cambio\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := verifyJSON(t, signature); result.Verdict != "broken" {
		t.Errorf("with a changed document: verdict %s, want broken", result.Verdict)
	}
	if err := os.Remove(document); err != nil {
		t.Fatal(err)
	}
	result = verifyJSON(t, signature)
	if result.Signers[0].Integrity != "unknown" || result.Verdict == "broken" || !hasCode(result.Signers[0].Findings, "content.missing") {
		t.Errorf("without the document: %+v, verdict %s", result.Signers[0], result.Verdict)
	}
}

// TestAnEnvelopingXadesSignsAnyFile.
func TestAnEnvelopingXadesSignsAnyFile(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "contrato.pdf", "%PDF-1.4\n%contrato\n")
	if _, stderr, code := run("sign", document, "--p12", key, "--format", "xades", "--enveloping"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	signed := strings.TrimSuffix(document, ".pdf") + "_signed.xml"
	if result := verifyJSON(t, signed); result.Signers[0].Integrity != "good" {
		t.Errorf("enveloping PDF: %+v", result.Signers[0])
	}
	if _, _, code := run("sign", document, "--p12", key, "--format", "xades", "--enveloping", "--detached"); code == 0 {
		t.Error("enveloping and detached at once must be refused")
	}
	if _, _, code := run("sign", document, "--p12", key, "--format", "xades"); code == 0 {
		t.Error("an enveloped signature of a PDF must be refused")
	}
}

func hasCode(findings []struct {
	Code string `json:"code"`
}, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

// TestPlainXMLDSigFromTheCommandLine: level B only, reported as XMLDSig.
func TestPlainXMLDSigFromTheCommandLine(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeDocument(t, "acta.xml", "<acta><punto>1</punto></acta>")
	if _, stderr, code := run("sign", document, "--p12", key, "--format", "xmldsig"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	signed := strings.TrimSuffix(document, ".xml") + "_signed.xml"
	stdout, _, _ := run("verify", signed, "--json")
	if !strings.Contains(stdout, `"format": "XMLDSig"`) || !strings.Contains(stdout, `"integrity": "good"`) {
		t.Errorf("verify: %s", stdout)
	}
	if _, _, code := run("sign", document, "--p12", key, "--format", "xmldsig", "--level", "t", "--tsa", "http://tsa.example.invalid"); code == 0 {
		t.Error("XMLDSig at level T must be refused")
	}
}
