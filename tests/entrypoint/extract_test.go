package cli_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNestedEnvelopesGiveBackTheOriginalBytes(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeOnePagePDF(t)
	original, _ := os.ReadFile(document)

	for _, envelope := range []string{document, document + ".p7m"} {
		if _, stderr, code := run("sign", envelope, "--p12", key, "--format", "cades"); code != 0 {
			t.Fatalf("sign %s: exit %d: %s", envelope, code, stderr)
		}
	}
	output := filepath.Join(t.TempDir(), "estratto.pdf")
	stdout, stderr, code := run("extract", document+".p7m.p7m", "--out", output, "--json")
	if code != 0 {
		t.Fatalf("extract: exit %d: %s", code, stderr)
	}
	if extracted, _ := os.ReadFile(output); !bytes.Equal(extracted, original) {
		t.Error("the extracted document differs from the one signed")
	}
	if !bytes.Contains([]byte(stdout), []byte(`"layers": 2`)) {
		t.Errorf("stdout = %s, want two envelopes opened", stdout)
	}
}

func TestABase64EnvelopeIsReadLikeABinaryOne(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeOnePagePDF(t)
	if _, stderr, code := run("sign", document, "--p12", key, "--format", "cades"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	binary, _ := os.ReadFile(document + ".p7m")
	encoded := filepath.Join(t.TempDir(), "mailed.p7m")
	if err := os.WriteFile(encoded, []byte(base64.StdEncoding.EncodeToString(binary)), 0o600); err != nil {
		t.Fatal(err)
	}

	if result := verifyJSON(t, encoded); result.Signers[0].Integrity != "good" {
		t.Errorf("a Base64 .p7m must verify, integrity %s", result.Signers[0].Integrity)
	}
	if _, stderr, code := run("extract", encoded, "--out", filepath.Join(t.TempDir(), "out.pdf")); code != 0 {
		t.Errorf("extract: exit %d: %s", code, stderr)
	}
}

func TestExtractionRefusesToOverwrite(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeOnePagePDF(t)
	if _, _, code := run("sign", document, "--p12", key, "--format", "cades"); code != 0 {
		t.Fatal("sign failed")
	}
	if _, _, code := run("extract", document+".p7m"); code != 1 {
		t.Errorf("exit %d, want 1: the original sits where the extract would go", code)
	}
}

// TestSigningRefusesToOverwrite: a second signature onto the same name is
// refused, as extracting and decrypting refuse; --force replaces it, and
// nothing ever replaces the document being signed.
func TestSigningRefusesToOverwrite(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	document := writeOnePagePDF(t)
	if _, _, code := run("sign", document, "--p12", key, "--invisible"); code != 0 {
		t.Fatal("the first signature failed")
	}
	if _, stderr, code := run("sign", document, "--p12", key, "--invisible"); code != 1 || !strings.Contains(stderr, "--force") {
		t.Errorf("a second signature onto the same name: exit %d, %q", code, stderr)
	}
	if _, _, code := run("sign", document, "--p12", key, "--invisible", "--force"); code != 0 {
		t.Errorf("--force replaces it: exit %d", code)
	}
	original, _ := os.ReadFile(document)
	if _, stderr, code := run("sign", document, "--p12", key, "--invisible", "--force", "--out", document); code != 1 || !strings.Contains(stderr, "the document being signed") {
		t.Errorf("signing onto the document: exit %d, %q", code, stderr)
	}
	if after, _ := os.ReadFile(document); string(after) != string(original) {
		t.Error("the document was replaced")
	}
}
