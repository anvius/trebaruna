package cli_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/tests/support/tsa"
)

type treeNode struct {
	Field        string `json:"field"`
	Signer       string `json:"signer"`
	Integrity    string `json:"integrity"`
	Countersigns string `json:"countersigns"`
	Timestamped  bool   `json:"timestamped"`
}

type treeReport struct {
	Verdict string     `json:"verdict"`
	Signers []treeNode `json:"signers"`
}

func verifyTree(t *testing.T, arguments ...string) treeReport {
	t.Helper()
	stdout, stderr, _ := run(append([]string{"verify"}, append(arguments, "--json")...)...)
	var report treeReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("verify printed %q (stderr %q)", stdout, stderr)
	}
	return report
}

// envelopeSignedBy signs a fresh PDF as a .p7m with a first key.
func envelopeSignedBy(t *testing.T, key string) string {
	t.Helper()
	document := writeOnePagePDF(t)
	if _, stderr, code := run("sign", document, "--p12", key, "--format", "cades"); code != 0 {
		t.Fatalf("sign: exit %d: %s", code, stderr)
	}
	return document + ".p7m"
}

func TestAParallelSignatureIsAddedAndBothVerify(t *testing.T) {
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	first, second := writeProtectedP12(t, "segreto"), writeIdentityP12(t, "segreto", "ANNA BIANCHI", 2)
	envelope := envelopeSignedBy(t, first)

	stdout, stderr, code := run("sign", envelope, "--cosign", "--p12", second, "--json")
	if code != 0 {
		t.Fatalf("cosign: exit %d: %s", code, stderr)
	}
	cosigned := strings.TrimSuffix(envelope, ".p7m") + "_cosigned.p7m"
	if !strings.Contains(stdout, cosigned) {
		t.Fatalf("stdout = %s, want %s", stdout, cosigned)
	}

	report := verifyTree(t, cosigned)
	if len(report.Signers) != 2 || report.Signers[0].Integrity != "good" || report.Signers[1].Integrity != "good" {
		t.Fatalf("report = %+v, want two good parallel signatures", report)
	}
	if _, err := exec.LookPath("openssl"); err == nil {
		output, err := exec.Command("openssl", "cms", "-verify", "-inform", "DER", "-in", cosigned, "-noverify", "-binary", "-out", os.DevNull).CombinedOutput()
		if err != nil || !strings.Contains(string(output), "Verification successful") {
			t.Errorf("openssl refuses the co-signed envelope: %v\n%s", err, output)
		}
	}
}

func TestCounterSignaturesGoToTheLeavesOrToTheWholeTree(t *testing.T) {
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	first, second, third := writeProtectedP12(t, "segreto"), writeIdentityP12(t, "segreto", "ANNA BIANCHI", 2), writeIdentityP12(t, "segreto", "LUCA VERDI", 3)
	envelope := envelopeSignedBy(t, first)
	if _, _, code := run("sign", envelope, "--cosign", "--p12", second); code != 0 {
		t.Fatal("cosign failed")
	}
	cosigned := strings.TrimSuffix(envelope, ".p7m") + "_cosigned.p7m"

	if _, stderr, code := run("sign", cosigned, "--countersign", "leaves", "--p12", third); code != 0 {
		t.Fatalf("countersign: exit %d: %s", code, stderr)
	}
	leaves := strings.TrimSuffix(cosigned, ".p7m") + "_countersigned.p7m"
	report := verifyTree(t, leaves)
	if len(report.Signers) != 4 {
		t.Fatalf("got %d nodes, want two signatures each with a counter-signature: %+v", len(report.Signers), report.Signers)
	}
	for _, node := range report.Signers {
		if node.Integrity != "good" {
			t.Errorf("%s: integrity %s", node.Field, node.Integrity)
		}
	}
	if report.Signers[1].Countersigns != "CMS #1" || report.Signers[3].Countersigns != "CMS #2" {
		t.Errorf("tree = %+v, want each counter-signature under its signature", report.Signers)
	}

	if _, stderr, code := run("sign", leaves, "--countersign", "all", "--p12", first, "--out", filepath.Join(t.TempDir(), "all.p7m")); code != 0 {
		t.Fatalf("countersign all: exit %d: %s", code, stderr)
	}
}

// countersignatureChunk returns where the first counter-signature of the
// first signer sits in the envelope, by parsing it independently.
func countersignatureChunk(t *testing.T, envelope []byte) (int, int) {
	t.Helper()
	var contentInfo struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(envelope, &contentInfo); err != nil {
		t.Fatal(err)
	}
	var signed struct {
		Version          int
		DigestAlgorithms asn1.RawValue `asn1:"set"`
		Encap            asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos      asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signed); err != nil {
		t.Fatal(err)
	}
	var signer struct {
		Version   int
		SID       asn1.RawValue
		Digest    asn1.RawValue
		Signed    asn1.RawValue `asn1:"optional,tag:0"`
		Algorithm asn1.RawValue
		Signature []byte
		Unsigned  asn1.RawValue `asn1:"optional,tag:1"`
	}
	if _, err := asn1.Unmarshal(signed.SignerInfos.Bytes, &signer); err != nil {
		t.Fatal(err)
	}
	var attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(signer.Unsigned.Bytes, &attribute); err != nil {
		t.Fatal(err)
	}
	var counter asn1.RawValue
	if _, err := asn1.Unmarshal(attribute.Values.Bytes, &counter); err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(envelope, counter.FullBytes)
	if start < 0 {
		t.Fatal("counter-signature not found")
	}
	return start, len(counter.FullBytes)
}

func TestATamperedCounterSignatureFailsAloneAndContentChangesSpareIt(t *testing.T) {
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	first, second := writeProtectedP12(t, "segreto"), writeIdentityP12(t, "segreto", "ANNA BIANCHI", 2)
	envelope := envelopeSignedBy(t, first)
	if _, _, code := run("sign", envelope, "--countersign", "leaves", "--p12", second); code != 0 {
		t.Fatal("countersign failed")
	}
	countersigned := strings.TrimSuffix(envelope, ".p7m") + "_countersigned.p7m"
	original, _ := os.ReadFile(countersigned)

	// The last byte of the counter-signature is its signature value.
	start, length := countersignatureChunk(t, original)
	broken := append([]byte{}, original...)
	broken[start+length-1] ^= 0xff
	tampered := filepath.Join(t.TempDir(), "tampered.p7m")
	if err := os.WriteFile(tampered, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	report := verifyTree(t, tampered)
	if report.Signers[0].Integrity != "good" || report.Signers[1].Integrity != "bad" {
		t.Errorf("nodes = %+v, want the signature intact and only its counter-signature bad", report.Signers)
	}

	// Changing the document breaks the signature over it, not the
	// counter-signature, which signs the signature value.
	document := bytes.Index(original, []byte("%PDF-1.4"))
	altered := append([]byte{}, original...)
	altered[document+5] = '9'
	changed := filepath.Join(t.TempDir(), "changed.p7m")
	if err := os.WriteFile(changed, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	report = verifyTree(t, changed)
	if report.Verdict != "broken" || report.Signers[0].Integrity != "bad" || report.Signers[1].Integrity != "good" {
		t.Errorf("verdict %s, nodes %+v", report.Verdict, report.Signers)
	}
}

func TestAnEnvelopeCoSignedByOpenSSLIsReadNodeByNode(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	envelope := envelopeSignedBy(t, writeProtectedP12(t, "segreto"))
	directory := t.TempDir()
	key, certificate := filepath.Join(directory, "k.pem"), filepath.Join(directory, "c.pem")
	if output, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
		"-out", certificate, "-days", "1", "-subj", "/CN=ANNA BIANCHI").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	resigned := filepath.Join(directory, "resigned.p7m")
	if output, err := exec.Command("openssl", "cms", "-resign", "-binary", "-in", envelope, "-inform", "DER",
		"-signer", certificate, "-inkey", key, "-outform", "DER", "-out", resigned).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}

	report := verifyTree(t, resigned)
	if len(report.Signers) != 2 || report.Signers[1].Signer != "ANNA BIANCHI" || report.Signers[1].Integrity != "good" {
		t.Errorf("report = %+v", report)
	}
}

func TestADetachedEnvelopeIsCoSignedWithItsDocument(t *testing.T) {
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	first, second := writeProtectedP12(t, "segreto"), writeIdentityP12(t, "segreto", "ANNA BIANCHI", 2)
	document := writeDocument(t, "offerta.txt", "offerta\n")
	if _, _, code := run("sign", document, "--p12", first, "--format", "cades", "--detached"); code != 0 {
		t.Fatal("detached sign failed")
	}
	signature := document + ".p7s"

	if _, _, code := run("sign", signature, "--cosign", "--p12", second); code == 0 {
		t.Error("co-signing a .p7s without its document must fail")
	}
	if _, stderr, code := run("sign", signature, "--cosign", "--p12", second, "--content", document); code != 0 {
		t.Fatalf("cosign with the document: exit %d: %s", code, stderr)
	}
	cosigned := strings.TrimSuffix(signature, ".p7s") + "_cosigned.p7s"
	report := verifyTree(t, cosigned, "--content", document)
	if len(report.Signers) != 2 || report.Signers[0].Integrity != "good" || report.Signers[1].Integrity != "good" {
		t.Errorf("report = %+v", report)
	}
}

func TestAnAddedSignatureCanCarryATimestamp(t *testing.T) {
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	authority := tsa.New(t)
	first, second := writeProtectedP12(t, "segreto"), writeIdentityP12(t, "segreto", "ANNA BIANCHI", 2)
	envelope := envelopeSignedBy(t, first)

	if _, stderr, code := run("sign", envelope, "--cosign", "--p12", second, "--level", "t", "--tsa", authority.URL(t)); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	report := verifyTree(t, strings.TrimSuffix(envelope, ".p7m")+"_cosigned.p7m")
	if report.Signers[0].Timestamped || !report.Signers[1].Timestamped {
		t.Errorf("nodes = %+v, want only the added signature timestamped", report.Signers)
	}
	if _, _, code := run("sign", envelope, "--cosign", "--p12", second, "--level", "lt", "--tsa", authority.URL(t), "--online-revocation"); code == 0 {
		t.Error("LT on an added signature is not available and must be refused")
	}
}

func TestOnlyEnvelopesTakeAddedSignatures(t *testing.T) {
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	key := writeProtectedP12(t, "segreto")
	if _, _, code := run("sign", writeOnePagePDF(t), "--cosign", "--p12", key); code == 0 {
		t.Error("a PDF is signed again by signing the signed file, not co-signed")
	}
	if _, _, code := run("sign", envelopeSignedBy(t, key), "--countersign", "sometimes", "--p12", key); code == 0 {
		t.Error("an unknown scope must be refused")
	}
}
