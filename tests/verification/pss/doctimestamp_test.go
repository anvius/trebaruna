package pss_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/timestamp"

	"codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
	"codeberg.org/simplicer/trebaruna/tests/support/tsa"
)

// pssToken is an RFC 3161 token over imprint (SHA-256) that OpenSSL signed
// with RSASSA-PSS, as an authority with a PSS key does.
func pssToken(t *testing.T, imprint []byte) []byte {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl signs the PSS token")
	}
	directory := t.TempDir()
	key, certificate := filepath.Join(directory, "tsa.key"), filepath.Join(directory, "tsa.pem")
	if output, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", certificate,
		"-days", "1", "-subj", "/CN=PSS TSA", "-addext", "extendedKeyUsage=critical,timeStamping").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	type messageImprint struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	info, err := asn1.Marshal(struct {
		Version      int
		Policy       asn1.ObjectIdentifier
		Imprint      messageImprint
		SerialNumber *big.Int
		Time         time.Time `asn1:"generalized"`
	}{1, asn1.ObjectIdentifier{1, 2, 3, 4}, messageImprint{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}, imprint},
		big.NewInt(9), time.Now().UTC().Truncate(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	infoPath, tokenPath := filepath.Join(directory, "tstinfo.der"), filepath.Join(directory, "token.der")
	os.WriteFile(infoPath, info, 0o600)
	if output, err := exec.Command("openssl", "cms", "-sign", "-binary", "-nodetach", "-cades", "-econtent_type", "1.2.840.113549.1.9.16.1.4",
		"-in", infoPath, "-signer", certificate, "-inkey", key, "-keyopt", "rsa_padding_mode:pss", "-md", "sha256",
		"-outform", "DER", "-out", tokenPath).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	token, _ := os.ReadFile(tokenPath)
	return token
}

// pssDocumentTimestamp is a one-page PDF with a document timestamp whose
// authority signed with RSASSA-PSS: pdfsign wrote it with an ordinary
// token, here replaced in /Contents by a PSS one over the same digest.
func pssDocumentTimestamp(t *testing.T) []byte {
	t.Helper()
	blank := []byte("%PDF-1.7\n")
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> >>"}
	var builder bytes.Buffer
	builder.Write(blank)
	offsets := make([]int, len(objects))
	for index, object := range objects {
		offsets[index] = builder.Len()
		fmt.Fprintf(&builder, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xref := builder.Len()
	fmt.Fprintf(&builder, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&builder, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&builder, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)

	document, err := pdfsign.Open(bytes.NewReader(builder.Bytes()), int64(builder.Len()))
	if err != nil {
		t.Fatal(err)
	}
	document.Timestamp(tsa.New(t).URL(t))
	var stamped bytes.Buffer
	if _, err := document.Write(&stamped); err != nil {
		t.Fatal(err)
	}
	content := stamped.Bytes()

	hole := regexp.MustCompile(`/Contents\s*<([0-9A-Fa-f]+)>`).FindSubmatchIndex(content)
	if hole == nil {
		t.Fatal("no /Contents")
	}
	padded, err := hex.DecodeString(string(content[hole[2]:hole[3]]))
	if err != nil {
		t.Fatal(err)
	}
	var ordinary asn1.RawValue
	if _, err := asn1.Unmarshal(padded, &ordinary); err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.Parse(ordinary.FullBytes)
	if err != nil {
		t.Fatal(err)
	}
	replacement := hex.EncodeToString(pssToken(t, parsed.HashedMessage))
	width := hole[3] - hole[2]
	if len(replacement) > width {
		t.Fatalf("the PSS token (%d) does not fit the hole (%d)", len(replacement), width)
	}
	replacement += strings.Repeat("0", width-len(replacement))
	return append(append(append([]byte{}, content[:hole[2]]...), replacement...), content[hole[3]:]...)
}

// TestADocumentTimestampSignedWithRSAPSS: a document timestamp whose
// authority signed with RSASSA-PSS, which the PDF library cannot check,
// holds while the document is unchanged, and the document changed under it
// is not reported intact.
func TestADocumentTimestampSignedWithRSAPSS(t *testing.T) {
	stamped := pssDocumentTimestamp(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "stamped.pdf")
	os.WriteFile(path, stamped, 0o600)
	report := only(t, verificationinfra.NewPDFVerifier(), path)
	if report.Integrity != domain.StatusGood || !report.Timestamped || report.SignedAt.IsZero() {
		t.Errorf("unchanged: %s %v %v %+v", report.Integrity, report.Timestamped, report.SignedAt, report.Findings)
	}

	altered := bytes.Replace(stamped, []byte("/MediaBox [0 0 595 842]"), []byte("/MediaBox [0 0 596 842]"), 1)
	if bytes.Equal(altered, stamped) {
		t.Fatal("the change did not apply")
	}
	changedPath := filepath.Join(directory, "changed.pdf")
	os.WriteFile(changedPath, altered, 0o600)
	if report := only(t, verificationinfra.NewPDFVerifier(), changedPath); report.Integrity == domain.StatusGood {
		t.Errorf("a changed document under a PSS document timestamp is reported intact: %+v", report.Findings)
	}
}
