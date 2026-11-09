package integration_test

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// pssAuthority is a timestamp authority whose key signs with RSASSA-PSS:
// OpenSSL signs each TSTInfo.
type pssAuthority struct {
	t                           *testing.T
	directory, key, certificate string
}

func newPSSAuthority(t *testing.T) *pssAuthority {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl signs the PSS tokens")
	}
	directory := t.TempDir()
	authority := &pssAuthority{t: t, directory: directory,
		key: filepath.Join(directory, "tsa.key"), certificate: filepath.Join(directory, "tsa.pem")}
	if output, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", authority.key,
		"-out", authority.certificate, "-days", "1", "-subj", "/CN=PSS TSA",
		"-addext", "extendedKeyUsage=critical,timeStamping").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	return authority
}

// Token is a granted TimeStampResp over the SHA-256 digest.
func (a *pssAuthority) Token(_ context.Context, digest []byte, _, _, _ string) ([]byte, error) {
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
	}{1, asn1.ObjectIdentifier{1, 2, 3, 4}, messageImprint{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}, digest},
		big.NewInt(11), time.Now().UTC().Truncate(time.Second)})
	if err != nil {
		return nil, err
	}
	infoPath, tokenPath := filepath.Join(a.directory, "tstinfo.der"), filepath.Join(a.directory, "token.der")
	if err := os.WriteFile(infoPath, info, 0o600); err != nil {
		return nil, err
	}
	if output, err := exec.Command("openssl", "cms", "-sign", "-binary", "-nodetach", "-cades", "-econtent_type", "1.2.840.113549.1.9.16.1.4",
		"-in", infoPath, "-signer", a.certificate, "-inkey", a.key, "-keyopt", "rsa_padding_mode:pss", "-md", "sha256",
		"-outform", "DER", "-out", tokenPath).CombinedOutput(); err != nil {
		a.t.Errorf("%v\n%s", err, output)
		return nil, err
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, err
	}
	granted, _ := asn1.Marshal(struct{ Status int }{0})
	return asn1.Marshal(struct {
		Status asn1.RawValue
		Token  asn1.RawValue
	}{asn1.RawValue{FullBytes: granted}, asn1.RawValue{FullBytes: token}})
}

// TestAPAdESTimestampSignedWithRSAPSS: a PAdES-T whose signature
// timestamp an authority signed with RSASSA-PSS, which the PDF library
// cannot read: the signature and the timestamp hold, and a change to the
// document breaks it.
func TestAPAdESTimestampSignedWithRSAPSS(t *testing.T) {
	fixture := newFixture(t)
	signer := buildPemSigner(t, readFile(t, fixture.keyPath), readFile(t, fixture.certPath))
	age, err := domain.NamedPolicy("age", domain.Pades)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := infrastructure.NewPadesSigner(newPSSAuthority(t)).SignPades(context.Background(), application.PadesRequest{
		Content: blankPDFBytes(), Signer: signer, Level: domain.T, Policy: age, SignedAt: timeNow(),
		TimestampURL: "http://tsa.example.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	read := func(content []byte) verificationdomain.SignerReport {
		t.Helper()
		path := filepath.Join(t.TempDir(), "signed.pdf")
		os.WriteFile(path, content, 0o600)
		reports, err := verificationinfra.NewPDFVerifier().Extract(path)
		if err != nil || len(reports) != 1 {
			t.Fatalf("%v %v", reports, err)
		}
		return reports[0]
	}
	report := read(signed)
	if report.Integrity != verificationdomain.StatusGood || !report.Timestamped || report.TimestampAuthority != "PSS TSA" {
		t.Errorf("PAdES-T with a PSS timestamp: %s timestamped=%v by %q %+v", report.Integrity, report.Timestamped,
			report.TimestampAuthority, report.Findings)
	}
	altered := bytes.Replace(signed, []byte("/MediaBox [0 0 595 842]"), []byte("/MediaBox [0 0 596 842]"), 1)
	if bytes.Equal(altered, signed) {
		t.Fatal("the change did not apply")
	}
	if report := read(altered); report.Integrity == verificationdomain.StatusGood {
		t.Errorf("a changed document is reported intact: %+v", report.Findings)
	}
}
