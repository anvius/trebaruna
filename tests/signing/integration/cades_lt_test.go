package integration_test

// CAdES-LT and CAdES-LTA, verified with OpenSSL rather than by inspecting our own
// output: the attributes have standard OIDs, and a wrong one produces a container
// that parses while meaning something else. That happened — revocationValues was
// written with the certificateValues OID — and only an independent parser showed it.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// cadesFixture returns a document and a signer whose certificate publishes an OCSP
// responder, which LT requires.
func cadesFixture(t *testing.T) ([]byte, signingdomain.Signer) {
	t.Helper()
	return ltaFixture(t)
}

// TestCadesLtNeedsARevocationSource: LT is an opt-in network operation.
func TestCadesLtNeedsARevocationSource(t *testing.T) {
	content, signer := cadesFixture(t)

	_, err := infrastructure.NewCadesSigner(newLocalTSA(t)).SignCades(context.Background(),
		application.CadesRequest{
			Content:      content,
			Signer:       signer,
			Level:        signingdomain.LT,
			TimestampURL: "http://tsa.example.invalid",
		})
	if err == nil {
		t.Fatal("CAdES-LT without --online-revocation must be refused")
	}
	if !strings.Contains(err.Error(), "--online-revocation") {
		t.Errorf("the error must name the flag that fixes it, got: %v", err)
	}
}

// TestCadesLtCarriesRevocationValues checks the attribute OpenSSL calls
// id-smime-aa-ets-revocationValues, which is the one and only correct name.
func TestCadesLtCarriesRevocationValues(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	content, signer := cadesFixture(t)
	tsa := newLocalTSA(t)

	signed, err := infrastructure.NewCadesSigner(tsa).SignCades(context.Background(),
		application.CadesRequest{
			Content:         content,
			Signer:          signer,
			Level:           signingdomain.LT,
			TimestampURL:    "http://tsa.example.invalid",
			EmbedRevocation: true,
		})
	if err != nil {
		t.Fatalf("sign CAdES-LT: %v", err)
	}

	path := filepath.Join(t.TempDir(), "lt.p7m")
	if err := os.WriteFile(path, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	output := runAsn1Parse(t, path)
	if !strings.Contains(output, "revocationValues") {
		t.Errorf("the container carries no revocationValues attribute:\n%s", output)
	}
	// The neighbouring OID means "certificateValues"; carrying OCSP responses
	// under that name is worse than failing, because it looks correct.
	if strings.Contains(output, "certValues") {
		t.Error("the container mislabels its revocation material as certValues")
	}
}

// TestCadesLtStillVerifiesWithOpenSSL: adding unsigned attributes must not touch
// the signature they sit beside.
func TestCadesLtStillVerifiesWithOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	content, signer := cadesFixture(t)
	tsa := newLocalTSA(t)

	signed, err := infrastructure.NewCadesSigner(tsa).SignCades(context.Background(),
		application.CadesRequest{
			Content:         content,
			Signer:          signer,
			Level:           signingdomain.LT,
			TimestampURL:    "http://tsa.example.invalid",
			EmbedRevocation: true,
		})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	directory := t.TempDir()
	container := filepath.Join(directory, "lt.p7m")
	if err := os.WriteFile(container, signed, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The fixture's CA issues the signing certificate, so it is the anchor.
	keyPair, err := infrastructure.LoadKeyPair(signer)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	anchor := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(anchor, pemEncodeCertificate(keyPair.Chain[0]), 0o644); err != nil {
		t.Fatalf("write anchor: %v", err)
	}

	command := exec.Command("openssl", "cms", "-verify", "-inform", "DER",
		"-in", container, "-CAfile", anchor, "-purpose", "any", "-cades", "-out", os.DevNull)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("the CAdES-LT container does not verify: %v\n%s", err, output)
	}
}

// TestCadesLtaAddsTheArchiveTimeStamp: LTA is LT plus a token over everything.
func TestCadesLtaAddsTheArchiveTimeStamp(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}

	content, signer := cadesFixture(t)
	tsa := newLocalTSA(t)

	lt, err := infrastructure.NewCadesSigner(tsa).SignCades(context.Background(),
		application.CadesRequest{
			Content: content, Signer: signer, Level: signingdomain.LT,
			TimestampURL: "http://tsa.example.invalid", EmbedRevocation: true,
		})
	if err != nil {
		t.Fatalf("sign LT: %v", err)
	}

	lta, err := infrastructure.NewCadesSigner(tsa).SignCades(context.Background(),
		application.CadesRequest{
			Content: content, Signer: signer, Level: signingdomain.LTA,
			TimestampURL: "http://tsa.example.invalid", EmbedRevocation: true,
		})
	if err != nil {
		t.Fatalf("sign LTA: %v", err)
	}

	if len(lta) <= len(lt) {
		t.Fatalf("LTA (%d bytes) is not larger than LT (%d bytes): no archive timestamp was added",
			len(lta), len(lt))
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "lta.p7m")
	if err := os.WriteFile(path, lta, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	output := runAsn1Parse(t, path)
	// archive-time-stamp-v3 and, in its token, ats-hash-index-v3: openssl's
	// names for 0.4.0.1733.2.4 and 0.4.0.19122.1.5.
	if !strings.Contains(output, "id-aa-ets-archiveTimestampV3") || !strings.Contains(output, "id-aa-ATSHashIndex-v3") {
		t.Errorf("the container carries no archive timestamp:\n%s", output)
	}

	// The archive timestamp must come after the revocation material: it covers it.
	revocationAt := strings.Index(output, "revocationValues")
	archiveAt := strings.Index(output, "id-aa-ets-archiveTimestampV3")
	if revocationAt < 0 || archiveAt < revocationAt {
		t.Error("the archive timestamp must be written after the revocation material it covers")
	}
}

// TestCadesBesAndTAreUnchanged guards the boundary: neither carries revocation.
func TestCadesBesAndTAreUnchanged(t *testing.T) {
	content, signer := cadesFixture(t)

	for _, level := range []signingdomain.Level{signingdomain.BES, signingdomain.T} {
		signed, err := infrastructure.NewCadesSigner(newLocalTSA(t)).SignCades(context.Background(),
			application.CadesRequest{
				Content: content, Signer: signer, Level: level,
				TimestampURL: "http://tsa.example.invalid",
			})
		if err != nil {
			t.Fatalf("%s: %v", level, err)
		}
		if bytes.Contains(signed, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x24}) {
			t.Errorf("%s carries a revocationValues attribute it should not have", level)
		}
	}
}

// runAsn1Parse dumps a DER file through OpenSSL's parser.
func runAsn1Parse(t *testing.T, path string) string {
	t.Helper()

	command := exec.Command("openssl", "asn1parse", "-inform", "DER", "-in", path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse: %v\n%s", err, output)
	}
	return string(output)
}

// TestACadesArchiveTimestampSealsWhatEN319122Says: the archive-time-stamp-v3
// covers the content, the SignerInfo and the hash index of the
// certificates, revocation values and unsigned attributes (EN 319 122-1,
// 5.5.2 and 5.5.3), and the verifier recomputes it. A token over the
// container's DER, how trebaruna sealed it before 0.67.1, proves nothing;
// a hash index listing an element the signature lost does not hold.
func TestACadesArchiveTimestampSealsWhatEN319122Says(t *testing.T) {
	content, signer := cadesFixture(t)
	authority := newLocalTSA(t)
	lta, err := infrastructure.NewCadesSigner(authority).SignCades(context.Background(), application.CadesRequest{
		Content: content, Signer: signer, Level: signingdomain.LTA,
		TimestampURL: "http://tsa.example.invalid", EmbedRevocation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if finding := archiveFinding(t, lta); finding != "timestamp.archival" {
		t.Errorf("a trebaruna CAdES-LTA: %q", finding)
	}

	lt, err := infrastructure.NewCadesSigner(authority).SignCades(context.Background(), application.CadesRequest{
		Content: content, Signer: signer, Level: signingdomain.LT,
		TimestampURL: "http://tsa.example.invalid", EmbedRevocation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	whole := sha256.Sum256(lt)
	response, err := authority.Token(context.Background(), whole[:], "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := cms.ExtractToken(response)
	if err != nil {
		t.Fatal(err)
	}
	_, index, err := cms.ArchiveTimeStampV3Input(lt, 0, content, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	overTheContainer, err := cms.WithArchiveTimeStampV3(lt, 0, token, index)
	if err != nil {
		t.Fatal(err)
	}
	if finding := archiveFinding(t, overTheContainer); finding != "timestamp.archive_unbound" {
		t.Errorf("a token over the container's DER: %q", finding)
	}

	_, current, err := cms.ArchiveTimeStampV3Input(lta, 0, content, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := cms.HashIndexHolds(current, index); !errors.Is(err, cms.ErrArchiveMismatch) {
		t.Errorf("an index listing the archive timestamp the signature no longer has: %v", err)
	}
}

// archiveFinding verifies an envelope and returns its archive finding.
func archiveFinding(t *testing.T, envelope []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lta.p7m")
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewCadesVerifier().Extract(path)
	if err != nil || len(reports) != 1 {
		t.Fatalf("%v %v", reports, err)
	}
	for _, finding := range reports[0].Findings {
		if strings.HasPrefix(finding.Code, "timestamp.archiv") {
			return finding.Code
		}
	}
	return ""
}

// TestAddedSignaturesTakeLevelsLTAndLTA: a parallel signature and
// counter-signatures carry their chain's revocation values (LT) and, at
// LTA, an archive timestamp seals the signature added, or each signature
// that took counter-signatures. The verifier reads every signature intact
// and each archive timestamp bound; openssl verifies the envelope.
func TestAddedSignaturesTakeLevelsLTAndLTA(t *testing.T) {
	content, signer := cadesFixture(t)
	authority := newLocalTSA(t)
	sign := func(request application.CadesRequest) []byte {
		t.Helper()
		request.Signer, request.TimestampURL, request.EmbedRevocation = signer, "http://tsa.example.invalid", true
		signed, err := infrastructure.NewCadesSigner(authority).SignCades(context.Background(), request)
		if err != nil {
			t.Fatalf("%+v: %v", request.Level, err)
		}
		return signed
	}
	original := sign(application.CadesRequest{Content: content, Level: signingdomain.BES})
	revocationValues := []byte{0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x18}

	for name, request := range map[string]application.CadesRequest{
		"a parallel signature": {Content: original, Cosign: true},
		"counter-signatures":   {Content: original, Countersign: "leaves"},
	} {
		lt := request
		lt.Level = signingdomain.LT
		withRevocation := sign(lt)
		if bytes.Count(withRevocation, revocationValues) != 1 {
			t.Errorf("%s at LT: %d revocationValues, want the added signature's one", name, bytes.Count(withRevocation, revocationValues))
		}

		lta := request
		lta.Level = signingdomain.LTA
		archived := sign(lta)
		path := filepath.Join(t.TempDir(), "added.p7m")
		if err := os.WriteFile(path, archived, 0o600); err != nil {
			t.Fatal(err)
		}
		reports, err := verificationinfra.NewCadesVerifier().Extract(path)
		if err != nil || len(reports) != 2 {
			t.Fatalf("%s: %v %v", name, reports, err)
		}
		archives := 0
		for _, report := range reports {
			if report.Integrity != verificationdomain.StatusGood {
				t.Errorf("%s: %s is %s", name, report.FieldName, report.Integrity)
			}
			for _, finding := range report.Findings {
				switch finding.Code {
				case "timestamp.archival":
					archives++
				case "timestamp.archive_unbound":
					t.Errorf("%s: %s: %s", name, report.FieldName, finding.Detail)
				}
			}
		}
		if archives != 1 {
			t.Errorf("%s: %d archive timestamps, want 1", name, archives)
		}
		if output, err := exec.Command("openssl", "cms", "-verify", "-inform", "DER", "-in", path, "-noverify", "-out", os.DevNull).CombinedOutput(); err != nil {
			t.Errorf("%s: openssl: %v\n%s", name, err, output)
		}
	}
}
