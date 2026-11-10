package integration_test

// The European Commission's DSS library as a common judge, independent of
// trebaruna: what trebaruna signs at its highest levels, CAdES with its
// archive-time-stamp-v3 (which only trebaruna had checked), XAdES, PAdES
// and an ASiC-E container, counter-signed or detached, is validated by
// DSS, offline, with the test authorities as anchors. Each signature must
// be intact and valid with every reference found and intact, each
// timestamp's imprint must match what it seals, and DSS must name the
// baseline level trebaruna meant to write.
//
// DSS_LIB names a directory holding DSS's jars and their dependencies
// (fetched with Maven from eu.europa.ec.joinup.sd-dss, see
// tests/support/dss/README.md); without it, or without Java, the test
// skips.

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// dssSignature is what DSS said about one signature.
type dssSignature struct {
	id, indication, subindication, format string
	intact, valid, references             bool
	timestamps                            []dssTimestamp
	errors                                []string
}

// dssTimestamp is what DSS said about one of a signature's timestamps.
type dssTimestamp struct {
	kind                   string
	imprint, intact, valid bool
}

// dssJudge has DSS validate the file and reads its verdict.
func dssJudge(t *testing.T, name string, content []byte, detached map[string][]byte, anchors ...*x509.Certificate) []dssSignature {
	t.Helper()
	library := os.Getenv("DSS_LIB")
	if library == "" {
		t.Skip("DSS_LIB does not name EU DSS's jars")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("java is not available")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	judge, err := filepath.Abs(filepath.Join("..", "..", "support", "dss", "DssJudge.java"))
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"-Dorg.slf4j.simpleLogger.defaultLogLevel=error", "-cp", filepath.Join(library, "*"), judge, path}
	for documentName, document := range detached {
		documentPath := filepath.Join(directory, documentName)
		if err := os.WriteFile(documentPath, document, 0o600); err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "detached="+documentPath)
	}
	for index, anchor := range anchors {
		anchorPath := filepath.Join(directory, fmt.Sprintf("anchor-%d.cer", index))
		if err := os.WriteFile(anchorPath, anchor.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "anchor="+anchorPath)
	}
	output, err := exec.Command("java", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("DSS: %v\n%s", err, output)
	}
	t.Logf("DSS on %s:\n%s", name, output)
	var signatures []dssSignature
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 8 && fields[0] == "signature":
			signatures = append(signatures, dssSignature{id: fields[1], indication: fields[2], subindication: fields[3], format: fields[4],
				intact: fields[5] == "intact=true", valid: fields[6] == "valid=true", references: fields[7] == "references=true"})
		case len(fields) > 2 && fields[0] == "error" && len(signatures) > 0:
			last := &signatures[len(signatures)-1]
			last.errors = append(last.errors, strings.Join(fields[2:], " "))
		case len(fields) == 6 && fields[0] == "timestamp" && len(signatures) > 0:
			last := &signatures[len(signatures)-1]
			last.timestamps = append(last.timestamps, dssTimestamp{kind: fields[2],
				imprint: fields[3] == "imprint=true", intact: fields[4] == "intact=true", valid: fields[5] == "valid=true"})
		}
	}
	if len(signatures) == 0 {
		t.Fatalf("DSS found no signature:\n%s", output)
	}
	return signatures
}

// withoutRevocation are the only complaints DSS may have about a signature
// that carries no revocation (level T), validated offline.
var withoutRevocation = map[string]bool{
	"The certificate validation is not conclusive!": true,
	"No revocation data found for the certificate!": true,
}

// judged checks DSS's verdict: as many signatures as written, each one
// whole, the first at the level meant, and the timestamps of the kinds
// expected all sealing what they say. Every signature passes, or, when
// offline is set (a level that embeds no revocation), is left undecided
// for that reason alone.
func judged(t *testing.T, signatures []dssSignature, count int, format string, offline bool, kinds ...string) {
	t.Helper()
	if len(signatures) != count {
		t.Errorf("DSS found %d signatures, want %d: %+v", len(signatures), count, signatures)
	}
	if signatures[0].format != format {
		t.Errorf("DSS reads %s, want %s", signatures[0].format, format)
	}
	found := map[string]bool{}
	for _, signature := range signatures {
		if !signature.intact || !signature.valid || !signature.references {
			t.Errorf("DSS: signature %s intact %v, valid %v, references %v", signature.id, signature.intact, signature.valid, signature.references)
		}
		undecidedOffline := offline && signature.indication == "INDETERMINATE" && len(signature.errors) > 0
		for _, complaint := range signature.errors {
			undecidedOffline = undecidedOffline && withoutRevocation[complaint]
		}
		if signature.indication != "TOTAL_PASSED" && !undecidedOffline {
			t.Errorf("DSS: signature %s is %s (%s): %v", signature.id, signature.indication, signature.subindication, signature.errors)
		}
		for _, timestamp := range signature.timestamps {
			found[timestamp.kind] = true
			if !timestamp.imprint || !timestamp.intact || !timestamp.valid {
				t.Errorf("DSS: %s of %s: imprint %v, intact %v, valid %v", timestamp.kind, signature.id, timestamp.imprint, timestamp.intact, timestamp.valid)
			}
		}
	}
	for _, kind := range kinds {
		if !found[kind] {
			t.Errorf("DSS found no %s: %+v", kind, signatures)
		}
	}
}

func TestDSSAcceptsWhatTrebarunaSigns(t *testing.T) {
	content, signer := ltaFixture(t)
	authority := newLocalTSAWithStatus(t)
	cades := func(request application.CadesRequest) []byte {
		t.Helper()
		request.Signer, request.TimestampURL, request.EmbedRevocation = signer, "http://tsa.example.invalid", true
		signed, err := infrastructure.NewCadesSigner(authority).SignCades(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}

	t.Run("CAdES-LTA", func(t *testing.T) {
		envelope := cades(application.CadesRequest{Content: content, Level: signingdomain.LTA})
		judged(t, dssJudge(t, "acta.pdf.p7m", envelope, nil, authority.ca), 1, "CAdES-BASELINE-LTA", false, "SIGNATURE_TIMESTAMP", "ARCHIVE_TIMESTAMP")
	})

	t.Run("CAdES-LTA counter-signed", func(t *testing.T) {
		original := cades(application.CadesRequest{Content: content, Level: signingdomain.BES})
		countersigned := cades(application.CadesRequest{Content: original, Level: signingdomain.LTA, Countersign: "leaves"})
		judged(t, dssJudge(t, "acta.pdf.p7m", countersigned, nil, authority.ca), 2, "CAdES-BASELINE-B", false, "SIGNATURE_TIMESTAMP", "ARCHIVE_TIMESTAMP")
	})

	t.Run("CAdES-T detached", func(t *testing.T) {
		envelope := cades(application.CadesRequest{Content: content, Detached: true, Level: signingdomain.T})
		judged(t, dssJudge(t, "acta.pdf.p7s", envelope, map[string][]byte{"acta.pdf": content}, authority.ca), 1, "CAdES-BASELINE-T", true, "SIGNATURE_TIMESTAMP")
	})

	t.Run("XAdES-LTA", func(t *testing.T) {
		request := buildXadesRequest(signer, []byte(`<fattura><numero>7</numero></fattura>`), false)
		request.Level, request.TimestampURL, request.EmbedRevocation = signingdomain.LTA, "http://tsa.example.invalid", true
		signed, err := infrastructure.NewXadesSigner(authority).SignXades(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		judged(t, dssJudge(t, "fattura.xml", signed, nil, authority.ca), 1, "XAdES-BASELINE-LTA", false, "SIGNATURE_TIMESTAMP", "ARCHIVE_TIMESTAMP")
	})

	t.Run("PAdES-LTA", func(t *testing.T) {
		signed, err := infrastructure.NewPadesSigner(authority).SignPades(context.Background(), application.PadesRequest{
			Content: content, Signer: signer, Level: signingdomain.LTA, SignedAt: timeNow(), TimestampURL: authority.url(t), EmbedRevocation: true})
		if err != nil {
			t.Fatal(err)
		}
		judged(t, dssJudge(t, "acta.pdf", signed, nil, authority.ca), 1, "PAdES-BASELINE-LTA", false, "SIGNATURE_TIMESTAMP", "DOCUMENT_TIMESTAMP")
	})

	t.Run("ASiC-E counter-signed at LTA", func(t *testing.T) {
		containers := infrastructure.AsicContainers{}
		documents := []application.ContainerEntry{{Name: "acta.txt", Content: []byte("acta\n")}, {Name: "plano.pdf", Content: content}}
		manifest, err := containers.Manifest("META-INF/signature001.p7s", documents)
		if err != nil {
			t.Fatal(err)
		}
		signature := cades(application.CadesRequest{Content: manifest, Detached: true, Level: signingdomain.BES})
		container, err := containers.WriteContainer(signingdomain.ASiCE, append(documents,
			application.ContainerEntry{Name: "META-INF/ASiCManifest001.xml", Content: manifest},
			application.ContainerEntry{Name: "META-INF/signature001.p7s", Content: signature}))
		if err != nil {
			t.Fatal(err)
		}
		countersigned, err := application.NewCountersignContainer(containers, infrastructure.NewCadesSigner(authority), infrastructure.NewXadesSigner(authority)).
			Execute(context.Background(), application.Request{Signer: signer, Level: signingdomain.LTA, EmbedRevocation: true,
				TimestampURL: "http://tsa.example.invalid", Countersign: "leaves"}, container)
		if err != nil {
			t.Fatal(err)
		}
		judged(t, dssJudge(t, "expediente.asice", countersigned.Content, nil, authority.ca), 2, "CAdES-BASELINE-B", false, "SIGNATURE_TIMESTAMP", "ARCHIVE_TIMESTAMP")
	})
}
