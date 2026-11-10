// Package dss runs the European Commission's DSS library on a signed file,
// through DssJudge.java beside this file, and reads its verdict: one
// Signature per signature found, each with its timestamps and the errors
// DSS's AdES validation reported. It needs Java and DSS_LIB, a directory
// holding DSS's jars (see README.md); without them the calling test skips.
package dss

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Signature is what DSS said about one signature.
type Signature struct {
	ID, Indication, Subindication, Format string
	Intact, Valid, References             bool
	Timestamps                            []Timestamp
	Errors                                []string
}

// Timestamp is what DSS said about one of a signature's timestamps.
type Timestamp struct {
	Kind                   string
	Imprint, Intact, Valid bool
}

// withoutRevocation are the only complaints DSS may have about a signature
// that carries no revocation (levels B and T), validated offline.
var withoutRevocation = map[string]bool{
	"The certificate validation is not conclusive!": true,
	"No revocation data found for the certificate!": true,
}

// Passed reports a signature DSS accepted: TOTAL_PASSED, or, when offline
// is set (a level that embeds no revocation, checked with no network),
// left undecided for that reason alone.
func (s Signature) Passed(offline bool) bool {
	if s.Indication == "TOTAL_PASSED" {
		return true
	}
	undecided := offline && s.Indication == "INDETERMINATE" && len(s.Errors) > 0
	for _, complaint := range s.Errors {
		undecided = undecided && withoutRevocation[complaint]
	}
	return undecided
}

// Available reports whether DSS can run here: DSS_LIB set and Java found.
func Available() bool {
	_, err := exec.LookPath("java")
	return os.Getenv("DSS_LIB") != "" && err == nil
}

// Judge has DSS validate content, written as name, with the detached
// documents it signs and the anchors given besides the self-signed
// certificates the file carries.
func Judge(t testing.TB, name string, content []byte, detached map[string][]byte, anchors ...*x509.Certificate) []Signature {
	t.Helper()
	library := os.Getenv("DSS_LIB")
	if library == "" {
		t.Skip("DSS_LIB does not name EU DSS's jars")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("java is not available")
	}
	_, here, _, _ := runtime.Caller(0)
	judge := filepath.Join(filepath.Dir(here), "DssJudge.java")
	directory := t.TempDir()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
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
	var signatures []Signature
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 8 && fields[0] == "signature":
			signatures = append(signatures, Signature{ID: fields[1], Indication: fields[2], Subindication: fields[3], Format: fields[4],
				Intact: fields[5] == "intact=true", Valid: fields[6] == "valid=true", References: fields[7] == "references=true"})
		case len(fields) > 2 && fields[0] == "error" && len(signatures) > 0:
			last := &signatures[len(signatures)-1]
			last.Errors = append(last.Errors, strings.Join(fields[2:], " "))
		case len(fields) == 6 && fields[0] == "timestamp" && len(signatures) > 0:
			last := &signatures[len(signatures)-1]
			last.Timestamps = append(last.Timestamps, Timestamp{Kind: fields[2],
				Imprint: fields[3] == "imprint=true", Intact: fields[4] == "intact=true", Valid: fields[5] == "valid=true"})
		}
	}
	if len(signatures) == 0 {
		t.Fatalf("DSS found no signature:\n%s", output)
	}
	return signatures
}

// Judged checks DSS's verdict on signatures: as many as written, each one
// whole and accepted (see Passed), the first at the level meant, and
// timestamps of the kinds expected, all sealing what they say.
func Judged(t testing.TB, signatures []Signature, count int, format string, offline bool, kinds ...string) {
	t.Helper()
	if len(signatures) != count {
		t.Errorf("DSS found %d signatures, want %d: %+v", len(signatures), count, signatures)
	}
	if len(signatures) > 0 && signatures[0].Format != format {
		t.Errorf("DSS reads %s, want %s", signatures[0].Format, format)
	}
	found := map[string]bool{}
	for _, signature := range signatures {
		if !signature.Intact || !signature.Valid || !signature.References {
			t.Errorf("DSS: signature %s intact %v, valid %v, references %v", signature.ID, signature.Intact, signature.Valid, signature.References)
		}
		if !signature.Passed(offline) {
			t.Errorf("DSS: signature %s is %s (%s): %v", signature.ID, signature.Indication, signature.Subindication, signature.Errors)
		}
		for _, timestamp := range signature.Timestamps {
			found[timestamp.Kind] = true
			if !timestamp.Imprint || !timestamp.Intact || !timestamp.Valid {
				t.Errorf("DSS: %s of %s: imprint %v, intact %v, valid %v", timestamp.Kind, signature.ID, timestamp.Imprint, timestamp.Intact, timestamp.Valid)
			}
		}
	}
	for _, kind := range kinds {
		if !found[kind] {
			t.Errorf("DSS found no %s: %+v", kind, signatures)
		}
	}
}
