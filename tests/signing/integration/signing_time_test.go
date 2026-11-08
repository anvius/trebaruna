package integration_test

// A signature carries two times: the /M entry a reader displays, and the moment
// the signature claims to have been made. They must be the same instant, and it
// must be the one the caller asked for. Otherwise a document signed at 10:00
// shows 10:05 in one place and 10:00 in another, and a timestamped signature
// ends up with an /M that disagrees with its own token.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// TestSignedPdfRecordsTheSigningMoment pins /M to the moment of signing.
//
// It cannot pin /M to an arbitrary past instant: pdfsign v1.0.0 writes /M from
// its own clock and its builder exposes no date setter, and /M sits inside the
// ByteRange, so rewriting it afterwards would invalidate the signature. What is
// asserted here is the contract that actually holds: a signature made now carries
// a time that is now, not a stale or invented one. Recorded as a gap in
// README.md, Known limits.
func TestSignedPdfRecordsTheSigningMoment(t *testing.T) {
	fixture := newFixture(t)
	document := writeBlankPDF(t, fixture.directory)

	original, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}

	signedAt := time.Now()

	keyMaterial := append(append([]byte{}, mustRead(t, fixture.certPath)...),
		mustRead(t, fixture.keyPath)...)
	signer, err := signingdomain.NewSigner("Fixture", signingdomain.FromPEM,
		signingdomain.WithKeyMaterial(keyMaterial))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	signed, err := infrastructure.NewPadesSigner(nil).SignPades(context.Background(), application.PadesRequest{
		Content:  original,
		Signer:   signer,
		Level:    signingdomain.BES,
		SignedAt: signedAt,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	written := filepath.Join(fixture.directory, "signed.pdf")
	if err := os.WriteFile(written, signed, 0o644); err != nil {
		t.Fatalf("write signed PDF: %v", err)
	}

	match := regexp.MustCompile(`/M\s*\(([^)]*)\)`).FindSubmatch(signed)
	if match == nil {
		t.Fatal("the signature has no /M entry; PAdES requires one")
	}

	// The entry carries a local offset (D:...+01'00'), so parse it rather than
	// comparing digit strings: the same instant has several valid spellings.
	recorded, err := parsePDFDate(string(match[1]))
	if err != nil {
		t.Fatalf("parse /M %q: %v", match[1], err)
	}
	if difference := recorded.Sub(signedAt); difference > 2*time.Minute || difference < -2*time.Minute {
		t.Errorf("/M = %s, want the moment of signing (%s)", recorded, signedAt)
	}
}

// mustRead reads a fixture file or fails.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// parsePDFDate reads a PDF date string: D:YYYYMMDDHHmmSSOHH'mm'.
func parsePDFDate(value string) (time.Time, error) {
	trimmed := strings.TrimPrefix(value, "D:")
	if len(trimmed) < 14 {
		return time.Time{}, fmt.Errorf("date %q is too short", value)
	}

	moment, err := time.Parse("20060102150405", trimmed[:14])
	if err != nil {
		return time.Time{}, err
	}

	rest := trimmed[14:]
	if len(rest) >= 3 && (rest[0] == '+' || rest[0] == '-') {
		hours := rest[1:3]
		minutes := "00"
		if len(rest) >= 6 {
			minutes = strings.ReplaceAll(rest[4:6], "'", "")
		}
		offset, err := time.ParseDuration(rest[0:1] + hours + "h" + minutes + "m")
		if err != nil {
			return time.Time{}, err
		}
		// The wall-clock fields are in the local zone, so subtract the offset to
		// recover the instant.
		return moment.Add(-offset), nil
	}
	return moment.UTC(), nil
}
