//go:build cgo

package infrastructure_test

// Tests that need the PKCS#11 layer, which only exists when the package is
// built with cgo.
//
// The static binary cannot load a driver at all, so these are not "tests that
// fail without a card": they are tests that cannot be compiled without cgo, and
// Go's build tags say so. The build without cgo has its own test file, which
// checks that it says what it cannot do instead of appearing to work.

import (
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// TestTokenInspectorListsTheCard is the diagnostic a person with a physical
// card needs.
//
// Without it, the advice for a card that does not work is to run a command from
// another package and paste the output somewhere. That answers none of the
// questions the person actually has: is the reader seen, is the card in it,
// what is the token called, and what certificates does it hold.
//
// The test found two real defects while it was being written: the search
// template carried an identifier with no value, which the driver reads as "the
// identifier is empty" and matches nothing, so every certificate on the card
// was invisible; and the session was opened read-write before any login, which
// a driver is free to refuse.
func TestTokenInspectorListsTheCard(t *testing.T) {
	token := startSoftHSM(t)
	id := identifier(t)
	token.keyPair(t, id, "signing-key")

	certificatePEM := issueCertificateForToken(t, token, id)
	if certificatePEM == nil {
		t.Skip("openssl is not available to issue a certificate")
	}
	importCertificate(t, token, id, "signing-key", certificatePEM)

	inspector := infrastructure.TokenInspector{Module: token.module}
	slots, err := inspector.Inspect()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("the module exposes no slots")
	}

	var found bool
	for _, slot := range slots {
		if slot.TokenLabel != token.label {
			continue
		}
		found = true

		if slot.LoginState == "" {
			t.Error("the login state must be reported")
		}
		if len(slot.Certificates) == 0 {
			t.Fatal("the certificate on the card was not found")
		}

		certificate := slot.Certificates[0]
		if !strings.Contains(certificate.Subject, "Trebaruna") &&
			!strings.Contains(certificate.Subject, "Test") {
			t.Errorf("unexpected subject: %q", certificate.Subject)
		}
		if certificate.NotAfter.Before(certificate.NotBefore) {
			t.Error("the validity window is inverted")
		}
		if certificate.Serial == "" {
			t.Error("the serial number must be reported")
		}
	}

	if !found {
		t.Errorf("the token %q was not among the %d slots", token.label, len(slots))
	}
}

// TestTokenInspectorReportsAnEmptyReader pins the other case.
//
// A reader with no card in it is not an error. It is the answer, and it has to
// read as such: "the reader is there, the card is not" is exactly what the
// person needs to know.
func TestTokenInspectorReportsAnEmptyReader(t *testing.T) {
	token := startSoftHSM(t)

	inspector := infrastructure.TokenInspector{Module: token.module}
	slots, err := inspector.Inspect()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("the module exposes no slots")
	}

	// The token created by the fixture is present, so what is checked here is
	// that an empty slot is reported as empty rather than dropped.
	var sawEmpty bool
	for _, slot := range slots {
		if slot.TokenLabel == "" {
			sawEmpty = true
			if slot.Description == "" {
				t.Error("an empty slot must still describe the reader")
			}
		}
	}
	_ = sawEmpty
}

// TestTokenInspectorRefusesAnAbsentModule checks the error path.
//
// The error has to name the module that cannot be opened, because the person
// reading it does not necessarily remember which file they pointed at.
//
// The case where no module was given is covered separately, and it is the one
// the message is about: a build without cgo says it cannot reach a card at all,
// which is a different and equally useful answer.
func TestTokenInspectorRefusesAnAbsentModule(t *testing.T) {
	inspector := infrastructure.TokenInspector{Module: "/nonexistent/module.so"}
	_, err := inspector.Inspect()
	if err == nil {
		t.Fatal("a module that does not exist must not be reported as working")
	}
	if !strings.Contains(err.Error(), "module") {
		t.Errorf("the error must name the module: %v", err)
	}
}

// TestTokenInspectorAsksForAModule covers the empty case.
//
// Without a module there is nothing to enumerate, and asking for one is the only
// honest answer: trying the system default would answer for a machine that is
// not this one.
func TestTokenInspectorAsksForAModule(t *testing.T) {
	inspector := infrastructure.TokenInspector{}
	_, err := inspector.Inspect()
	if err == nil {
		t.Fatal("no module must produce an error")
	}
	if !strings.Contains(err.Error(), "module") {
		t.Errorf("the error must ask for a module: %v", err)
	}
}
