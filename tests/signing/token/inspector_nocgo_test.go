//go:build !cgo

package infrastructure_test

// The checks for a build that cannot reach a card at all.
//
// This build is not broken: it is the one that runs on a machine with no reader
// and no driver, and its job is to say so. A message that mentioned a module
// path would be a lie, because nothing was ever loaded.

import (
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// TestTokenBuildSaysItCannotUseACard is the whole contract of the no-cgo build.
//
// The binary is static and portable, and a portable binary cannot dlopen a
// PKCS#11 library. Saying that plainly is what stops the failure from reading
// as "the card is broken".
func TestTokenBuildSaysItCannotUseACard(t *testing.T) {
	inspector := infrastructure.TokenInspector{Module: "/nonexistent/module.so"}
	_, err := inspector.Inspect()
	if err == nil {
		t.Fatal("a build without cgo must not report that it can use a card")
	}
	if !strings.Contains(err.Error(), "smartcard") {
		t.Errorf("the error must say why the build cannot use a card: %v", err)
	}
}
