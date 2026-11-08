//go:build !cgo

package infrastructure

import (
	"fmt"
)

// inspectToken reports that this build cannot reach a card.
//
// The static build exists to be copied to a machine and run. A build without cgo
// cannot load a PKCS#11 library, and saying so plainly is better than failing
// with a linker error or, worse, appearing to work.
func inspectToken(module, pin string) ([]TokenSlot, error) {
	return nil, fmt.Errorf(
		"this build cannot use a smartcard: it was compiled without cgo\n" +
			"  use the token build: trebaruna-token")
}
