//go:build !cgo

package infrastructure

import (
	"fmt"

	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// openToken fails cleanly in builds without CGO.
func openToken(signer domain.Signer) (tokenContext, error) {
	return nil, fmt.Errorf(
		"this binary was built without CGO, so PKCS#11 smartcards are unavailable.\n" +
			"  use a P12 file, or rebuild with CGO_ENABLED=1 to enable smartcard support",
	)
}
