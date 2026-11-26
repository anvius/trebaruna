//go:build !cgo

package localtls

import "crypto/x509"

// Without cgo there is no PKCS#11 library to open a store with: every store
// reads as one that cannot be checked, and nothing is written.

func available() bool {
	return false
}

func hasRoot(string) (Presence, error) {
	return Absent, ErrNoNSS
}

func writeRoot(string, *x509.Certificate) error {
	return ErrNoNSS
}

func removeRoot(string) error {
	return ErrNoNSS
}

func makeStore(string) error {
	return ErrNoNSS
}
