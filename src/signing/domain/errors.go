package domain

import "errors"

// Domain errors. They are sentinel values so adapters can map them to
// exit codes and HTTP problem types without inspecting strings.
var (
	// ErrSignerWithoutName means the signer has no display name.
	ErrSignerWithoutName = errors.New("signer needs a name")

	// ErrSignerWithoutSource means no key source was declared.
	ErrSignerWithoutSource = errors.New("signer needs a key source: p12, pem, token or csc")

	// ErrP12WithoutContent means the P12 source carries no bytes.
	ErrP12WithoutContent = errors.New("p12 signer needs the file content")

	// ErrPEMWithoutContent means the PEM source carries no bytes.
	ErrPEMWithoutContent = errors.New("pem signer needs the certificate and key content")

	// ErrTokenWithoutModule means the PKCS#11 source has no module path.
	ErrTokenWithoutModule = errors.New("token signer needs the PKCS#11 module path")

	// ErrUnsupportedFormat means the document type cannot carry that format.
	ErrUnsupportedFormat = errors.New("signature format not applicable to this document")
)
