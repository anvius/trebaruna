package domain

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrInvalidContentDigest marks a digest that cannot be signed as given.
var ErrInvalidContentDigest = errors.New("invalid content digest")

// ContentDigest is the digest of a document signed without the document:
// a site computed it and sent only that (afirma:// precalculatedHashAlgorithm).
// A signature over it cannot carry the document, so it is detached.
type ContentDigest struct {
	algorithm string
	value     []byte
}

// NewContentDigest takes the algorithm as SHA-256, SHA256 or its XML URI and
// the digest, which must have that algorithm's length. SHA-1 is refused: it
// is broken for signatures, and a signature over a SHA-1 digest is worth no
// more than the digest.
func NewContentDigest(algorithm string, value []byte) (ContentDigest, error) {
	name, known := digestName(algorithm)
	switch {
	case !known:
		return ContentDigest{}, fmt.Errorf("%w: unknown digest algorithm %q", ErrInvalidContentDigest, algorithm)
	case name == "SHA1":
		return ContentDigest{}, fmt.Errorf("%w: SHA-1 digests are not signed, SHA-1 is broken for signatures", ErrInvalidContentDigest)
	case len(value) != digestSizes[name]:
		return ContentDigest{}, fmt.Errorf("%w: a %s digest has %d bytes, this one %d", ErrInvalidContentDigest, name, digestSizes[name], len(value))
	}
	return ContentDigest{algorithm: name, value: bytes.Clone(value)}, nil
}

// IsZero reports no digest: the document itself is signed.
func (d ContentDigest) IsZero() bool { return d.algorithm == "" }

// Algorithm is SHA256, SHA384 or SHA512.
func (d ContentDigest) Algorithm() string { return d.algorithm }

// Value is the digest.
func (d ContentDigest) Value() []byte { return bytes.Clone(d.value) }
