package domain

import "fmt"

// Container is an ASiC container (ETSI EN 319 162-1): a ZIP holding the
// signed documents and, under META-INF, the signatures over them.
type Container string

const (
	// NoContainer leaves the signature as a file of its own.
	NoContainer Container = ""
	// ASiCS holds one document and its signatures.
	ASiCS Container = "asic-s"
	// ASiCE holds several documents.
	ASiCE Container = "asic-e"
)

// ParseContainer reads a container from its external name: s or e.
func ParseContainer(raw string) (Container, error) {
	switch raw {
	case "":
		return NoContainer, nil
	case "s", "asic-s", "asics":
		return ASiCS, nil
	case "e", "asic-e", "asice":
		return ASiCE, nil
	}
	return NoContainer, fmt.Errorf("unknown container %q: use s (ASiC-S) or e (ASiC-E)", raw)
}

// MediaType is the content of the container's mimetype entry.
func (c Container) MediaType() string {
	if c == ASiCE {
		return "application/vnd.etsi.asic-e+zip"
	}
	return "application/vnd.etsi.asic-s+zip"
}

// Extension is the container's file suffix.
func (c Container) Extension() string {
	if c == ASiCE {
		return ".asice"
	}
	return ".asics"
}

// SignatureEntry is where a signature of the format goes in the container:
// META-INF/signature.p7s for CAdES, META-INF/signatures.xml for XML ones.
func (c Container) SignatureEntry(format Format) string {
	if format.IsXML() {
		return "META-INF/signatures.xml"
	}
	return "META-INF/signature.p7s"
}

// Holds reports whether the container can carry signatures of the format:
// PAdES signs inside the PDF and needs none.
func (c Container) Holds(format Format) bool {
	return format == Cades || format.IsXML()
}
