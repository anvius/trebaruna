// Package dss writes the PDF Document Security Store that PAdES B-LT requires.
//
// ETSI EN 319 142-1 puts long-term validation material outside the signature, in
// a /DSS dictionary reachable from the document catalog. Adding it means an
// incremental update: new objects, a new cross-reference section, and a new
// trailer chained to the previous one. Nothing already written is modified, which
// is exactly what keeps the existing signatures valid.
//
// Why hand-written: pdfsign v1.0.0 has no /DSS writer. Its only revocation path
// is the Adobe 1.2.840.113583.1.1.8 attribute, which EN 319 142-1 forbids in
// PAdES, and its cross-reference writer is unexported. The structure below is
// small enough to write exactly, and it is checked against pdfsig and qpdf.
package dss

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"sort"

	"github.com/digitorus/pdf"
)

// Validation is the material to embed.
type Validation struct {
	// Certificates are the chain certificates, leaf first. The leaf is normally
	// already in the signature, but including it is harmless and some validators
	// expect the whole chain to be present.
	Certificates []*x509.Certificate
	// OCSPResponses are DER-encoded OCSP responses, each already validated.
	OCSPResponses [][]byte
	// CRLs are DER-encoded certificate revocation lists.
	CRLs [][]byte
	// VRI adds a per-signature entry so a validator can find the material for
	// one signature without scanning everything.
	VRI []VRIEntry
}

// VRIEntry associates validation material with one signature.
//
// EN 319 142-1 §6.5: the key is the uppercase hex SHA-1 of the signature's
// /Contents, which is how a validator locates the material for a given signature.
type VRIEntry struct {
	// Key is the uppercase hex digest of the signature value.
	Key string
	// Certificates, OCSPResponses and CRLs mirror Validation.
	Certificates  []*x509.Certificate
	OCSPResponses [][]byte
	CRLs          [][]byte
}

// writer accumulates objects for the incremental update.
type writer struct {
	// buffer holds the new bytes, starting at the end of the original file.
	buffer bytes.Buffer
	// base is the offset the buffer starts at.
	base int64
	// nextObject is the first free object number.
	nextObject uint32
	// entries records the new cross-reference entries in write order.
	entries []xrefEntry
}

// xrefEntry is one row of the cross-reference table.
type xrefEntry struct {
	object uint32
	offset int64
}

// addObject writes an object and returns its number.
func (w *writer) addObject(body []byte) uint32 {
	number := w.nextObject
	w.nextObject++

	w.entries = append(w.entries, xrefEntry{object: number, offset: w.base + int64(w.buffer.Len())})
	fmt.Fprintf(&w.buffer, "%d 0 obj\n", number)
	w.buffer.Write(body)
	w.buffer.WriteString("\nendobj\n")
	return number
}

// addStream writes a stream object with the given dictionary entries.
func (w *writer) addStream(dictionary string, content []byte) uint32 {
	body := fmt.Sprintf("<< %s /Length %d >>\nstream\n", dictionary, len(content))
	stream := append([]byte(body), content...)
	stream = append(stream, []byte("\nendstream")...)
	return w.addObject(stream)
}

// Append adds the /DSS dictionary to a signed PDF.
//
// It returns the new document. The original bytes are preserved byte for byte at
// the start: any signature over them keeps verifying, because its ByteRange is
// untouched.
func Append(original []byte, validation Validation) ([]byte, error) {
	if len(original) == 0 {
		return nil, fmt.Errorf("the document is empty")
	}
	if len(validation.Certificates) == 0 && len(validation.OCSPResponses) == 0 && len(validation.CRLs) == 0 {
		return nil, fmt.Errorf("no validation material to embed")
	}

	reader, err := pdf.NewReader(bytes.NewReader(original), int64(len(original)))
	if err != nil {
		return nil, fmt.Errorf("read the signed PDF: %w", err)
	}

	catalogReference, ok := catalogObjectNumber(reader)
	if !ok {
		return nil, fmt.Errorf("the trailer publishes no /Root reference; cannot attach /DSS")
	}

	w := &writer{base: int64(len(original)), nextObject: uint32(reader.XrefInformation.ItemCount)}

	// One array per material type, shared by the dictionary and the VRI entries.
	certObjects := map[int]uint32{}
	var certRefs []uint32
	for index, certificate := range validation.Certificates {
		certObjects[index] = w.addStream("", certificate.Raw)
	}
	for index := range validation.Certificates {
		certRefs = append(certRefs, certObjects[index])
	}

	var ocspRefs []uint32
	for _, response := range validation.OCSPResponses {
		ocspRefs = append(ocspRefs, w.addStream("", response))
	}

	var crlRefs []uint32
	for _, crl := range validation.CRLs {
		crlRefs = append(crlRefs, w.addStream("", crl))
	}

	// The VRI dictionary is optional per the standard but is what lets a
	// validator match material to one signature when several are present.
	vriRef := uint32(0)
	if len(validation.VRI) > 0 {
		vriRef = w.writeVRI(validation.VRI)
	}

	// /DSS itself.
	var dictionary bytes.Buffer
	dictionary.WriteString("<< /Type /DSS")
	if len(certRefs) > 0 {
		dictionary.WriteString(" /Certs [" + referenceList(certRefs) + "]")
	}
	if len(ocspRefs) > 0 {
		dictionary.WriteString(" /OCSPs [" + referenceList(ocspRefs) + "]")
	}
	if len(crlRefs) > 0 {
		dictionary.WriteString(" /CRLs [" + referenceList(crlRefs) + "]")
	}
	if vriRef != 0 {
		fmt.Fprintf(&dictionary, " /VRI << /%s %d 0 R >>", validation.VRI[0].Key, vriRef)
	}
	dictionary.WriteString(" >>")

	dssObject := w.addObject(dictionary.Bytes())

	// The catalog is rewritten as a new object with /DSS added. Rewriting rather
	// than patching keeps the original object intact, which matters because its
	// bytes may be inside a previous signature's range.
	if err := w.writeCatalog(reader, catalogReference, dssObject); err != nil {
		return nil, err
	}

	output, err := w.finish(original, reader)
	if err != nil {
		return nil, err
	}
	return output, nil
}

// writeVRI writes the /VRI dictionary for the given entries.
func (w *writer) writeVRI(entries []VRIEntry) uint32 {
	var body bytes.Buffer
	body.WriteString("<<")
	for _, entry := range entries {
		var certificateRefs, ocspRefs, crlRefs []uint32
		for _, certificate := range entry.Certificates {
			certificateRefs = append(certificateRefs, w.addStream("", certificate.Raw))
		}
		for _, response := range entry.OCSPResponses {
			ocspRefs = append(ocspRefs, w.addStream("", response))
		}
		for _, crl := range entry.CRLs {
			crlRefs = append(crlRefs, w.addStream("", crl))
		}

		fmt.Fprintf(&body, " /%s <<", entry.Key)
		if len(certificateRefs) > 0 {
			body.WriteString(" /Cert [" + referenceList(certificateRefs) + "]")
		}
		if len(ocspRefs) > 0 {
			body.WriteString(" /OCSP [" + referenceList(ocspRefs) + "]")
		}
		if len(crlRefs) > 0 {
			body.WriteString(" /CRL [" + referenceList(crlRefs) + "]")
		}
		body.WriteString(" >>")
	}
	body.WriteString(" >>")
	return w.addObject(body.Bytes())
}

// writeCatalog emits a copy of the catalog with /DSS pointing at the store.
//
// The catalog is re-serialised from the parsed dictionary and the new key is
// appended before the closing bracket. Rewriting the object rather than patching
// it in place keeps the original bytes untouched, which matters because they may
// fall inside a previous signature's ByteRange.
func (w *writer) writeCatalog(reader *pdf.Reader, catalogNumber uint32, dssObject uint32) error {
	catalog := reader.Trailer().Key("Root")
	if catalog.Kind() != pdf.Dict {
		return fmt.Errorf("the trailer /Root is not a dictionary")
	}

	serialised := catalog.String()
	if len(serialised) < 2 || serialised[len(serialised)-2:] != ">>" {
		return fmt.Errorf("cannot re-serialise the catalog")
	}

	body := serialised[:len(serialised)-2] + fmt.Sprintf(" /DSS %d 0 R >>", dssObject)
	w.addObjectAt([]byte(body), catalogNumber)
	return nil
}

// addObjectAt rewrites an existing object number in the new section.
//
// An incremental update may redefine an existing object: the newest
// cross-reference entry wins, and the old bytes stay in the file untouched.
func (w *writer) addObjectAt(body []byte, number uint32) {
	w.entries = append(w.entries, xrefEntry{object: number, offset: w.base + int64(w.buffer.Len())})
	fmt.Fprintf(&w.buffer, "%d 0 obj\n", number)
	w.buffer.Write(body)
	w.buffer.WriteString("\nendobj\n")
}

// finish writes the cross-reference section and the trailer.
func (w *writer) finish(original []byte, reader *pdf.Reader) ([]byte, error) {
	xrefOffset := w.base + int64(w.buffer.Len())

	// Entries must be sorted by object number, which is what a reference table
	// requires; a set of runs is the compact form the format allows.
	sort.Slice(w.entries, func(i, j int) bool { return w.entries[i].object < w.entries[j].object })

	var xref bytes.Buffer
	xref.WriteString("xref\n")
	for start := 0; start < len(w.entries); {
		end := start
		for end+1 < len(w.entries) && w.entries[end+1].object == w.entries[end].object+1 {
			end++
		}
		fmt.Fprintf(&xref, "%d %d\n", w.entries[start].object, end-start+1)
		for index := start; index <= end; index++ {
			fmt.Fprintf(&xref, "%010d 00000 n \n", w.entries[index].offset)
		}
		start = end + 1
	}

	previousOffset, err := previousStartXref(original)
	if err != nil {
		return nil, err
	}

	var trailer bytes.Buffer
	fmt.Fprintf(&trailer, "trailer\n<< /Size %d", w.nextObject)
	if id := reader.Trailer().Key("ID"); id.Kind() != pdf.Null {
		trailer.WriteString(" /ID ")
		trailer.WriteString(id.String())
	}
	rootNumber, _ := catalogObjectNumber(reader)
	fmt.Fprintf(&trailer, " /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		rootNumber, previousOffset, xrefOffset)

	output := make([]byte, 0, len(original)+w.buffer.Len()+xref.Len()+trailer.Len())
	output = append(output, original...)
	output = append(output, w.buffer.Bytes()...)
	output = append(output, xref.Bytes()...)
	output = append(output, trailer.Bytes()...)
	return output, nil
}

// catalogObjectNumber returns the object number the trailer's /Root points at.
func catalogObjectNumber(reader *pdf.Reader) (uint32, bool) {
	root := reader.Trailer().Key("Root")
	if root.Kind() != pdf.Dict {
		return 0, false
	}

	// Key resolves the reference but keeps it, so GetPtr reports the object the
	// trailer actually pointed at rather than the dictionary it came from.
	if pointer := root.GetPtr(); pointer.GetID() > 0 {
		return pointer.GetID(), true
	}

	// A direct dictionary (no indirection) is legal but rare. Fall back to
	// searching for the single /Type /Catalog object.
	for number := uint32(1); number <= uint32(reader.XrefInformation.ItemCount); number++ {
		value, err := reader.GetObject(number)
		if err != nil || value.Kind() != pdf.Dict {
			continue
		}
		if value.Key("Type").Name() == "Catalog" {
			return number, true
		}
	}
	return 0, false
}

// previousStartXref reads the startxref value of the last section.
//
// Chaining with /Prev is what turns a plain append into a valid update: without
// it the new trailer hides the old objects instead of extending them.
func previousStartXref(content []byte) (int64, error) {
	marker := []byte("startxref")
	index := bytes.LastIndex(content, marker)
	if index < 0 {
		return 0, fmt.Errorf("the document has no startxref")
	}

	rest := content[index+len(marker):]
	var offset int64
	digits := 0
	for _, character := range rest {
		if character >= '0' && character <= '9' {
			offset = offset*10 + int64(character-'0')
			digits++
			continue
		}
		if digits > 0 {
			return offset, nil
		}
		if character == ' ' || character == '\n' || character == '\r' || character == '\t' {
			continue
		}
		return 0, fmt.Errorf("malformed startxref")
	}
	if digits == 0 {
		return 0, fmt.Errorf("startxref carries no offset")
	}
	return offset, nil
}

// referenceList renders object references for an array.
func referenceList(numbers []uint32) string {
	var builder bytes.Buffer
	for index, number := range numbers {
		if index > 0 {
			builder.WriteString(" ")
		}
		fmt.Fprintf(&builder, "%d 0 R", number)
	}
	return builder.String()
}
