package integration_test

import (
	"bytes"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/tsd"
)

// indefinite rewrites the outermost SEQUENCE of a DER structure with an
// indefinite length, the BER form some tools write.
func indefinite(t *testing.T, der []byte) []byte {
	t.Helper()
	if der[0] != 0x30 {
		t.Fatal("not a sequence")
	}
	header := 2
	if der[1]&0x80 != 0 {
		header = 2 + int(der[1]&0x7f)
	}
	body := der[header:]
	return append(append([]byte{0x30, 0x80}, body...), 0x00, 0x00)
}

// TestTimeStampedDataReadsBERAsWellAsDER and keeps every field.
func TestTimeStampedDataReadsBERAsWellAsDER(t *testing.T) {
	token := []byte{0x30, 0x03, 0x02, 0x01, 0x07} // stands in for a TimeStampToken
	encoded, err := tsd.Encode([]byte("contenuto"), "atto.pdf", "application/pdf", token)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"DER": encoded, "BER": indefinite(t, encoded)} {
		if !tsd.Is(data) {
			t.Errorf("%s: not recognised", name)
			continue
		}
		document, err := tsd.Decode(data)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(document.Content) != "contenuto" || document.FileName != "atto.pdf" ||
			document.MediaType != "application/pdf" || document.HashProtected || !bytes.Equal(document.Tokens[0], token) {
			t.Errorf("%s: decoded %+v", name, document)
		}
		if !bytes.Equal(document.Covered(0), []byte("contenuto")) {
			t.Errorf("%s: the first token covers the content", name)
		}
	}
	if tsd.Is([]byte("not ASN.1")) {
		t.Error("random bytes are not time-stamped data")
	}
}
