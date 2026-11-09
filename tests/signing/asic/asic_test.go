package asic_test

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/asic"
)

// TestTheMediaTypeComesFirstAndUncompressed: readers key on the first bytes.
func TestTheMediaTypeComesFirstAndUncompressed(t *testing.T) {
	container, err := asic.Write("application/vnd.etsi.asic-s+zip", []asic.Entry{
		{Name: "informe.pdf", Content: []byte("%PDF")},
		{Name: "META-INF/signature.p7s", Content: []byte{0x30}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(container[30:], []byte("mimetypeapplication/vnd.etsi.asic-s+zip")) {
		t.Errorf("the first entry must be the stored media type: %q", container[:80])
	}
	archive, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatal(err)
	}
	if archive.File[0].Method != zip.Store || archive.Comment != "mimetype=application/vnd.etsi.asic-s+zip" {
		t.Errorf("method %d, comment %q", archive.File[0].Method, archive.Comment)
	}
	reader, _ := archive.File[2].Open()
	content, _ := io.ReadAll(reader)
	if archive.File[2].Name != "META-INF/signature.p7s" || !bytes.Equal(content, []byte{0x30}) {
		t.Errorf("entry %s = %x", archive.File[2].Name, content)
	}
}

// TestNamesThatLeaveTheContainerAreRefused, and a name twice.
func TestNamesThatLeaveTheContainerAreRefused(t *testing.T) {
	for _, name := range []string{"../x", "/etc/x", "a/../../x", `a\\x`, "", "./x", "mimetype"} {
		if _, err := asic.Write("application/vnd.etsi.asic-s+zip", []asic.Entry{{Name: name, Content: []byte("x")}}); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	if _, err := asic.Write("application/vnd.etsi.asic-e+zip", []asic.Entry{{Name: "a"}, {Name: "a"}}); err == nil {
		t.Error("a name twice accepted")
	}
}
