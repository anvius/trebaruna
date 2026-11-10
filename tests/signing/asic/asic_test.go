package asic_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	// The mimetype's own header holds its CRC and sizes: no data descriptor
	// (flag bit 3), no extra field (EN 319 162-1, A.1).
	media := []byte("application/vnd.etsi.asic-s+zip")
	local := container[:30]
	if flags := binary.LittleEndian.Uint16(local[6:]); flags&0x8 != 0 {
		t.Errorf("the mimetype entry has a data descriptor (flags %#x)", flags)
	}
	if crc := binary.LittleEndian.Uint32(local[14:]); crc != crc32.ChecksumIEEE(media) {
		t.Errorf("the mimetype header's CRC is %#x", crc)
	}
	if compressed, size := binary.LittleEndian.Uint32(local[18:]), binary.LittleEndian.Uint32(local[22:]); compressed != uint32(len(media)) || size != compressed {
		t.Errorf("the mimetype header's sizes are %d and %d", compressed, size)
	}
	if extra := binary.LittleEndian.Uint16(local[28:]); extra != 0 {
		t.Errorf("the mimetype header has %d bytes of extra field", extra)
	}
	// Every entry is dated: a zero MS-DOS date has month 0.
	for _, file := range archive.File {
		if month := (file.ModifiedDate >> 5) & 0xF; month == 0 || file.Modified.Before(time.Now().Add(-time.Hour)) {
			t.Errorf("%s is dated %v (MS-DOS date %#x)", file.Name, file.Modified, file.ModifiedDate)
		}
	}
}

// TestJavaReadsTheContainerEntryByEntry: Java's ZipInputStream, as Java
// signing tools read an ASiC, refuses a stored entry with a data descriptor.
func TestJavaReadsTheContainerEntryByEntry(t *testing.T) {
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("no java to judge with")
	}
	container, err := asic.Write("application/vnd.etsi.asic-e+zip", []asic.Entry{
		{Name: "acta.txt", Content: []byte("acta\n")},
		{Name: "META-INF/signatures001.xml", Content: []byte("<x/>")},
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "expediente.asice")
	source := filepath.Join(directory, "ReadEntries.java")
	if err := os.WriteFile(path, container, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(readEntries), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(java, source, path).CombinedOutput()
	if err != nil || string(output) != "mimetype 31\nacta.txt 5\nMETA-INF/signatures001.xml 4\n" {
		t.Errorf("java: %v\n%s", err, output)
	}
}

// readEntries prints each entry's name and size as ZipInputStream reads it.
const readEntries = `import java.io.FileInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ReadEntries {
    public static void main(String[] args) throws Exception {
        try (ZipInputStream in = new ZipInputStream(new FileInputStream(args[0]))) {
            for (ZipEntry entry; (entry = in.getNextEntry()) != null; ) {
                System.out.println(entry.getName() + " " + in.readAllBytes().length);
            }
        }
    }
}
`

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

// TestTheManifestListsEveryDocumentWithItsDigest, the signature it belongs
// to first.
func TestTheManifestListsEveryDocumentWithItsDigest(t *testing.T) {
	manifest, err := asic.Manifest("META-INF/signature.p7s", []asic.Entry{
		{Name: "acta.txt", Content: []byte("acta\n")},
		{Name: "plano de obra.pdf", Content: []byte("%PDF-1.4\n")},
		{Name: "factura", Content: []byte("<Facturae><a>1</a></Facturae>")},
		{Name: "memoria.odt", Content: []byte("PK\x03\x04")},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(manifest)
	for _, expected := range []string{
		`<asic:SigReference URI="META-INF/signature.p7s" MimeType="application/pkcs7-signature"/>`,
		`<asic:DataObjectReference URI="acta.txt" MimeType="text/plain">`,
		`<asic:DataObjectReference URI="plano%20de%20obra.pdf" MimeType="application/pdf">`,
		// An XML document without its declaration is no plain text, nor an
		// office document a plain ZIP.
		`<asic:DataObjectReference URI="factura" MimeType="text/xml">`,
		`<asic:DataObjectReference URI="memoria.odt" MimeType="application/vnd.oasis.opendocument.text">`,
		`<ds:DigestValue>` + "XsU+tThjwjNG+k4uF2H3QVlDPcA/c0hx3GTYdZYabvs=" + `</ds:DigestValue>`,
	} {
		if !bytes.Contains(manifest, []byte(expected)) {
			t.Errorf("the manifest lacks %s:\n%s", expected, text)
		}
	}
}

// TestTheManifestOfASignatureIsTheOneThatNamesIt: by its SigReference,
// escaped or not, among other manifests and files.
func TestTheManifestOfASignatureIsTheOneThatNamesIt(t *testing.T) {
	documents := []asic.Entry{{Name: "acta.txt", Content: []byte("acta\n")}}
	first, _ := asic.Manifest("META-INF/signature001.p7s", documents)
	spaced, _ := asic.Manifest("META-INF/signature de juan.p7s", documents)
	entries := []asic.Entry{
		{Name: "acta.txt", Content: []byte("acta\n")},
		{Name: "ASiCManifest.xml", Content: first},
		{Name: "META-INF/ASiCManifest001.xml", Content: []byte("<x/>")},
		{Name: "META-INF/ASiCManifest002.xml", Content: spaced},
		{Name: "META-INF/ASiCManifest003.xml", Content: first},
	}
	if manifest, found := asic.ManifestOf("META-INF/signature001.p7s", entries); !found || manifest.Name != "META-INF/ASiCManifest003.xml" {
		t.Errorf("signature001: %q %v", manifest.Name, found)
	}
	if manifest, found := asic.ManifestOf("META-INF/signature de juan.p7s", entries); !found || manifest.Name != "META-INF/ASiCManifest002.xml" {
		t.Errorf("an escaped name: %q %v", manifest.Name, found)
	}
	if manifest, found := asic.ManifestOf("META-INF/signature004.p7s", entries); found {
		t.Errorf("no manifest names signature004: %q", manifest.Name)
	}
	for _, other := range []string{
		strings.Replace(string(first), "http://uri.etsi.org/02918/v1.2.1#", "urn:other", 1),
		`<asic:Other xmlns:asic="http://uri.etsi.org/02918/v1.2.1#"><asic:SigReference URI="META-INF/signature001.p7s"/></asic:Other>`,
		`<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#"><o:SigReference xmlns:o="urn:other" URI="META-INF/signature001.p7s"/></asic:ASiCManifest>`,
	} {
		if _, found := asic.ManifestOf("META-INF/signature001.p7s", []asic.Entry{{Name: "META-INF/ASiCManifest.xml", Content: []byte(other)}}); found {
			t.Errorf("not a manifest, taken: %s", other)
		}
	}
}
