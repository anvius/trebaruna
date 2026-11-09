package mediatype_test

import (
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/mediatype"
)

// TestADocumentIsNamedByItsExtensionThenItsBytes: the name decides when its
// extension is known; the bytes otherwise, an XML document without its
// declaration still XML.
func TestADocumentIsNamedByItsExtensionThenItsBytes(t *testing.T) {
	for _, check := range []struct{ name, content, want string }{
		{"factura.xml", "<Facturae/>", "text/xml"},
		{"FACTURA.XML", "no es XML", "text/xml"},
		{"memoria.odt", "PK\x03\x04", "application/vnd.oasis.opendocument.text"},
		{"informe.docx", "PK\x03\x04", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		{"plano.pdf", "x", "application/pdf"},
		{"", "%PDF-1.4\n", "application/pdf"},
		{"", "<?xml version=\"1.0\"?><a/>", "text/xml"},
		{"", "\xEF\xBB\xBF  <Facturae><a>1</a></Facturae>", "text/xml"},
		{"datos", "<factura><linea></factura>", "text/plain"},
		{"datos", "< no es XML", "text/plain"},
		{"datos", "acta\n", "text/plain"},
		{"datos.bin", "PK\x03\x04", "application/zip"},
		{"datos", "\x00\x01\x02", "application/octet-stream"},
	} {
		if got := mediatype.Of(check.name, []byte(check.content)); got != check.want {
			t.Errorf("%q %q: %s, want %s", check.name, check.content, got, check.want)
		}
	}
}
