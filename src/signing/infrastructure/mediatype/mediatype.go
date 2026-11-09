// Package mediatype names a document's media type for the signatures and
// manifests that declare it (XAdES DataObjectFormat, an ASiC manifest's
// MimeType).
package mediatype

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"
)

// byExtension are the types sniffing gets wrong or too vague: an office
// document reads as a plain ZIP, an XML document without its declaration as
// text.
var byExtension = map[string]string{
	".xml":  "text/xml",
	".pdf":  "application/pdf",
	".txt":  "text/plain",
	".csv":  "text/csv",
	".json": "application/json",
	".html": "text/html",
	".htm":  "text/html",
	".odt":  "application/vnd.oasis.opendocument.text",
	".ods":  "application/vnd.oasis.opendocument.spreadsheet",
	".odp":  "application/vnd.oasis.opendocument.presentation",
	".odg":  "application/vnd.oasis.opendocument.graphics",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".doc":  "application/msword",
	".xls":  "application/vnd.ms-excel",
	".ppt":  "application/vnd.ms-powerpoint",
	".rtf":  "application/rtf",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".gif":  "image/gif",
	".tif":  "image/tiff",
	".tiff": "image/tiff",
	".svg":  "image/svg+xml",
	".zip":  "application/zip",
}

// Of is the media type of a document: by its name's extension when that is
// a known one, else sniffed from its bytes (an XML document known as such
// even without its declaration), without parameters.
func Of(name string, content []byte) string {
	if known, ok := byExtension[strings.ToLower(path.Ext(name))]; ok {
		return known
	}
	detected := http.DetectContentType(content)
	if semicolon := strings.Index(detected, ";"); semicolon >= 0 {
		detected = detected[:semicolon]
	}
	detected = strings.TrimSpace(detected)
	if detected == "text/plain" && isXML(content) {
		return "text/xml"
	}
	return detected
}

// isXML reports content whose first markup is an element and that reads as
// XML to its end.
func isXML(content []byte) bool {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(content, []byte("\xEF\xBB\xBF")), " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("<")) {
		return false
	}
	decoder := xml.NewDecoder(bytes.NewReader(trimmed))
	elements := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return elements > 0
		}
		if err != nil {
			return false
		}
		if _, ok := token.(xml.StartElement); ok {
			elements++
		}
	}
}
