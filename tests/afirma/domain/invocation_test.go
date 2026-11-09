package domain_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
)

func failureCode(t *testing.T, err error) domain.FailureCode {
	t.Helper()
	var failure domain.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("not a failure: %v", err)
	}
	return failure.Code
}

// TestTheOperationIsTheHostMatchedLiterally (A.1).
func TestTheOperationIsTheHostMatchedLiterally(t *testing.T) {
	cases := map[string]domain.Operation{
		"afirma://sign?format=CAdES":         domain.Sign,
		"afirma://sign/?format=CAdES":        domain.Sign,
		"afirma://signandsave?cop=sign":      domain.SignAndSave,
		"afirma://countersign?target=tree":   domain.Countersign,
		"afirma://batch?jsonbatch=true":      domain.Batch,
		"afirma://selectcert?op=sign":        domain.SelectCert,
		"afirma://websocket?ports=63117&v=4": domain.WebSocket,
	}
	for uri, want := range cases {
		invocation, err := domain.ParseInvocation(uri)
		if err != nil || invocation.Operation != want {
			t.Errorf("%s: %v, %v", uri, invocation.Operation, err)
		}
	}
	refused := map[string]domain.FailureCode{
		"":                          domain.NullURI,
		"AFIRMA://sign?x=1":         domain.UnsupportedProtocol,
		"afirma://Sign?x=1":         domain.UnsupportedOperation,
		"afirma://?op=sign":         domain.UnsupportedOperation,
		"afirma://log?x=1":          domain.UnsupportedOperation,
		"afirma://sign":             domain.UnsupportedOperation,
		"https://example.org/?op=1": domain.UnsupportedProtocol,
	}
	for uri, want := range refused {
		if _, err := domain.ParseInvocation(uri); failureCode(t, err) != want {
			t.Errorf("%q: %v, want SAF_%02d", uri, err, want)
		}
	}
}

// TestTheQueryIsReadLikeAutoFirma (A.2): first "=", form decoding, last wins,
// pieces without a key ignored, the op parameter never selects.
func TestTheQueryIsReadLikeAutoFirma(t *testing.T) {
	invocation, err := domain.ParseInvocation("afirma://sign?op=batch&a=1&a=2&=x&flag&b=c%3Dd%26e&c=uno+dos&empty=")
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Operation != domain.Sign || invocation.Param("a") != "2" || invocation.Param("b") != "c=d&e" ||
		invocation.Param("c") != "uno dos" || !invocation.Has("empty") || invocation.Has("flag") {
		t.Errorf("parsed %+v", invocation)
	}
}

// TestDataAreResolvedInAutoFirmasOrder (A.3).
func TestDataAreResolvedInAutoFirmasOrder(t *testing.T) {
	if _, err := domain.ResolvePayload("file:///etc/passwd", false); failureCode(t, err) != domain.Params {
		t.Error("a local file must be refused")
	}
	remote, _ := domain.ResolvePayload("https://sede.example/doc.pdf", false)
	if remote.URL != "https://sede.example/doc.pdf" || len(remote.Bytes) != 0 {
		t.Errorf("a web address must be kept to show, not fetched: %+v", remote)
	}
	urlSafe, _ := domain.ResolvePayload(base64.URLEncoding.EncodeToString([]byte("\xfb\xff hola")), false)
	if string(urlSafe.Bytes) != "\xfb\xff hola" {
		t.Errorf("URL-safe Base64: %q", urlSafe.Bytes)
	}
	text, _ := domain.ResolvePayload("hola mundo!", false)
	if string(text.Bytes) != "hola mundo!" {
		t.Errorf("text: %q", text.Bytes)
	}
	unpadded, _ := domain.ResolvePayload("aG9sYQ", false)
	if string(unpadded.Bytes) != "aG9sYQ" {
		t.Errorf("unpadded Base64 is text to AutoFirma: %q", unpadded.Bytes)
	}
	var packed bytes.Buffer
	writer := gzip.NewWriter(&packed)
	writer.Write([]byte("comprimido"))
	writer.Close()
	gzipped, err := domain.ResolvePayload(base64.StdEncoding.EncodeToString(packed.Bytes()), true)
	if err != nil || string(gzipped.Bytes) != "comprimido" {
		t.Errorf("gzip: %q, %v", gzipped.Bytes, err)
	}
}

// TestPropertiesAreJavaProperties (A.7).
func TestPropertiesAreJavaProperties(t *testing.T) {
	text := "# comment\n! other\nmode=implicit\nfilters.1 = subject.rfc2254:(cn=A)\nkey\\:x:value\nlong=uno \\\n  dos\nunicode=\\u00f1u\\u00f1o\nspaced value here\n"
	properties := domain.ParseProperties(text)
	expected := map[string]string{
		"mode": "implicit", "filters.1": "subject.rfc2254:(cn=A)", "key:x": "value",
		"long": "uno dos", "unicode": "ñuño", "spaced": "value here",
	}
	for key, want := range expected {
		if properties[key] != want {
			t.Errorf("%s = %q, want %q", key, properties[key], want)
		}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("a=1\nb=2"))
	// A "+" a form decoder turned into a space still decodes.
	if decoded := domain.DecodeProperties(encoded); decoded["b"] != "2" {
		t.Errorf("decoded %v", decoded)
	}
}

// TestRequestsAreValidatedLikeAutoFirma (A.5, A.6, A.10).
func TestRequestsAreValidatedLikeAutoFirma(t *testing.T) {
	valid := "afirma://sign?ver=3&id=Ab12345678901234567x&key=12345678&stservlet=https%3A%2F%2Fsede.example%2FStorageService&format=CAdES&algorithm=SHA256withRSA&dat=aG9sYQ%3D%3D&aw=true&appname=SEDE"
	invocation, _ := domain.ParseInvocation(valid)
	request, err := domain.ReadSignRequest(invocation, true)
	if err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	if request.Format.Family != "cades" || request.Channel.Key != "12345678" || !request.Channel.ActiveWaiting ||
		request.Site() != "sede.example" || string(request.Data.Bytes) != "hola" || request.Version != 3 {
		t.Errorf("request %+v", request)
	}

	cases := map[string]domain.FailureCode{
		"afirma://sign?algorithm=SHA256withRSA":                                                            domain.Params,
		"afirma://sign?format=PGP&algorithm=SHA256withRSA":                                                 domain.UnsupportedFormat,
		"afirma://sign?format=CAdES&algorithm=sha256withrsa":                                               domain.Params,
		"afirma://sign?format=CAdES&algorithm=SHA256&ver=5":                                                domain.UnsupportedProcedure,
		"afirma://sign?format=CAdES&algorithm=SHA256&mcv=1.10":                                             domain.MinimumVersion,
		"afirma://sign?format=CAdES&algorithm=SHA256&key=123":                                              domain.Params,
		"afirma://sign?format=CAdES&algorithm=SHA256&id=abc&stservlet=http%3A%2F%2Flocalhost%2Fs":          domain.LocalAccessBlocked,
		"afirma://sign?format=CAdES&algorithm=SHA256&id=abc&stservlet=https%3A%2F%2Fs.example%2Fs%3Fa%3Db": domain.Params,
		"afirma://sign?format=CAdES&algorithm=SHA256&id=abc":                                               domain.Params,
		"afirma://sign?format=CAdES&algorithm=SHA256&id=a-b":                                               domain.Params,
		"afirma://signandsave?format=CAdES&algorithm=SHA256&cop=sing":                                      domain.SignatureFailed,
	}
	for uri, want := range cases {
		invocation, err := domain.ParseInvocation(uri)
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		if _, err := domain.ReadSignRequest(invocation, true); failureCode(t, err) != want {
			t.Errorf("%s: %v, want SAF_%02d", uri, err, want)
		}
	}
	older, _ := domain.ParseInvocation("afirma://sign?format=auto&algorithm=SHA1&mcv=1.8.2")
	if _, err := domain.ReadSignRequest(older, true); err != nil {
		t.Errorf("an older minimum version is satisfied: %v", err)
	}
}

// TestAnswersAreWrittenLikeAutoFirma (B.1, B.3).
func TestAnswersAreWrittenLikeAutoFirma(t *testing.T) {
	sign := domain.SignAnswer([]byte{0xfb, 0xff}, []byte("sig"), "atto.pdf", 3)
	if sign.Text() != "-_8=|c2ln|eyJmaWxlbmFtZSI6ICJhdHRvLnBkZiJ9" {
		t.Errorf("sign answer %q", sign.Text())
	}
	if domain.SignAnswer([]byte("c"), []byte("s"), "atto.pdf", 2).Text() != "Yw==|cw==" {
		t.Error("the file name is protocol 3 and later only")
	}
	if domain.BatchAnswer([]byte("r"), []byte("c"), false).Text() != "cg==" || domain.BatchAnswer([]byte("r"), []byte("c"), true).Text() != "cg==|Yw==" {
		t.Error("batch answers: result first, certificate on request")
	}
	if (domain.Failure{Code: domain.Params}).Answer() != "SAF_03: Error en los parámetros de entrada" {
		t.Error("generic failure text")
	}
	if (domain.Failure{Code: domain.SignatureFailed, Cause: "la tarjeta"}).Answer() != "SAF_09: la tarjeta" {
		t.Error("signature failures carry their cause")
	}
	if (domain.Failure{Code: domain.Params, Cause: "detail"}).Answer() != "SAF_03: Error en los parámetros de entrada" {
		t.Error("other failures keep the generic text")
	}
}

// TestEveryNameAutoFirmaSignsIsKnown: AOSignConstants' names, each to its
// family and phase; Externally Detached and SOAP are not signed.
func TestEveryNameAutoFirmaSignsIsKnown(t *testing.T) {
	for name, want := range map[string]domain.Format{
		"FacturaEtri":        {Family: "facturae", Triphase: true},
		"Adobe PDF TriPhase": {Family: "pades", Triphase: true},
		"PAdEStri":           {Family: "pades", Triphase: true},
		"PKCS1":              {Family: "none"},
		"PKCS#1":             {Family: "none"},
		"NONEtri":            {Family: "none", Triphase: true},
	} {
		got, err := domain.ParseFormat(name)
		if err != nil || got.Family != want.Family || got.Triphase != want.Triphase || got.Packaging != want.Packaging {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
	for _, name := range []string{"SOAP", "XMLDSig Externally Detached"} {
		if _, err := domain.ParseFormat(name); err == nil {
			t.Errorf("%s is not signed", name)
		}
	}
}

// TestReferencedDocumentsAreReadAsAutoFirmaReadsThem: uri with the data as
// its digest, or uri1/md1… for a manifest; the digest's algorithm from
// precalculatedHashAlgorithm, referencesDigestMethod or SHA-512.
func TestReferencedDocumentsAreReadAsAutoFirmaReadsThem(t *testing.T) {
	data := []byte("digest-bytes")
	single, err := domain.References(map[string]string{"format": "XAdES Externally Detached", "uri": "https://sede/doc.pdf", "mimeType": "application/pdf"}, data)
	if err != nil || len(single) != 1 || single[0].URI != "https://sede/doc.pdf" || string(single[0].Digest) != "digest-bytes" ||
		single[0].Algorithm != "SHA-512" || single[0].MimeType != "application/pdf" {
		t.Errorf("one document: %+v %v", single, err)
	}
	manifest, err := domain.References(map[string]string{"useManifest": "true", "referencesDigestMethod": "SHA-384",
		"uri1": "https://sede/a", "md1": base64.StdEncoding.EncodeToString([]byte("aaa")), "mimeType1": "text/plain",
		"uri2": "https://sede/b", "md2": base64.StdEncoding.EncodeToString([]byte("bbb")), "uri4": "https://sede/lost"}, nil)
	if err != nil || len(manifest) != 2 || string(manifest[1].Digest) != "bbb" || manifest[0].Algorithm != "SHA-384" || manifest[0].MimeType != "text/plain" {
		t.Errorf("a manifest: %+v %v", manifest, err)
	}
	both, _ := domain.References(map[string]string{"uri": "u", "referencesDigestMethod": "SHA-384", "precalculatedHashAlgorithm": "SHA-256"}, data)
	if both[0].Algorithm != "SHA-256" {
		t.Errorf("precalculatedHashAlgorithm wins: %s", both[0].Algorithm)
	}
	for name, properties := range map[string]map[string]string{
		"no uri":         {"format": "XAdES Externally Detached"},
		"empty manifest": {"useManifest": "true"},
		"no digest":      {"useManifest": "true", "uri1": "https://sede/a"},
	} {
		if _, err := domain.References(properties, data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !domain.ExternallyDetached(map[string]string{"format": "xades externally detached"}) || domain.ExternallyDetached(map[string]string{"format": "XAdES Detached"}) {
		t.Error("the variant is read case-insensitively, and only that one")
	}
}

// TestAVisibleSealIsAskedUnlessThePagePlacedIt: visibleSignature want or
// optional, case-insensitively; a page that gives the place or a field
// asks nothing of the person.
func TestAVisibleSealIsAskedUnlessThePagePlacedIt(t *testing.T) {
	for properties, want := range map[string]string{
		"visibleSignature=Want":     "want",
		"visibleSignature=optional": "optional",
		"visibleSignature=true":     "",
		"visibleSignature=want\nsignaturePositionOnPageLowerLeftX=10": "",
		"visibleSignature=want\nsignatureField=Firma1":                "",
		"": "",
	} {
		if got := domain.SealWanted(domain.DecodeProperties(base64.StdEncoding.EncodeToString([]byte(properties)))); got != want {
			t.Errorf("%q: %q, want %q", properties, got, want)
		}
	}
	placed := domain.SealBox{Page: 2, LowerLeftX: 72.5, LowerLeftY: 90, UpperRightX: 272.5, UpperRightY: 150}.Into(map[string]string{"signReason": "x"})
	if placed["signaturePage"] != "2" || placed["signaturePositionOnPageLowerLeftX"] != "72.5" || placed["signaturePositionOnPageUpperRightY"] != "150" ||
		placed["signReason"] != "x" {
		t.Errorf("the box as AutoFirma's parameters: %v", placed)
	}
	if !(domain.SealBox{}).IsZero() {
		t.Error("no box")
	}
}
