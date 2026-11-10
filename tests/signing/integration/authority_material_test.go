package integration_test

// The long-term levels carry the validation material of the authority
// behind the signature timestamp too (EN 319 122-1, EN 319 132-1 and
// ISO 32000-2 at B-LT): its chain and an OCSP answer for it, beside the
// signer's. Without them EU DSS rates the signature at T. XAdES carries the
// certificates ds:KeyInfo leaves out in xades:CertificateValues, without
// which a validator not given the signer's authority cannot build the
// chain. A revoked authority certificate refuses the signature. A CAdES
// signature added to an envelope carries its own authority's material.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/digitorus/pdf"
	"golang.org/x/crypto/ocsp"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
)

func TestAnXadesLtCarriesTheAuthorityAndTheIssuers(t *testing.T) {
	_, signer := ltaFixture(t)
	authority := newLocalTSAWithStatus(t)
	request := buildXadesRequest(signer, []byte("<fattura><numero>8</numero></fattura>"), false)
	request.Level, request.TimestampURL, request.EmbedRevocation = domain.LT, "http://tsa.example.invalid", true
	signed, err := infrastructure.NewXadesSigner(authority).SignXades(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	var carried []string
	for _, value := range document.FindElements("//CertificateValues/EncapsulatedX509Certificate") {
		carried = append(carried, strings.Join(strings.Fields(value.Text()), ""))
	}
	for name, wanted := range map[string][]byte{"the timestamp authority": authority.certificate.Raw, "its root": authority.ca.Raw} {
		if !containsString(carried, base64.StdEncoding.EncodeToString(wanted)) {
			t.Errorf("xades:CertificateValues lacks %s", name)
		}
	}
	if len(carried) != 3 {
		t.Errorf("xades:CertificateValues holds %d certificates, want the signer's issuer and the authority's two", len(carried))
	}
	answers := document.FindElements("//RevocationValues/OCSPValues/EncapsulatedOCSPValue")
	if len(answers) != 2 {
		t.Fatalf("%d OCSP answers, want the signer's and the authority's", len(answers))
	}
	for _, answer := range answers {
		raw, _ := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(answer.Text()), ""))
		if parsed, err := ocsp.ParseResponse(raw, nil); err != nil || parsed.Status != ocsp.Good {
			t.Errorf("an OCSP answer: %v", err)
		}
	}
	verifyXML(t, signed)
}

func TestAPadesLtStoresTheAuthorityToo(t *testing.T) {
	original, signer := ltaFixture(t)
	authority := newLocalTSAWithStatus(t)
	signed, err := infrastructure.NewPadesSigner(authority).SignPades(context.Background(), application.PadesRequest{
		Content: original, Signer: signer, Level: domain.LT, SignedAt: timeNow(), TimestampURL: authority.url(t), EmbedRevocation: true})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := pdf.NewReader(bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		t.Fatal(err)
	}
	store := reader.Trailer().Key("Root").Key("DSS")
	certificates, answers := store.Key("Certs"), store.Key("OCSPs")
	var held [][]byte
	for index := 0; index < certificates.Len(); index++ {
		held = append(held, readStream(t, certificates.Index(index)))
	}
	for name, wanted := range map[string][]byte{"the timestamp authority": authority.certificate.Raw, "its root": authority.ca.Raw} {
		if !containsBytes(held, wanted) {
			t.Errorf("the /DSS lacks %s", name)
		}
	}
	if answers.Len() != 2 {
		t.Errorf("the /DSS holds %d OCSP answers, want the signer's and the authority's", answers.Len())
	}
}

func TestARevokedTimestampAuthorityRefusesTheSignature(t *testing.T) {
	content, signer := cadesFixture(t)
	_, err := infrastructure.NewCadesSigner(newRevokedLocalTSA(t)).SignCades(context.Background(), application.CadesRequest{
		Content: content, Signer: signer, Level: domain.LT, TimestampURL: "http://tsa.example.invalid", EmbedRevocation: true})
	if err == nil || !strings.Contains(err.Error(), "timestamp authority's certificate") || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("a revoked timestamp authority: %v", err)
	}
}

// readStream is a PDF stream's decoded content.
func readStream(t *testing.T, stream pdf.Value) []byte {
	t.Helper()
	reader := stream.Reader()
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsBytes(values [][]byte, wanted []byte) bool {
	for _, value := range values {
		if bytes.Equal(value, wanted) {
			return true
		}
	}
	return false
}

// sharedChain is a root, an intermediate it issued, and a signer and a
// timestamp authority the intermediate issued, each certificate naming a
// local OCSP responder that answers for it with its issuer's key; and a
// decoy bearing the intermediate's name with another key.
type sharedChain struct {
	signer    domain.Signer
	authority *localTSA
}

func newSharedChain(t *testing.T) sharedChain {
	t.Helper()
	newKey := func() *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	responder := func(issuer **x509.Certificate, key *rsa.PrivateKey) string {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			body, _ := io.ReadAll(request.Body)
			parsed, err := ocsp.ParseRequest(body)
			if err != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			answer, err := ocsp.CreateResponse(*issuer, *issuer, ocsp.Response{Status: ocsp.Good, SerialNumber: parsed.SerialNumber,
				ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}, key)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			writer.Write(answer)
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	issue := func(template, parent *x509.Certificate, public, signing *rsa.PrivateKey) *x509.Certificate {
		template.NotBefore, template.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &public.PublicKey, signing)
		if err != nil {
			t.Fatal(err)
		}
		certificate, _ := x509.ParseCertificate(der)
		return certificate
	}
	rootKey, intermediateKey, signerKey, authorityKey, decoyKey := newKey(), newKey(), newKey(), newKey(), newKey()
	authorities := pkix.Name{CommonName: "Shared Intermediate CA"}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(900), Subject: pkix.Name{CommonName: "Shared Root CA"},
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	root := issue(rootTemplate, rootTemplate, rootKey, rootKey)
	var intermediate *x509.Certificate
	intermediate = issue(&x509.Certificate{SerialNumber: big.NewInt(901), Subject: authorities, KeyUsage: x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true, OCSPServer: []string{responder(&root, rootKey)}}, root, intermediateKey, rootKey)
	leafResponder := responder(&intermediate, intermediateKey)
	signer := issue(&x509.Certificate{SerialNumber: big.NewInt(902), Subject: pkix.Name{CommonName: "Shared Signer"},
		KeyUsage: x509.KeyUsageDigitalSignature, OCSPServer: []string{leafResponder}}, intermediate, signerKey, intermediateKey)
	authority := issue(&x509.Certificate{SerialNumber: big.NewInt(903), Subject: pkix.Name{CommonName: "Shared TSA"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		OCSPServer: []string{leafResponder}}, intermediate, authorityKey, intermediateKey)
	decoyTemplate := &x509.Certificate{SerialNumber: big.NewInt(904), Subject: authorities, KeyUsage: x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true}
	decoy := issue(decoyTemplate, decoyTemplate, decoyKey, decoyKey)

	keyDER, _ := x509.MarshalPKCS8PrivateKey(signerKey)
	var bundle []byte
	for _, certificate := range []*x509.Certificate{signer, intermediate, root} {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	signing, err := domain.NewSigner("Shared", domain.FromPEM, domain.WithKeyMaterial(bundle))
	if err != nil {
		t.Fatal(err)
	}
	return sharedChain{signer: signing, authority: &localTSA{certificate: authority, ca: intermediate, key: authorityKey,
		decoys: []*x509.Certificate{decoy}}}
}

// TestAnAuthorityUnderTheSignersIssuersIsCarriedOnce: when the authority
// and the signer share their issuers, each certificate is carried once
// and each answer asked once; the authority's issuer is the one whose key
// signed its certificate, not a certificate bearing its name.
func TestAnAuthorityUnderTheSignersIssuersIsCarriedOnce(t *testing.T) {
	chain := newSharedChain(t)
	request := buildXadesRequest(chain.signer, []byte("<fattura><numero>9</numero></fattura>"), false)
	request.Level, request.TimestampURL, request.EmbedRevocation = domain.LT, "http://tsa.example.invalid", true
	signed, err := infrastructure.NewXadesSigner(chain.authority).SignXades(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(signed); err != nil {
		t.Fatal(err)
	}
	// The intermediate and the root, then the authority: three, each once.
	if carried := document.FindElements("//CertificateValues/EncapsulatedX509Certificate"); len(carried) != 3 {
		t.Errorf("xades:CertificateValues holds %d certificates, want 3", len(carried))
	}
	// The signer's, the intermediate's and the authority's.
	if answers := document.FindElements("//RevocationValues/OCSPValues/EncapsulatedOCSPValue"); len(answers) != 3 {
		t.Errorf("%d OCSP answers, want 3", len(answers))
	}
}

// TestAnAddedCadesSignatureCarriesItsOwnAuthority: a co-signature or a
// counter-signature at LT carries, in SignedData, the material of the
// authority behind the timestamp it brought, and asks nothing about the
// timestamps already in the envelope: here the earlier signature's
// authority is revoked, which would refuse the signature if it were asked.
func TestAnAddedCadesSignatureCarriesItsOwnAuthority(t *testing.T) {
	content, signer := cadesFixture(t)
	original, err := infrastructure.NewCadesSigner(newRevokedLocalTSA(t)).SignCades(context.Background(), application.CadesRequest{
		Content: content, Signer: signer, Level: domain.T, TimestampURL: "http://tsa.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	ocspAnswer := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x10, 0x02}
	for name, request := range map[string]application.CadesRequest{
		"a co-signature":      {Cosign: true},
		"a counter-signature": {Countersign: "leaves"},
	} {
		authority := newLocalTSAWithStatus(t)
		request.Content, request.Signer, request.Level = original, signer, domain.LT
		request.TimestampURL, request.EmbedRevocation = "http://tsa.example.invalid", true
		added, err := infrastructure.NewCadesSigner(authority).SignCades(context.Background(), request)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The signer's answer and its new authority's.
		if answers := bytes.Count(added, ocspAnswer); answers != 2 {
			t.Errorf("%s: %d OCSP answers, want 2", name, answers)
		}
		certificates, err := cms.Certificates(added)
		if err != nil {
			t.Fatal(err)
		}
		if !containsBytes(certificates, authority.certificate.Raw) || !containsBytes(certificates, authority.ca.Raw) {
			t.Errorf("%s: SignedData.certificates lacks its authority's chain", name)
		}
	}
}
