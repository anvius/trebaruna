package infrastructure_test

// NONE and NONEtri (AutoFirma's AOPkcs1Signer): the page's bytes signed as
// they are, PKCS#1 v1.5 for RSA and ASN.1 for ECDSA; through the site's
// server, whose pre-signature for NONE is the document itself, which
// trebaruna checks.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/tests/support/afirmaserver"
)

// identityWith is identity for a chosen key.
func identityWith(t *testing.T, key crypto.Signer, holder string, serial int64) (signing.Signer, *x509.Certificate) {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: holder},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(raw)
	bundle, err := pkcs12.Modern.Encode(key, certificate, nil, "x")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.NewSigner(signing.NameFromCertificate, signing.FromP12,
		signing.WithKeyMaterial(bundle), signing.WithPassphrase("x"))
	if err != nil {
		t.Fatal(err)
	}
	return signer, certificate
}

func bareRequest(t *testing.T, id, key, operation, format, algorithm, properties string, data []byte) domain.Invocation {
	t.Helper()
	uri := "afirma://" + operation + "?jvc=3&ver=3&op=" + operation + "&id=" + id + "&key=" + key + "&stservlet=" + url.QueryEscape(storage) +
		"&format=" + format + "&algorithm=" + algorithm + "&appname=SEDE" +
		"&properties=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(properties))) +
		"&dat=" + base64.URLEncoding.EncodeToString(data)
	invocation, err := domain.ParseInvocation(uri)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

// opensslVerifies asks openssl whether signature is the digest's signature
// of data under the certificate's key.
func opensslVerifies(t *testing.T, certificate *x509.Certificate, digest string, data, signature []byte) bool {
	t.Helper()
	directory := t.TempDir()
	public, _ := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	files := map[string][]byte{"key.pem": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}),
		"data": data, "signature": signature}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output, err := exec.Command("openssl", "dgst", "-"+digest, "-verify", filepath.Join(directory, "key.pem"),
		"-signature", filepath.Join(directory, "signature"), filepath.Join(directory, "data")).CombinedOutput()
	return err == nil && strings.Contains(string(output), "Verified OK")
}

func TestABareSignatureIsTheDataSignedAsTheyAre(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, test := range map[string]struct {
		key                      crypto.Signer
		algorithm, opensslDigest string
	}{
		"RSA, SHA-256":   {rsaKey, "SHA256withRSA", "sha256"},
		"ECDSA, SHA-384": {ecKey, "SHA384withECDSA", "sha384"},
		"RSA, bare name": {rsaKey, "SHA512", "sha512"},
	} {
		server := afirmaserver.New(t)
		maria, certificate := identityWith(t, test.key, "MARIA GARCIA", 81)
		id, key := sessionID(), "11223344"
		data := []byte("cadena de autenticacion 2026-11-09")
		approver := &recordingApprover{approving: approving{key: maria}}
		if _, err := useCase(server, approver).Execute(context.Background(),
			bareRequest(t, id, key, "sign", "NONE", test.algorithm, "", data)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		elements := pageReads(t, server, id, key)
		if len(elements) != 2 || string(elements[0]) != string(certificate.Raw) {
			t.Fatalf("%s: the page reads cert|signature, got %d elements", name, len(elements))
		}
		if !opensslVerifies(t, certificate, test.opensslDigest, data, elements[1]) {
			t.Errorf("%s: openssl does not verify the bare signature", name)
		}
		if !slices.ContainsFunc(approver.proposal.Warnings, func(warning string) bool { return strings.Contains(warning, "bare signature (NONE)") }) {
			t.Errorf("%s: the approval does not say what a bare signature is: %v", name, approver.proposal.Warnings)
		}
	}
}

func TestABareSignatureHasNoCoSignatures(t *testing.T) {
	server := afirmaserver.New(t)
	maria, _ := identity(t, "MARIA GARCIA", 82)
	for _, operation := range []string{"cosign", "countersign"} {
		id, key := sessionID(), "11223344"
		useCase(server, approving{key: maria}).Execute(context.Background(),
			bareRequest(t, id, key, operation, "NONE", "SHA256withECDSA", "", []byte("firma previa")))
		if history := server.History(id); len(history) == 0 || !strings.HasPrefix(history[len(history)-1], "SAF_04") {
			t.Errorf("%s of NONE: the page reads %v", operation, history)
		}
	}
}

// TestABareSignatureThroughTheSitesServerIsOfTheDocumentShown: NONEtri's
// pre-signature is the document; a server that asks for other bytes is
// refused before anything is signed.
func TestABareSignatureThroughTheSitesServerIsOfTheDocumentShown(t *testing.T) {
	server := afirmaserver.New(t)
	outcome := server.EnableTriphase()
	maria, certificate := identity(t, "MARIA GARCIA", 83)
	properties := "serverUrl=http://sede.example/TriPhaseSignerServer"
	id, key := sessionID(), "55667788"
	approver := &recordingApprover{approving: approving{key: maria}}
	if _, err := batchUseCase(server, approver).Execute(context.Background(),
		bareRequest(t, id, key, "sign", "NONEtri", "SHA256withECDSA", properties, []byte("expediente-90"))); err != nil {
		t.Fatal(err)
	}
	if len(outcome.Calls) != 2 || !outcome.Verified || outcome.Calls[0]["format"] != "NONE" {
		t.Fatalf("pre then post with format NONE, the signature verifying: %d calls, verified %v", len(outcome.Calls), outcome.Verified)
	}
	if elements := pageReads(t, server, id, key); len(elements) != 2 || string(elements[0]) != string(certificate.Raw) ||
		string(elements[1]) != "signed-expediente-90" {
		t.Errorf("the page reads cert|id, got %q", elements)
	}
	if slices.ContainsFunc(approver.proposal.Warnings, func(warning string) bool { return strings.Contains(warning, "prepared by the site's server") }) {
		t.Error("NONEtri's server prepares nothing, and the approval does not say it does")
	}

	dishonest := afirmaserver.New(t)
	swapped := dishonest.EnableTriphase()
	id = sessionID()
	batchUseCase(dishonest, approving{key: maria}).Execute(context.Background(),
		bareRequest(t, id, key, "sign", "NONEtri", "SHA256withECDSA", properties, []byte("swap")))
	if len(swapped.Calls) != 1 {
		t.Errorf("after other bytes in the pre-signature nothing goes back to the server: %d calls", len(swapped.Calls))
	}
	if history := dishonest.History(id); len(history) == 0 || !strings.HasPrefix(history[len(history)-1], "SAF_") {
		t.Errorf("the page hears the refusal: %v", history)
	}
}

// TestABareSignatureIsCheckedAgainstTheCertificate: a key that is not the
// certificate's makes a signature the page could not verify; AutoFirma
// checks, and so does trebaruna.
func TestABareSignatureIsCheckedAgainstTheCertificate(t *testing.T) {
	ecOne, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecTwo, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaOne, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaTwo, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, keys := range map[string][2]crypto.Signer{"ECDSA": {ecOne, ecTwo}, "RSA": {rsaOne, rsaTwo}} {
		_, certificate := identityWith(t, keys[0], "MARIA GARCIA", 84)
		bundle, err := pkcs12.Modern.Encode(keys[1], certificate, nil, "x")
		if err != nil {
			t.Fatal(err)
		}
		mismatched, _ := signing.NewSigner(signing.NameFromCertificate, signing.FromP12,
			signing.WithKeyMaterial(bundle), signing.WithPassphrase("x"))
		server := afirmaserver.New(t)
		id, key := sessionID(), "11223344"
		useCase(server, approving{key: mismatched}).Execute(context.Background(),
			bareRequest(t, id, key, "sign", "NONE", "SHA256withRSA", "", []byte("datos")))
		if history := server.History(id); len(history) == 0 || !strings.HasPrefix(history[len(history)-1], "SAF_") {
			t.Errorf("%s: a signature its certificate does not verify reached the page: %v", name, history)
		}
	}
}
