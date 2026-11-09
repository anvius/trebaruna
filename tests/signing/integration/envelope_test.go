package integration_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/cms"
)

// recipient makes an RSA key and certificate with OpenSSL, as a recipient's
// authority would, with the key encipherment usage.
func recipient(t *testing.T, directory, name string) (certificate *x509.Certificate, key *rsa.PrivateKey, certPath, keyPath string) {
	t.Helper()
	certPath, keyPath = filepath.Join(directory, name+".pem"), filepath.Join(directory, name+".key")
	command := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath,
		"-out", certPath, "-days", "2", "-subj", "/CN="+name, "-addext", "keyUsage=critical,keyEncipherment")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, output)
	}
	block, _ := pem.Decode(readFile(t, certPath))
	certificate, _ = x509.ParseCertificate(block.Bytes)
	keyBlock, _ := pem.Decode(readFile(t, keyPath))
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, parsed.(*rsa.PrivateKey), certPath, keyPath
}

// TestOpenSSLOpensOurEnvelopes, with both key transports.
func TestOpenSSLOpensOurEnvelopes(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	maria, _, mariaCert, mariaKey := recipient(t, directory, "MARIA")
	luca, _, lucaCert, lucaKey := recipient(t, directory, "LUCA")
	content := bytes.Repeat([]byte("Documento riservato. "), 200)

	for _, transport := range []cms.KeyTransport{cms.PKCS1v15, cms.OAEP} {
		envelope, err := cms.Seal(content, []*x509.Certificate{maria, luca}, transport)
		if err != nil {
			t.Fatalf("%s: seal: %v", transport, err)
		}
		path := filepath.Join(directory, string(transport)+".p7e")
		os.WriteFile(path, envelope, 0o600)
		for _, who := range [][2]string{{mariaCert, mariaKey}, {lucaCert, lucaKey}} {
			output, err := exec.Command("openssl", "cms", "-decrypt", "-inform", "DER", "-in", path,
				"-recip", who[0], "-inkey", who[1]).Output()
			if err != nil {
				t.Fatalf("%s: openssl cannot open it for %s: %v", transport, who[0], err)
			}
			if !bytes.Equal(output, content) {
				t.Errorf("%s: openssl decrypted different content", transport)
			}
		}
	}
}

// TestWeOpenOpenSSLEnvelopes, with both key transports.
func TestWeOpenOpenSSLEnvelopes(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	certificate, key, certPath, _ := recipient(t, directory, "MARIA")
	content := []byte("Contenuto cifrato da OpenSSL\n")
	plain := filepath.Join(directory, "plain.txt")
	os.WriteFile(plain, content, 0o600)

	for name, extra := range map[string][]string{
		"pkcs1":     nil,
		"oaep":      {"-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"},
		"oaep-sha1": {"-keyopt", "rsa_padding_mode:oaep"},
	} {
		out := filepath.Join(directory, name+".p7e")
		arguments := append([]string{"cms", "-encrypt", "-binary", "-aes256", "-outform", "DER", "-in", plain, "-out", out, "-recip", certPath}, extra...)
		if output, err := exec.Command("openssl", arguments...).CombinedOutput(); err != nil {
			t.Fatalf("%s: openssl cms -encrypt: %v\n%s", name, err, output)
		}
		opened, err := cms.Open(readFile(t, out), certificate, key)
		if err != nil {
			t.Fatalf("%s: open: %v", name, err)
		}
		if !bytes.Equal(opened, content) {
			t.Errorf("%s: content %q", name, opened)
		}
	}
}

// TestAnEnvelopeForSomeoneElseIsSaidSo.
func TestAnEnvelopeForSomeoneElseIsSaidSo(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	maria, _, _, _ := recipient(t, directory, "MARIA")
	luca, lucaKey, _, _ := recipient(t, directory, "LUCA")
	envelope, err := cms.Seal([]byte("per Maria"), []*x509.Certificate{maria}, cms.PKCS1v15)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cms.Open(envelope, luca, lucaKey); !errors.Is(err, cms.ErrNotARecipient) {
		t.Errorf("got %v", err)
	}
	ids, err := cms.Recipients(envelope)
	if err != nil || len(ids) != 1 || !ids[0].Matches(maria) {
		t.Errorf("recipients %v, %v", ids, err)
	}
}
