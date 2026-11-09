package brainpool_test

// ECDSA on the Brainpool curves, judged by openssl: it makes the keys and
// the signatures, the package verifies them and refuses altered ones.

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/brainpool"
)

func openssl(t *testing.T, directory string, arguments ...string) []byte {
	t.Helper()
	command := exec.Command("openssl", arguments...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		t.Fatalf("openssl %v: %v", arguments, err)
	}
	return output
}

func TestOpenSSLSignaturesVerifyOnEachCurve(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	data := []byte("Rezept für Frau Müller\n")
	for name, digest := range map[string]struct {
		flag  string
		value []byte
	}{
		"brainpoolP256r1": {"-sha256", func() []byte { sum := sha256.Sum256(data); return sum[:] }()},
		"brainpoolP384r1": {"-sha384", func() []byte { sum := sha512.Sum384(data); return sum[:] }()},
		"brainpoolP512r1": {"-sha512", func() []byte { sum := sha512.Sum512(data); return sum[:] }()},
	} {
		directory := t.TempDir()
		os.WriteFile(filepath.Join(directory, "data"), data, 0o600)
		openssl(t, directory, "ecparam", "-name", name, "-genkey", "-noout", "-out", "key.pem")
		spki := openssl(t, directory, "ec", "-in", "key.pem", "-pubout", "-outform", "DER")
		signature := openssl(t, directory, "dgst", digest.flag, "-sign", "key.pem", "data")

		key, err := brainpool.ParsePublicKey(spki)
		if err != nil || key.Curve.Name != name {
			t.Fatalf("%s: %v", name, err)
		}
		if !key.Verify(digest.value, signature) {
			t.Errorf("%s: openssl's signature does not verify", name)
		}
		altered := append([]byte{}, digest.value...)
		altered[0] ^= 1
		if key.Verify(altered, signature) {
			t.Errorf("%s: a signature verifies another digest", name)
		}
		broken := append([]byte{}, signature...)
		broken[len(broken)-1] ^= 1
		if key.Verify(digest.value, broken) {
			t.Errorf("%s: an altered signature verifies", name)
		}
	}
}

func TestAPointOffTheCurveIsRefused(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	openssl(t, directory, "ecparam", "-name", "brainpoolP256r1", "-genkey", "-noout", "-out", "key.pem")
	spki := openssl(t, directory, "ec", "-in", "key.pem", "-pubout", "-outform", "DER")
	spki[len(spki)-1] ^= 1
	if _, err := brainpool.ParsePublicKey(spki); err == nil {
		t.Error("a point off the curve was accepted")
	}
	directory = t.TempDir()
	openssl(t, directory, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "key.pem")
	if _, err := brainpool.ParsePublicKey(openssl(t, directory, "ec", "-in", "key.pem", "-pubout", "-outform", "DER")); err == nil {
		t.Error("a P-256 key is no Brainpool key")
	}
}

// brainpoolChain makes, with openssl, a Brainpool authority and a
// Brainpool signer it certifies.
func brainpoolChain(t *testing.T, directory, curve string) (authority, signer []byte) {
	t.Helper()
	openssl(t, directory, "ecparam", "-name", curve, "-genkey", "-noout", "-out", "ca.key")
	openssl(t, directory, "req", "-utf8", "-x509", "-new", "-key", "ca.key", "-subj", "/C=DE/O=Ärztekammer/CN=HBA-CA 7", "-days", "30",
		"-addext", "basicConstraints=critical,CA:true", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-outform", "DER", "-out", "ca.der")
	openssl(t, directory, "ecparam", "-name", curve, "-genkey", "-noout", "-out", "signer.key")
	openssl(t, directory, "req", "-utf8", "-new", "-key", "signer.key", "-subj", "/C=DE/CN=Dr. Anna Müller", "-out", "signer.csr")
	openssl(t, directory, "x509", "-req", "-in", "signer.csr", "-CA", "ca.der", "-CAform", "DER", "-CAkey", "ca.key", "-days", "30",
		"-extfile", "/dev/stdin", "-outform", "DER", "-out", "signer.der")
	authority, _ = os.ReadFile(filepath.Join(directory, "ca.der"))
	signer, _ = os.ReadFile(filepath.Join(directory, "signer.der"))
	return authority, signer
}

func TestABrainpoolCertificateIsReadAndItsChainChecked(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	for _, curve := range []string{"brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"} {
		directory := t.TempDir()
		authorityDER, signerDER := brainpoolChain(t, directory, curve)
		if _, err := x509.ParseCertificate(signerDER); err == nil {
			t.Fatalf("%s: Go reads it now; this package may no longer be needed", curve)
		}
		authority, err := brainpool.ParseCertificate(authorityDER)
		if err != nil {
			t.Fatalf("%s: %v", curve, err)
		}
		signer, err := brainpool.ParseCertificate(signerDER)
		if err != nil {
			t.Fatalf("%s: %v", curve, err)
		}
		key, ok := signer.PublicKey.(*brainpool.PublicKey)
		if !ok || key.Curve.Name != curve || signer.Subject.CommonName != "Dr. Anna Müller" || signer.Issuer.CommonName != "HBA-CA 7" ||
			string(signer.Raw) != string(signerDER) || !authority.IsCA {
			t.Errorf("%s: read %+v", curve, signer.Subject)
		}
		if err := brainpool.CheckSignatureFrom(signer, authority); err != nil {
			t.Errorf("%s: the authority's signature: %v", curve, err)
		}
		if err := brainpool.CheckSignatureFrom(authority, authority); err != nil {
			t.Errorf("%s: the self-signed authority: %v", curve, err)
		}
		if err := brainpool.CheckSignatureFrom(authority, signer); err == nil {
			t.Errorf("%s: a signer that is no authority issued a certificate", curve)
		}
		tampered := append([]byte{}, signerDER...)
		at := bytes.Index(tampered, []byte("Anna"))
		tampered[at] = 'E'
		forged, err := brainpool.ParseCertificate(tampered)
		if err != nil || brainpool.CheckSignatureFrom(forged, authority) == nil {
			t.Errorf("%s: a changed certificate passed: %v", curve, err)
		}
	}
}

// TestALongerDigestIsCutToTheOrder: SHA-512 with a 256-bit curve, as FIPS
// 186-4 cuts it; and s + N, which the curve's arithmetic alone would
// accept, is refused.
func TestALongerDigestIsCutToTheOrder(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	data := []byte("Befund\n")
	os.WriteFile(filepath.Join(directory, "data"), data, 0o600)
	openssl(t, directory, "ecparam", "-name", "brainpoolP256r1", "-genkey", "-noout", "-out", "key.pem")
	key, err := brainpool.ParsePublicKey(openssl(t, directory, "ec", "-in", "key.pem", "-pubout", "-outform", "DER"))
	if err != nil {
		t.Fatal(err)
	}
	signature := openssl(t, directory, "dgst", "-sha512", "-sign", "key.pem", "data")
	digest := sha512.Sum512(data)
	if !key.Verify(digest[:], signature) {
		t.Fatal("a SHA-512 signature on brainpoolP256r1 does not verify")
	}
	var values struct{ R, S *big.Int }
	asn1.Unmarshal(signature, &values)
	values.S.Add(values.S, key.Curve.N)
	malleable, _ := asn1.Marshal(values)
	if key.Verify(digest[:], malleable) {
		t.Error("s + N was accepted")
	}
}

// TestOnlyAnAuthorityIssuesAndOnlyItsKeyCounts: a certificate a mere signer
// signed is refused, and an authority with the right name but another key
// signs nothing.
func TestOnlyAnAuthorityIssuesAndOnlyItsKeyCounts(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	directory := t.TempDir()
	authorityDER, signerDER := brainpoolChain(t, directory, "brainpoolP256r1")
	authority, _ := brainpool.ParseCertificate(authorityDER)
	signer, _ := brainpool.ParseCertificate(signerDER)

	openssl(t, directory, "ecparam", "-name", "brainpoolP256r1", "-genkey", "-noout", "-out", "other.key")
	openssl(t, directory, "req", "-utf8", "-new", "-key", "other.key", "-subj", "/C=DE/CN=Unterzeichnet vom Arzt", "-out", "other.csr")
	openssl(t, directory, "x509", "-req", "-in", "other.csr", "-CA", "signer.der", "-CAform", "DER", "-CAkey", "signer.key",
		"-days", "30", "-outform", "DER", "-out", "other.der")
	otherDER, _ := os.ReadFile(filepath.Join(directory, "other.der"))
	other, err := brainpool.ParseCertificate(otherDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := brainpool.CheckSignatureFrom(other, signer); !errors.Is(err, brainpool.ErrNotIssuer) {
		t.Errorf("a signer issued a certificate: %v", err)
	}

	impostorDirectory := t.TempDir()
	impostorDER, _ := brainpoolChain(t, impostorDirectory, "brainpoolP256r1")
	impostor, _ := brainpool.ParseCertificate(impostorDER)
	if impostor.Subject.String() != authority.Subject.String() || brainpool.CheckSignatureFrom(signer, impostor) == nil {
		t.Error("an authority of the same name but another key signed the signer")
	}
}
