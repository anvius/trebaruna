package keybundle_test

// The fixtures are a throwaway test identity ("MARIA PRUEBA NSS", passphrase
// "segreto"), exported three times:
//
//   - openssl-der.p12 by `openssl pkcs12 -export` (DER, what Go's library reads);
//   - nss-ber.p12 by NSS `pk12util -o`, which is what Firefox and Thunderbird
//     write: BER with indefinite lengths, PBES2 (AES-256 for the key, AES-128
//     for the certificates), PBKDF2-HMAC-SHA256 with 600 000 iterations, and an
//     HMAC-SHA256 integrity check. Go's PKCS#12 library rejects it with
//     "indefinite length found (not DER)"; a real certificate exported this way
//     was refused as "not a certificate" by every version up to 0.6.0;
//   - nss-ber-legacy.p12 by the same tool with the older algorithms
//     (pbeWithSHA1And3-KeyTripleDES-CBC and an HMAC-SHA1 integrity check), as
//     older Firefox profiles and some certificate authorities still write.

import (
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/keybundle"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTheGoLibraryAloneRejectsAFirefoxExport(t *testing.T) {
	// Pins why the decoder exists: if this ever passes, the fallback can go.
	if _, _, _, err := pkcs12.DecodeChain(fixture(t, "nss-ber.p12"), "segreto"); err == nil {
		t.Skip("go-pkcs12 now reads BER; the fallback may be removable")
	}
}

func TestAFirefoxExportOpens(t *testing.T) {
	key, certificate, chain, err := keybundle.Decode(fixture(t, "nss-ber.p12"), "segreto")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if certificate.Subject.CommonName != "MARIA PRUEBA NSS" {
		t.Errorf("certificate = %q", certificate.Subject.CommonName)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("key %T cannot sign", key)
	}
	type comparable interface{ Equal(crypto.PublicKey) bool }
	if !signer.Public().(comparable).Equal(certificate.PublicKey) {
		t.Error("the key returned does not belong to the certificate returned")
	}
	if len(chain) != 0 {
		t.Errorf("chain = %d certificates, want none for a self-signed export", len(chain))
	}
}

func TestAnOlderFirefoxExportOpens(t *testing.T) {
	_, certificate, _, err := keybundle.Decode(fixture(t, "nss-ber-legacy.p12"), "segreto")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if certificate.Subject.CommonName != "MARIA PRUEBA NSS" {
		t.Errorf("certificate = %q", certificate.Subject.CommonName)
	}
	if _, _, _, err := keybundle.Decode(fixture(t, "nss-ber-legacy.p12"), "sbagliata"); !errors.Is(err, pkcs12.ErrIncorrectPassword) {
		t.Errorf("wrong passphrase: err = %v", err)
	}
}

func TestBothEncodingsOfTheSameBundleAgree(t *testing.T) {
	_, fromDER, _, err := keybundle.Decode(fixture(t, "openssl-der.p12"), "segreto")
	if err != nil {
		t.Fatalf("DER: %v", err)
	}
	_, fromBER, _, err := keybundle.Decode(fixture(t, "nss-ber.p12"), "segreto")
	if err != nil {
		t.Fatalf("BER: %v", err)
	}
	if !fromDER.Equal(fromBER) {
		t.Error("the two exports carry the same certificate and must decode to it")
	}
}

func TestAWrongPassphraseIsAWrongPassphraseInBothEncodings(t *testing.T) {
	for _, name := range []string{"openssl-der.p12", "nss-ber.p12"} {
		_, _, _, err := keybundle.Decode(fixture(t, name), "sbagliata")
		if !errors.Is(err, pkcs12.ErrIncorrectPassword) {
			t.Errorf("%s: err = %v, want ErrIncorrectPassword", name, err)
		}
	}
}

func TestSomethingThatIsNotABundleSaysSo(t *testing.T) {
	_, _, _, err := keybundle.Decode([]byte("-----BEGIN NOTHING-----"), "segreto")
	if err == nil || errors.Is(err, pkcs12.ErrIncorrectPassword) {
		t.Fatalf("err = %v, want a format error, not a passphrase error", err)
	}
}

func TestATruncatedFirefoxExportIsAFormatError(t *testing.T) {
	data := fixture(t, "nss-ber.p12")
	_, _, _, err := keybundle.Decode(data[:len(data)/2], "segreto")
	if err == nil || errors.Is(err, pkcs12.ErrIncorrectPassword) {
		t.Fatalf("err = %v, want a format error", err)
	}
}
