package infrastructure_test

// The PKCS#11 path was never exercised: it compiled and nothing else. These tests
// cover what can be covered without a physical smartcard by using SoftHSM, and
// they exist because the first real run found a genuine defect: the session was
// closed before the signature was produced, so every signing operation failed
// with "context is closed".
//
// The tests skip when SoftHSM is absent instead of pretending to pass.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// softHSM is a running, initialised token.
type softHSM struct {
	module    string
	label     string
	pin       string
	directory string
}

// sharedToken is the token every test in this package uses.
//
// It is created once because SoftHSM keeps its state in the process, not in the
// configuration file: a second token directory in the same process is ignored,
// the module keeps serving the first one, and the second test looks at a token
// that does not exist. That is a property of the driver, not of the tool, and
// the fixture has to live with it.
//
// The token is therefore shared, and each test uses its own identifier for the
// key material it stores, so the tests do not interfere with one another.
var (
	sharedToken    softHSM
	sharedTokenErr error
	sharedOnce     sync.Once
)

// startSoftHSM locates a module, initialises a token and returns it.
//
// It searches the usual locations and SOFTHSM2_MODULE, so the test works both on
// a machine where SoftHSM is installed system-wide and one where it was unpacked
// into a temporary directory.
func startSoftHSM(t *testing.T) softHSM {
	t.Helper()

	sharedOnce.Do(func() { sharedToken, sharedTokenErr = buildSoftHSM() })
	if sharedTokenErr != nil {
		if sharedTokenErr == errSoftHSMMissing {
			t.Skip("SoftHSM is not installed; set SOFTHSM2_MODULE to run these tests")
		}
		t.Skipf("SoftHSM cannot be started: %v", sharedTokenErr)
	}

	return softTokenFor(t)
}

// errSoftHSMMissing marks a machine without SoftHSM.
var errSoftHSMMissing = errors.New("softhsm is not installed")

// buildSoftHSM creates the module configuration and the token.
func buildSoftHSM() (softHSM, error) {
	module := os.Getenv("SOFTHSM2_MODULE")
	if module == "" {
		candidates := []string{
			"/usr/lib/softhsm/libsofthsm2.so",
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
			"/usr/local/lib/softhsm/libsofthsm2.so",
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				module = candidate
				break
			}
		}
	}
	if module == "" {
		return softHSM{}, errSoftHSMMissing
	}

	utility, err := exec.LookPath("softhsm2-util")
	if err != nil {
		return softHSM{}, errSoftHSMMissing
	}

	directory, err := os.MkdirTemp("", "trebaruna-softhsm")
	if err != nil {
		return softHSM{}, err
	}
	tokenDirectory := filepath.Join(directory, "tokens")
	if err := os.MkdirAll(tokenDirectory, 0o700); err != nil {
		return softHSM{}, err
	}

	configuration := filepath.Join(directory, "softhsm2.conf")
	content := "directories.tokendir = " + tokenDirectory + "\n" +
		"objectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		return softHSM{}, err
	}
	os.Setenv("SOFTHSM2_CONF", configuration)

	label := "trebaruna-test"
	command := exec.Command(utility, "--module", module, "--init-token",
		"--slot", "0", "--label", label, "--pin", "1234", "--so-pin", "123456")
	if output, err := command.CombinedOutput(); err != nil {
		return softHSM{}, fmt.Errorf("initialise token: %w\n%s", err, output)
	}

	return softHSM{module: module, label: label, pin: "1234", directory: directory}, nil
}

// softTokenFor returns the shared token with a per-test working directory.
//
// The key material is stored under a per-test identifier, so two tests that run
// in the same package do not overwrite each other's objects on the card.
func softTokenFor(t *testing.T) softHSM {
	t.Helper()
	token := sharedToken
	token.directory = t.TempDir()
	return token
}

// keyPair generates a key inside the token.
func (h softHSM) keyPair(t *testing.T, identifier, label string) {
	t.Helper()

	tool, err := exec.LookPath("pkcs11-tool")
	if err != nil {
		t.Skip("pkcs11-tool is not available")
	}

	command := exec.Command(tool, "--module", h.module, "--login", "--pin", h.pin,
		"--keypairgen", "--key-type", "rsa:2048", "--id", identifier, "--label", label)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate key pair: %v\n%s", err, output)
	}
}

// TestTokenSessionSurvivesUntilTheSignature is the regression guard for the bug
// that made every PKCS#11 signature fail: the context was closed by a defer
// before the signer was used.
func TestTokenSessionSurvivesUntilTheSignature(t *testing.T) {
	token := startSoftHSM(t)
	token.keyPair(t, identifier(t), "signing-key")

	// Without a certificate the token has no pairs, and the error must say so
	// rather than "context is closed" from the driver.
	signer, err := domain.NewSigner("Token", domain.FromToken,
		domain.WithToken(token.module, token.label, token.pin))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	keyPair, err := infrastructure.LoadKeyPair(signer)
	if err == nil {
		t.Fatal("a token with no certificate must not yield a key pair")
	}
	if strings.Contains(err.Error(), "context is closed") {
		t.Errorf("the driver was closed before it could answer: %v", err)
	}
	_ = keyPair

	// And the message must point at the tool that lists the token.
	if !strings.Contains(err.Error(), "pkcs11-tool") {
		t.Errorf("the error must say how to inspect the token, got: %v", err)
	}
}

// TestTokenSignsWhenTheSessionStaysOpen is the positive case: a real signature
// produced by a key that lives inside the token.
func TestTokenSignsWhenTheSessionStaysOpen(t *testing.T) {
	token := startSoftHSM(t)
	id := identifier(t)
	token.keyPair(t, id, "signing-key")

	// Issue a certificate for the token's public key, the way a CA would.
	certificatePEM := issueCertificateForToken(t, token, id)
	if certificatePEM == nil {
		t.Skip("openssl is not available to issue a certificate")
	}

	// Import the certificate back so the token pairs it with its key.
	importCertificate(t, token, id, "signing-key", certificatePEM)

	signer, err := domain.NewSigner("Token", domain.FromToken,
		domain.WithToken(token.module, token.label, token.pin))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	adapter := infrastructure.NewCadesSigner(nil)
	signed, err := adapter.SignCades(context.Background(), application.CadesRequest{
		Content: []byte("Contenuto firmato con la chiave nel token\n"),
		Signer:  signer,
		Level:   domain.BES,
	})
	if err != nil {
		t.Fatalf("sign with the token: %v", err)
	}
	if len(signed) == 0 {
		t.Fatal("the token produced no signature")
	}

	// The signature must verify against the CA that issued the token certificate.
	caPEM := readFileOrFail(t, filepath.Join(token.directory, "ca.pem"))
	if err := verifyWithOpenSSL(t, signed, caPEM); err != nil {
		t.Errorf("the signature made by the token does not verify: %v", err)
	}
}

// issueCertificateForToken builds a CSR from the token's public key and has a
// throwaway CA sign it.
func issueCertificateForToken(t *testing.T, token softHSM, identifier string) []byte {
	t.Helper()

	openssl, err := exec.LookPath("openssl")
	if err != nil {
		return nil
	}
	tool, err := exec.LookPath("pkcs11-tool")
	if err != nil {
		return nil
	}

	// The public key, as DER and PEM.
	publicPath := filepath.Join(token.directory, "public.der")
	command := exec.Command(tool, "--module", token.module, "--login", "--pin", token.pin,
		"--id", identifier, "--read-object", "--type", "pubkey", "--output-file", publicPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("read public key: %v\n%s", err, output)
	}

	publicPEM := filepath.Join(token.directory, "public.pem")
	der, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if err := os.WriteFile(publicPEM, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	// A CA to sign it.
	caKey := filepath.Join(token.directory, "ca.key")
	caCert := filepath.Join(token.directory, "ca.pem")
	generate := exec.Command(openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", caKey, "-out", caCert, "-days", "2", "-subj", "/CN=Token Test CA")
	if output, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("create CA: %v\n%s", err, output)
	}

	// The CSR is built and signed by the token itself, so the certificate binds
	// the key that will actually sign. Fetching a certificate for a different key
	// is the mistake that produced "Signature is Invalid" the first time.
	request := filepath.Join(token.directory, "request.der")
	buildCertificationRequest(t, token, identifier, request)

	signature := filepath.Join(token.directory, "request.sig")
	sign := exec.Command(tool, "--module", token.module, "--login", "--pin", token.pin,
		"--id", identifier, "--sign", "--mechanism", "SHA256-RSA-PKCS",
		"--input-file", request, "--output-file", signature)
	if output, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("sign the request: %v\n%s", err, output)
	}

	csr := filepath.Join(token.directory, "request.csr")
	assembleCertificationRequest(t, request, signature, csr)

	certificate := filepath.Join(token.directory, "certificate.pem")
	issue := exec.Command(openssl, "x509", "-req", "-in", csr, "-CA", caCert,
		"-CAkey", caKey, "-CAcreateserial", "-days", "2", "-out", certificate)
	if output, err := issue.CombinedOutput(); err != nil {
		t.Fatalf("issue certificate: %v\n%s", err, output)
	}

	return readFileOrFail(t, certificate)
}

// buildCertificationRequest writes the CertificationRequestInfo DER.
//
// It is assembled here because openssl cannot take its key from a PKCS#11 module
// without the provider, which is not always installed.
func buildCertificationRequest(t *testing.T, token softHSM, identifier, path string) {
	t.Helper()

	publicPath := filepath.Join(token.directory, "public.der")
	spki, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}

	request := derSequence(
		derInteger(0),
		derSequence(
			derSet(derSequence(derOID("2.5.4.5"), derUTF8("IDCES-00000000X"))),
			derSet(derSequence(derOID("2.5.4.3"), derUTF8("Token Test Signer"))),
		),
		spki,
		derTagged(0xa0, nil),
	)
	if err := os.WriteFile(path, request, 0o600); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

// assembleCertificationRequest wraps the info and its signature in a CSR.
func assembleCertificationRequest(t *testing.T, infoPath, signaturePath, path string) {
	t.Helper()

	info, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}

	algorithm := derSequence(derOID("1.2.840.113549.1.1.11"), derTagged(0x05, nil))
	request := derSequence(info, algorithm, derTagged(0x03, append([]byte{0}, signature...)))
	if err := os.WriteFile(path, request, 0o600); err != nil {
		t.Fatalf("write CSR: %v", err)
	}
}

// importCertificate stores the certificate on the token, paired with its key.
func importCertificate(t *testing.T, token softHSM, identifier, label string, certificate []byte) {
	t.Helper()

	tool, err := exec.LookPath("pkcs11-tool")
	if err != nil {
		t.Skip("pkcs11-tool is not available")
	}

	path := filepath.Join(token.directory, "import.pem")
	if err := os.WriteFile(path, certificate, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	command := exec.Command(tool, "--module", token.module, "--login", "--pin", token.pin,
		"--id", identifier, "--write-object", path, "--type", "cert", "--label", label)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("import certificate: %v\n%s", err, output)
	}
}

// verifyWithOpenSSL checks the CMS signature against the certificate.
func verifyWithOpenSSL(t *testing.T, signature, certificate []byte) error {
	t.Helper()

	directory := t.TempDir()
	container := filepath.Join(directory, "signed.p7m")
	anchor := filepath.Join(directory, "ca.pem")

	if err := os.WriteFile(container, signature, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(anchor, certificate, 0o600); err != nil {
		return err
	}

	// The certificate is self-signed by the throwaway CA, so it is its own anchor.
	command := exec.Command("openssl", "cms", "-verify", "-inform", "DER",
		"-in", container, "-CAfile", anchor, "-purpose", "any", "-cades", "-out", os.DevNull)
	output, err := command.CombinedOutput()
	if err != nil {
		return &commandError{output: string(output), err: err}
	}
	return nil
}

// commandError reports a failed external command with its output.
type commandError struct {
	output string
	err    error
}

func (e *commandError) Error() string { return e.err.Error() + ": " + e.output }
func (e *commandError) Unwrap() error { return e.err }

// readFileOrFail reads a file or fails the test.
func readFileOrFail(t *testing.T, path string) []byte {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return content
}

// DER helpers, kept local so the test does not depend on the code under test.
func derTagged(tag byte, body []byte) []byte {
	length := len(body)
	var encoded []byte
	switch {
	case length < 0x80:
		encoded = []byte{byte(length)}
	case length < 0x100:
		encoded = []byte{0x81, byte(length)}
	default:
		encoded = []byte{0x82, byte(length >> 8), byte(length)}
	}
	return append(append([]byte{tag}, encoded...), body...)
}

func derSequence(elements ...[]byte) []byte { return derTagged(0x30, bytes.Join(elements, nil)) }
func derSet(elements ...[]byte) []byte      { return derTagged(0x31, bytes.Join(elements, nil)) }
func derInteger(value int) []byte           { return derTagged(0x02, []byte{byte(value)}) }
func derUTF8(value string) []byte           { return derTagged(0x0c, []byte(value)) }

func derOID(value string) []byte {
	parts := strings.Split(value, ".")
	numbers := make([]int, len(parts))
	for index, part := range parts {
		var number int
		for _, character := range part {
			number = number*10 + int(character-'0')
		}
		numbers[index] = number
	}

	body := []byte{byte(40*numbers[0] + numbers[1])}
	for _, number := range numbers[2:] {
		var encoded []byte
		for {
			encoded = append([]byte{byte(number & 0x7f)}, encoded...)
			number >>= 7
			if number == 0 {
				break
			}
		}
		for index := 0; index < len(encoded)-1; index++ {
			encoded[index] |= 0x80
		}
		body = append(body, encoded...)
	}
	return derTagged(0x06, body)
}

// unused keeps the x509 import honest if a future revision drops it.
var _ = x509.Certificate{}

// identifier gives the test its own object identifier on the shared card.
//
// The card is shared by the package because SoftHSM keeps its state in the
// process. Two tests storing under the same identifier would overwrite one
// another's key material, and the failure would look like a bug in the tool.
func identifier(t *testing.T) string {
	t.Helper()
	name := t.Name()
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:4])
}
