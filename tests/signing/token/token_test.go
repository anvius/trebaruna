//go:build cgo

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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
)

// softHSM is a running, initialised token.
type softHSM struct {
	module string
	label  string
	// slot is the identifier SoftHSM gave the token; helpers select by it, as
	// two tokens may share a label.
	slot      string
	pin       string
	directory string
}

// tokenEnvironment is the one thing SoftHSM sets up per process.
//
// The configuration is read when the module is loaded, and the module is
// loaded once per process: a second configuration file in the same process is
// ignored, the module keeps serving the first token directory. That is a
// property of the driver, not of the tool, so the directory is created once
// and every test gets its own token inside it.
//
// One token per test, not one identifier per test on a shared token. A shared
// token made the tests order-dependent without looking like it: whichever test
// imported a certificate first decided whether a later test saw a token with
// "no certificate", and whichever certificate the card returned first decided
// which CA a later test had to verify against. Both failures appeared only in
// CI, because only there did the file order put the inspector tests first.
var (
	environmentOnce sync.Once
	environmentErr  error
	environment     softHSMEnvironment
	nextSlot        atomic.Uint32
)

// softHSMEnvironment is the shared token directory and its configuration.
type softHSMEnvironment struct {
	module    string
	pin       string
	soPin     string
	directory string
}

// startSoftHSM gives the test a token of its own.
//
// It searches the usual locations and SOFTHSM2_MODULE, so the test works both on
// a machine where SoftHSM is installed system-wide and one where it was unpacked
// into a temporary directory.
func startSoftHSM(t *testing.T) softHSM {
	t.Helper()
	return startSoftHSMLabelled(t, "")
}

// startSoftHSMLabelled is startSoftHSM with a chosen label, so two cards can
// carry the same one, as two identity cards do.
func startSoftHSMLabelled(t *testing.T, chosen string) softHSM {
	t.Helper()

	environmentOnce.Do(func() { environment, environmentErr = buildSoftHSMEnvironment() })
	if environmentErr != nil {
		if errors.Is(environmentErr, errSoftHSMMissing) {
			t.Skip("SoftHSM is not installed; set SOFTHSM2_MODULE to run these tests")
		}
		t.Skipf("SoftHSM cannot be started: %v", environmentErr)
	}

	// Slot numbers are handed out in order. Each slot holds one token, so two
	// tests never see each other's objects no matter which order they run in.
	slot := nextSlot.Add(1) - 1
	label := fmt.Sprintf("trebaruna-%d", slot)
	if chosen != "" {
		label = chosen
	}

	utility, err := exec.LookPath("softhsm2-util")
	if err != nil {
		t.Skip("softhsm2-util is not available")
	}
	command := exec.Command(utility, "--module", environment.module, "--init-token",
		"--slot", strconv.FormatUint(uint64(slot), 10), "--label", label,
		"--pin", environment.pin, "--so-pin", environment.soPin)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("initialise token: %v\n%s", err, output)
	}
	assigned := regexp.MustCompile(`slot (\d+)`).FindStringSubmatch(string(output))
	if assigned == nil {
		t.Fatalf("SoftHSM did not say which slot holds the token:\n%s", output)
	}

	return softHSM{
		module:    environment.module,
		label:     label,
		slot:      assigned[1],
		pin:       environment.pin,
		directory: t.TempDir(),
	}
}

// errSoftHSMMissing marks a machine without SoftHSM.
var errSoftHSMMissing = errors.New("softhsm is not installed")

// buildSoftHSMEnvironment creates the token directory and the configuration.
func buildSoftHSMEnvironment() (softHSMEnvironment, error) {
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
		return softHSMEnvironment{}, errSoftHSMMissing
	}

	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		return softHSMEnvironment{}, errSoftHSMMissing
	}

	directory, err := os.MkdirTemp("", "trebaruna-softhsm")
	if err != nil {
		return softHSMEnvironment{}, err
	}
	tokenDirectory := filepath.Join(directory, "tokens")
	if err := os.MkdirAll(tokenDirectory, 0o700); err != nil {
		return softHSMEnvironment{}, err
	}

	configuration := filepath.Join(directory, "softhsm2.conf")
	content := "directories.tokendir = " + tokenDirectory + "\n" +
		"objectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(configuration, []byte(content), 0o600); err != nil {
		return softHSMEnvironment{}, err
	}
	os.Setenv("SOFTHSM2_CONF", configuration)

	return softHSMEnvironment{module: module, pin: "1234", soPin: "123456", directory: directory}, nil
}

// keyPair generates a key inside the token.
func (h softHSM) keyPair(t *testing.T, identifier, label string) {
	t.Helper()

	tool, err := exec.LookPath("pkcs11-tool")
	if err != nil {
		t.Skip("pkcs11-tool is not available")
	}

	command := exec.Command(tool, "--module", h.module, "--slot", h.slot,
		"--login", "--pin", h.pin,
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
	token.keyPair(t, "01", "signing-key")

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
	token.keyPair(t, "01", "signing-key")

	// Issue a certificate for the token's public key, the way a CA would.
	certificatePEM := issueCertificateForToken(t, token, "01")
	if certificatePEM == nil {
		t.Skip("openssl is not available to issue a certificate")
	}

	// Import the certificate back so the token pairs it with its key.
	importCertificate(t, token, "01", "signing-key", certificatePEM)

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
	return issueCertificateWithUsage(t, token, identifier, "")
}

// issueCertificateWithUsage is issueCertificateForToken with a key usage
// extension ("nonRepudiation", "digitalSignature", ...), so a card can carry an
// authentication and a signature certificate like a real one. Every
// certificate of a token is issued by the same CA, with its own serial.
func issueCertificateWithUsage(t *testing.T, token softHSM, identifier, keyUsage string) []byte {
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
	publicPath := filepath.Join(token.directory, "public-"+identifier+".der")
	command := exec.Command(tool, "--module", token.module, "--slot", token.slot, "--login", "--pin", token.pin,
		"--id", identifier, "--read-object", "--type", "pubkey", "--output-file", publicPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("read public key: %v\n%s", err, output)
	}

	publicPEM := filepath.Join(token.directory, "public-"+identifier+".pem")
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
	if _, err := os.Stat(caCert); err != nil {
		generate := exec.Command(openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
			"-keyout", caKey, "-out", caCert, "-days", "2", "-subj", "/CN=Token Test CA")
		if output, err := generate.CombinedOutput(); err != nil {
			t.Fatalf("create CA: %v\n%s", err, output)
		}
	}

	// The CSR is built and signed by the token itself, so the certificate binds
	// the key that will actually sign. Fetching a certificate for a different key
	// is the mistake that produced "Signature is Invalid" the first time.
	request := filepath.Join(token.directory, "request-"+identifier+".der")
	buildCertificationRequest(t, token, identifier, request)

	signature := filepath.Join(token.directory, "request-"+identifier+".sig")
	sign := exec.Command(tool, "--module", token.module, "--slot", token.slot, "--login", "--pin", token.pin,
		"--id", identifier, "--sign", "--mechanism", "SHA256-RSA-PKCS",
		"--input-file", request, "--output-file", signature)
	if output, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("sign the request: %v\n%s", err, output)
	}

	csr := filepath.Join(token.directory, "request-"+identifier+".csr")
	assembleCertificationRequest(t, request, signature, csr)

	certificate := filepath.Join(token.directory, "certificate-"+identifier+".pem")
	arguments := []string{"x509", "-req", "-in", csr, "-CA", caCert,
		"-CAkey", caKey, "-CAcreateserial", "-days", "2", "-out", certificate}
	if keyUsage != "" {
		extensions := filepath.Join(token.directory, "usage-"+identifier+".cnf")
		if err := os.WriteFile(extensions, []byte("keyUsage = critical, "+keyUsage+"\n"), 0o600); err != nil {
			t.Fatalf("write extensions: %v", err)
		}
		arguments = append(arguments, "-extfile", extensions)
	}
	issue := exec.Command(openssl, arguments...)
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

	publicPath := filepath.Join(token.directory, "public-"+identifier+".der")
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

	path := filepath.Join(token.directory, "import-"+identifier+".pem")
	if err := os.WriteFile(path, certificate, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	command := exec.Command(tool, "--module", token.module, "--slot", token.slot, "--login", "--pin", token.pin,
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
