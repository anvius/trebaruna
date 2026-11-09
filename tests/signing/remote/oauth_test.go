package remote_test

// The OAuth2 authorisation-code flow of a CSC service: signing in, and
// authorising a signature, in the person's browser. The browser here is
// curl following the authorisation server's redirect back to trebaruna's
// loopback address, as a browser would once the person agreed.

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	cscclient "codeberg.org/simplicer/trebaruna/src/signing/infrastructure/csc"
	"codeberg.org/simplicer/trebaruna/tests/support/csc"
)

// curlBrowser makes $BROWSER a browser that agrees at once.
func curlBrowser(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl stands in for the browser")
	}
	browser := filepath.Join(t.TempDir(), "browser")
	if err := os.WriteFile(browser, []byte("#!/bin/sh\nexec curl -sS -L -o /dev/null \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BROWSER", browser)
}

func verifyInOpenSSL(t *testing.T, server *csc.Server, signed []byte) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		return
	}
	directory := t.TempDir()
	envelope, ca := filepath.Join(directory, "signed.p7m"), filepath.Join(directory, "ca.pem")
	os.WriteFile(envelope, signed, 0o600)
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.CA.Raw}), 0o600)
	output, err := exec.Command("openssl", "cms", "-verify", "-inform", "DER", "-in", envelope, "-CAfile", ca,
		"-purpose", "any", "-out", os.DevNull).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "Verification successful") {
		t.Fatalf("openssl: %v\n%s", err, output)
	}
}

func signCades(t *testing.T, service domain.RemoteService) ([]byte, error) {
	t.Helper()
	return infrastructure.NewCadesSigner(nil).SignCades(context.Background(), application.CadesRequest{
		Content: []byte("autorizzato nel browser\n"), Signer: remoteSigner(t, service), Level: domain.BES})
}

// TestSigningInThroughTheBrowser: no token, no password: the person signs
// in at the provider's OAuth2 server, and the token it gives signs.
func TestSigningInThroughTheBrowser(t *testing.T) {
	curlBrowser(t)
	server := csc.Start(t)
	signed, err := signCades(t, domain.RemoteService{Address: server.URL, Credential: "rsa-explicit", PIN: csc.PIN,
		OAuthClient: csc.OAuthClient})
	if err != nil {
		t.Fatal(err)
	}
	calls := server.Calls()
	for _, endpoint := range []string{"info", "oauth2/authorize", "oauth2/token", "credentials/authorize", "signatures/signHash"} {
		if !slices.Contains(calls, endpoint) {
			t.Errorf("%s was not called: %v", endpoint, calls)
		}
	}
	verifyInOpenSSL(t, server, signed)
}

// TestASignatureAuthorisedInTheBrowser: an oauth2code credential has each
// signature authorised by the person; the credential-scoped token, bound to
// the hash, stands in for the activation data.
func TestASignatureAuthorisedInTheBrowser(t *testing.T) {
	curlBrowser(t)
	server := csc.Start(t)
	service := domain.RemoteService{Address: server.URL, Credential: "rsa-oauth", Token: csc.Token}
	if _, err := signCades(t, service); err == nil || !strings.Contains(err.Error(), "--csc-client") {
		t.Errorf("without a client id: %v", err)
	}

	service.OAuthClient = csc.OAuthClient
	signed, err := signCades(t, service)
	if err != nil {
		t.Fatal(err)
	}
	calls := server.Calls()
	if !slices.Contains(calls, "oauth2/token") || slices.Contains(calls, "credentials/authorize") {
		t.Errorf("calls: %v", calls)
	}
	verifyInOpenSSL(t, server, signed)

	server.Refuse = true
	service.Credential, service.OTP = "rsa-oauth", "another service description, read afresh"
	if _, err := signCades(t, service); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("a refusal in the browser: %v", err)
	}
}

// TestTheBrowserMustComeBackWithThisRequest: a code that comes back with
// another state is not exchanged, and the redirect stays on this computer.
func TestTheBrowserMustComeBackWithThisRequest(t *testing.T) {
	server := csc.Start(t)
	oauth := cscclient.OAuth{
		Base: strings.TrimSuffix(server.URL, "/csc/v2"), ClientID: csc.OAuthClient, HTTP: http.DefaultClient,
		Open: func(address string) error {
			parsed, _ := url.Parse(address)
			back, _ := url.Parse(parsed.Query().Get("redirect_uri"))
			back.RawQuery = url.Values{"code": {"stolen"}, "state": {"forged"}}.Encode()
			go http.Get(back.String())
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := oauth.ServiceToken(ctx); err == nil || !strings.Contains(err.Error(), "state") {
		t.Errorf("a forged state: %v", err)
	}
	if slices.Contains(server.Calls(), "oauth2/token") {
		t.Error("a code with a forged state was exchanged")
	}

	plain := oauth
	plain.Base = "http://provider.example"
	if _, err := plain.ServiceToken(ctx); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Errorf("an OAuth2 server over plain HTTP elsewhere: %v", err)
	}
	oauth.Redirect = "http://provider.example/callback"
	if _, err := oauth.ServiceToken(ctx); err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("a redirect to another computer: %v", err)
	}
	if _, err := domain.NewSigner("x", domain.FromRemote, domain.WithRemoteService(domain.RemoteService{
		Address: server.URL, OAuthClient: csc.OAuthClient, OAuthRedirect: "https://provider.example/callback"})); err == nil {
		t.Error("a redirect off this computer must be refused when the signer is made")
	}
}
