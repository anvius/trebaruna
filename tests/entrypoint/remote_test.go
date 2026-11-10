package cli_test

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/tests/support/csc"
)

// TestSignWithARemoteKeyAndSaySo: the receipt names the provider, the
// connections are recorded, and neither the token nor the PIN shows.
func TestSignWithARemoteKeyAndSaySo(t *testing.T) {
	server := csc.Start(t)
	t.Setenv("TREBARUNA_CSC_TOKEN", csc.Token)
	t.Setenv("TREBARUNA_PIN", csc.PIN)
	document := writeDocument(t, "solicitud.txt", "solicitud\n")

	stdout, stderr, code := run("sign", document, "--csc", server.URL, "--credential", "rsa-explicit", "--format", "cades")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	// The identity shown and the signature come from one reading of the
	// credential: the provider is asked once.
	if info := countOf(server.Calls(), "credentials/info"); info != 1 {
		t.Errorf("credentials/info asked %d times: %v", info, server.Calls())
	}
	address, _ := url.Parse(server.URL)
	if !strings.Contains(stdout, "key     remote, kept by "+address.Host+" (CSC)") {
		t.Errorf("the receipt must say the key is remote:\n%s", stdout)
	}

	jsonOut, _, code := run("sign", document, "--csc", server.URL, "--credential", "rsa-explicit", "--format", "cades",
		"--out", document+".second.p7m", "--json")
	if code != 0 {
		t.Fatalf("JSON run: exit %d", code)
	}
	if !strings.Contains(jsonOut, `"key_source": "csc"`) || !strings.Contains(jsonOut, `"remote_service": "`+address.Host+`"`) {
		t.Errorf("JSON receipt: %s", jsonOut)
	}
	for _, output := range []string{stdout, jsonOut, stderr} {
		if strings.Contains(output, csc.Token) || strings.Contains(output, csc.PIN) {
			t.Error("a secret reached the output")
		}
	}
	if !strings.Contains(stdout, "remote-signing") {
		t.Errorf("the connections to the provider are listed:\n%s", stdout)
	}
	if result := verifyJSON(t, document+".p7m"); result.Signers[0].Integrity != "good" {
		t.Errorf("verify: %+v", result.Signers[0])
	}

	if _, stderr, code := run("sign", document, "--csc", server.URL, "--p12", "x.p12"); code == 0 || !strings.Contains(stderr, "ambiguous") {
		t.Errorf("two key sources: exit %d, %s", code, stderr)
	}
}

func countOf(calls []string, endpoint string) int {
	count := 0
	for _, call := range calls {
		if call == endpoint {
			count++
		}
	}
	return count
}

// TestAnotherCredentialIsReadAgain: what is remembered is one service's
// credential; another credential of the same service is asked for.
func TestAnotherCredentialIsReadAgain(t *testing.T) {
	server := csc.Start(t)
	t.Setenv("TREBARUNA_CSC_TOKEN", csc.Token)
	t.Setenv("TREBARUNA_PIN", csc.PIN)
	document := writeDocument(t, "solicitud.txt", "solicitud\n")
	for _, credential := range []string{"rsa-explicit", "ecdsa-implicit"} {
		if _, stderr, code := run("sign", document, "--csc", server.URL, "--credential", credential, "--format", "cades",
			"--out", document+"."+credential+".p7m"); code != 0 {
			t.Fatalf("%s: %s", credential, stderr)
		}
	}
	if info := countOf(server.Calls(), "credentials/info"); info != 2 || !slices.Contains(server.Calls(), "signatures/signHash") {
		t.Errorf("calls: %v", server.Calls())
	}
}

// TestSignWithASignatureAuthorisedInTheBrowser: --csc-client lets the
// person authorise the signature at the provider's OAuth2 server; neither
// the client secret nor the token shows.
func TestSignWithASignatureAuthorisedInTheBrowser(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl stands in for the browser")
	}
	browser := filepath.Join(t.TempDir(), "browser")
	if err := os.WriteFile(browser, []byte("#!/bin/sh\nexec curl -sS -L -o /dev/null \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BROWSER", browser)
	server := csc.Start(t)
	server.ClientSecret = "client-secret-value"
	t.Setenv("TREBARUNA_CSC_TOKEN", csc.Token)
	t.Setenv("TREBARUNA_CSC_CLIENT_SECRET", "client-secret-value")
	document := writeDocument(t, "delibera.txt", "delibera\n")

	stdout, stderr, code := run("sign", document, "--csc", server.URL, "--credential", "rsa-oauth", "--csc-client", csc.OAuthClient,
		"--format", "cades", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !slices.Contains(server.Calls(), "oauth2/token") {
		t.Errorf("calls: %v", server.Calls())
	}
	for _, output := range []string{stdout, stderr} {
		if strings.Contains(output, "client-secret-value") || strings.Contains(output, csc.Token) {
			t.Error("a secret reached the output")
		}
	}
	if _, stderr, code := run("sign", document, "--csc", server.URL, "--csc-client", csc.OAuthClient,
		"--csc-redirect", "https://provider.example/back", "--format", "cades", "--out", document+".x.p7m"); code == 0 ||
		!strings.Contains(stderr, "redirect") {
		t.Errorf("a redirect off this computer: exit %d, %s", code, stderr)
	}
}

// TestTheCredentialsOfAServiceAreListed: token --csc names each credential
// beside its certificate, in text and in the cards' JSON.
func TestTheCredentialsOfAServiceAreListed(t *testing.T) {
	server := csc.Start(t)
	t.Setenv("TREBARUNA_CSC_TOKEN", csc.Token)
	text, stderr, code := run("token", "--csc", server.URL)
	if code != 0 || !strings.Contains(text, "credential: rsa-explicit (--credential)") || !strings.Contains(text, "MARIO ROSSI (REMOTE)") {
		t.Fatalf("exit %d: %s%s", code, text, stderr)
	}
	listing, _, code := run("token", "--csc", server.URL, "--credential", "rsa-explicit", "--json")
	if code != 0 || !strings.Contains(listing, `"credential": "rsa-explicit"`) || strings.Contains(listing, "ecdsa-implicit") ||
		!strings.Contains(listing, `"pin": "ready"`) || !strings.Contains(listing, `"signs_by_default": true`) {
		t.Errorf("JSON: %s", listing)
	}
	if _, stderr, code := run("token", "--csc", "http://provider.example/csc/v2"); code == 0 || !strings.Contains(stderr, "https") {
		t.Errorf("plain HTTP elsewhere: exit %d, %s", code, stderr)
	}
}
