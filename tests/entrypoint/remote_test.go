package cli_test

import (
	"net/url"
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
