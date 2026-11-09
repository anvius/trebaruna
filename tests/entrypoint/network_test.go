package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/tests/support/tsa"
)

type networkReport struct {
	Network []struct {
		Purpose string `json:"purpose"`
		Method  string `json:"method"`
		URL     string `json:"url"`
		Status  int    `json:"status"`
	} `json:"network"`
}

// TestASignatureReportsTheConnectionsItNeeded: a T-level signature talks to a
// timestamp authority, and the receipt must say so (ADR-0010).
func TestASignatureReportsTheConnectionsItNeeded(t *testing.T) {
	authority := tsa.New(t)
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")

	stdout, stderr, code := run("sign", writeOnePagePDF(t), "--p12", key, "--level", "t", "--tsa", authority.URL(t)+"/tsa", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var report networkReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Network) == 0 {
		t.Fatalf("no connections reported for a timestamped signature: %s", stdout)
	}
	connection := report.Network[len(report.Network)-1]
	if connection.Purpose != "timestamp" || connection.Method != "POST" || connection.Status != 200 || !strings.HasSuffix(connection.URL, "/tsa") {
		t.Errorf("connection = %+v", connection)
	}
}

func TestAnOfflineSignatureReportsNoConnections(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")

	stdout, stderr, code := run("sign", writeOnePagePDF(t), "--p12", key, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"network": []`) {
		t.Errorf("an offline signature must state an empty list, got %s", stdout)
	}
}

func TestAStandaloneTimestampReportsItsAuthority(t *testing.T) {
	authority := tsa.New(t)
	file := filepath.Join(t.TempDir(), "nota.txt")
	if err := os.WriteFile(file, []byte("contenuto"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run("timestamp", file, "--tsa", authority.URL(t), "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"purpose": "timestamp"`) {
		t.Errorf("stdout = %s", stdout)
	}
}
