package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type batchReport struct {
	Signed  int `json:"signed"`
	Failed  int `json:"failed"`
	Results []struct {
		Document string `json:"document"`
		Error    string `json:"error"`
		Receipt  *struct {
			Path   string `json:"path"`
			Format string `json:"format"`
		} `json:"receipt"`
	} `json:"results"`
	Network []json.RawMessage `json:"network"`
}

func TestSeveralDocumentsAreSignedInOneRunEachInItsFormat(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	pdf := writeOnePagePDF(t)
	xml := writeDocument(t, "fattura.xml", "<fattura/>")
	text := writeDocument(t, "nota.txt", "nota\n")
	missing := filepath.Join(t.TempDir(), "assente.pdf")

	stdout, _, code := run("sign", pdf, xml, text, missing, "--p12", key, "--json")
	if code != 1 {
		t.Errorf("exit %d, want 1: one document failed", code)
	}
	var report batchReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if report.Signed != 3 || report.Failed != 1 || len(report.Results) != 4 {
		t.Fatalf("report = %+v", report)
	}
	formats := map[string]string{}
	for _, result := range report.Results {
		if result.Receipt != nil {
			formats[result.Document] = result.Receipt.Format
			if _, err := os.Stat(result.Receipt.Path); err != nil {
				t.Errorf("%s: the signed file is missing", result.Document)
			}
		}
	}
	if formats[pdf] != "pades" || formats[xml] != "xades" || formats[text] != "cades" {
		t.Errorf("formats = %v, want each inferred from its own suffix", formats)
	}
	if report.Results[3].Error == "" || report.Network == nil {
		t.Errorf("the missing document must say why, and the batch must state its connections: %+v", report)
	}
}

func TestABatchCannotShareOneOutputName(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	if _, _, code := run("sign", writeOnePagePDF(t), writeOnePagePDF(t), "--p12", key, "--out", "x.pdf"); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}

func TestABatchCanForceOneFormat(t *testing.T) {
	key := writeProtectedP12(t, "segreto")
	t.Setenv("TREBARUNA_PASSPHRASE", "segreto")
	stdout, stderr, code := run("sign", writeOnePagePDF(t), writeDocument(t, "a.xml", "<a/>"), "--p12", key, "--format", "cades", "--detached", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var report batchReport
	_ = json.Unmarshal([]byte(stdout), &report)
	for _, result := range report.Results {
		if result.Receipt == nil || filepath.Ext(result.Receipt.Path) != ".p7s" {
			t.Errorf("%s: want a detached .p7s, got %+v", result.Document, result.Receipt)
		}
	}
}
