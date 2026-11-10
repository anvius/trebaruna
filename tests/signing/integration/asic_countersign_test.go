package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
)

// TestAnASiCECadesSignatureIsCounterSignedAtLTA in its file: the archive
// timestamp that seals the counter-signature covers what the signature
// signs, the ASiCManifest that names it, so the verifier reads it bound.
func TestAnASiCECadesSignatureIsCounterSignedAtLTA(t *testing.T) {
	_, signer := cadesFixture(t)
	authority := newLocalTSA(t)
	containers := infrastructure.AsicContainers{}
	documents := []application.ContainerEntry{{Name: "acta.txt", Content: []byte("acta\n")}, {Name: "plano.pdf", Content: []byte("%PDF-1.4\n")}}
	manifest, err := containers.Manifest("META-INF/signature001.p7s", documents)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := infrastructure.NewCadesSigner(authority).SignCades(context.Background(), application.CadesRequest{
		Content: manifest, Detached: true, Signer: signer, Level: signingdomain.BES})
	if err != nil {
		t.Fatal(err)
	}
	container, err := containers.WriteContainer(signingdomain.ASiCE, append(documents,
		application.ContainerEntry{Name: "META-INF/ASiCManifest001.xml", Content: manifest},
		application.ContainerEntry{Name: "META-INF/signature001.p7s", Content: signature}))
	if err != nil {
		t.Fatal(err)
	}

	countersigned, err := application.NewCountersignContainer(containers, infrastructure.NewCadesSigner(authority), infrastructure.NewXadesSigner(authority)).
		Execute(context.Background(), application.Request{Signer: signer, Level: signingdomain.LTA, EmbedRevocation: true,
			TimestampURL: "http://tsa.example.invalid", Countersign: "leaves"}, container)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "expediente.asice")
	if err := os.WriteFile(path, countersigned.Content, 0o600); err != nil {
		t.Fatal(err)
	}
	reports, err := verificationinfra.NewAsicVerifier(verificationinfra.NewCadesVerifier(), verificationinfra.NewXadesVerifier()).Extract(path)
	if err != nil || len(reports) != 2 || countersigned.Format != signingdomain.Cades {
		t.Fatalf("%+v %v %s", reports, err, countersigned.Format)
	}
	archives := 0
	for _, report := range reports {
		if report.Integrity != verificationdomain.StatusGood {
			t.Errorf("%s is %s", report.FieldName, report.Integrity)
		}
		for _, finding := range report.Findings {
			switch finding.Code {
			case "timestamp.archival":
				archives++
			case "timestamp.archive_unbound":
				t.Errorf("%s: %s", report.FieldName, finding.Detail)
			}
		}
	}
	if archives != 1 || reports[1].Countersigns != reports[0].FieldName {
		t.Errorf("%d archive timestamps; %q counter-signs %q", archives, reports[1].FieldName, reports[1].Countersigns)
	}
}
