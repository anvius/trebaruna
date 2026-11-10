package integration_test

// The European Commission's DSS library as a common judge, independent of
// trebaruna: what trebaruna signs at its highest levels, CAdES with its
// archive-time-stamp-v3 (which only trebaruna had checked), XAdES, PAdES
// and an ASiC-E container, counter-signed or detached, is validated by
// DSS, offline, with the test authorities as anchors. Each signature must
// be intact and valid with every reference found and intact, each
// timestamp's imprint must match what it seals, and DSS must name the
// baseline level trebaruna meant to write.
//
// DSS_LIB names a directory holding DSS's jars and their dependencies
// (fetched with Maven from eu.europa.ec.joinup.sd-dss, see
// tests/support/dss/README.md); without it, or without Java, the test
// skips. `make check-dss` runs it.

import (
	"context"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	signingdomain "codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	"codeberg.org/simplicer/trebaruna/tests/support/dss"
)

func TestDSSAcceptsWhatTrebarunaSigns(t *testing.T) {
	content, signer := ltaFixture(t)
	authority := newLocalTSAWithStatus(t)
	cades := func(request application.CadesRequest) []byte {
		t.Helper()
		request.Signer, request.TimestampURL, request.EmbedRevocation = signer, "http://tsa.example.invalid", true
		signed, err := infrastructure.NewCadesSigner(authority).SignCades(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}

	t.Run("CAdES-LTA", func(t *testing.T) {
		envelope := cades(application.CadesRequest{Content: content, Level: signingdomain.LTA})
		dss.Judged(t, dss.Judge(t, "acta.pdf.p7m", envelope, nil, authority.ca), 1, "CAdES-BASELINE-LTA", false, "SIGNATURE_TIMESTAMP", "ARCHIVE_TIMESTAMP")
	})

	t.Run("CAdES-LTA counter-signed", func(t *testing.T) {
		original := cades(application.CadesRequest{Content: content, Level: signingdomain.BES})
		countersigned := cades(application.CadesRequest{Content: original, Level: signingdomain.LTA, Countersign: "leaves"})
		dss.Judged(t, dss.Judge(t, "acta.pdf.p7m", countersigned, nil, authority.ca), 2, "CAdES-BASELINE-B", false, "SIGNATURE_TIMESTAMP", "ARCHIVE_TIMESTAMP")
	})

	t.Run("CAdES-T detached", func(t *testing.T) {
		envelope := cades(application.CadesRequest{Content: content, Detached: true, Level: signingdomain.T})
		dss.Judged(t, dss.Judge(t, "acta.pdf.p7s", envelope, map[string][]byte{"acta.pdf": content}, authority.ca), 1, "CAdES-BASELINE-T", true, "SIGNATURE_TIMESTAMP")
	})

	t.Run("XAdES-LTA", func(t *testing.T) {
		request := buildXadesRequest(signer, []byte(`<fattura><numero>7</numero></fattura>`), false)
		request.Level, request.TimestampURL, request.EmbedRevocation = signingdomain.LTA, "http://tsa.example.invalid", true
		signed, err := infrastructure.NewXadesSigner(authority).SignXades(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		dss.Judged(t, dss.Judge(t, "fattura.xml", signed, nil, authority.ca), 1, "XAdES-BASELINE-LTA", false, "SIGNATURE_TIMESTAMP", "ARCHIVE_TIMESTAMP")
	})

	t.Run("PAdES-LTA", func(t *testing.T) {
		signed, err := infrastructure.NewPadesSigner(authority).SignPades(context.Background(), application.PadesRequest{
			Content: content, Signer: signer, Level: signingdomain.LTA, SignedAt: timeNow(), TimestampURL: authority.url(t), EmbedRevocation: true})
		if err != nil {
			t.Fatal(err)
		}
		dss.Judged(t, dss.Judge(t, "acta.pdf", signed, nil, authority.ca), 1, "PAdES-BASELINE-LTA", false, "SIGNATURE_TIMESTAMP", "DOCUMENT_TIMESTAMP")
	})

	t.Run("ASiC-E counter-signed at LTA", func(t *testing.T) {
		containers := infrastructure.AsicContainers{}
		documents := []application.ContainerEntry{{Name: "acta.txt", Content: []byte("acta\n")}, {Name: "plano.pdf", Content: content}}
		manifest, err := containers.Manifest("META-INF/signature001.p7s", documents)
		if err != nil {
			t.Fatal(err)
		}
		signature := cades(application.CadesRequest{Content: manifest, Detached: true, Level: signingdomain.BES})
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
		dss.Judged(t, dss.Judge(t, "expediente.asice", countersigned.Content, nil, authority.ca), 2, "CAdES-BASELINE-B", false, "SIGNATURE_TIMESTAMP", "ARCHIVE_TIMESTAMP")
	})
}
