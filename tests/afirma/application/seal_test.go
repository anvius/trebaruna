package application_test

// visibleSignature: the person places the seal on the PDF the page sent,
// and the signature is made with that place.

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/afirma/application"
	"codeberg.org/simplicer/trebaruna/src/afirma/domain"
	signing "codeberg.org/simplicer/trebaruna/src/signing/domain"
)

func sealRequest(t *testing.T, format, properties, data string) domain.Invocation {
	t.Helper()
	return invocation(t, "afirma://sign?format="+url.QueryEscape(format)+"&algorithm=SHA256&properties="+
		url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(properties)))+data)
}

func TestThePersonPlacesTheSealThePageWants(t *testing.T) {
	key, _ := signing.NewSigner("MARIA", signing.FromP12, signing.WithKeyMaterial([]byte("p12")))
	box := domain.SealBox{Page: 1, LowerLeftX: 300, LowerLeftY: 60, UpperRightX: 520, UpperRightY: 120}
	approver := &sequenceApprover{decisions: []application.Decision{{Approved: true, Key: key, Seal: box}}}
	signer := &recordingSigner{}
	use := application.NewAnswerPage(approver, signer, fixedCertificate{}, &recordingFetcher{}, memoryFiles{}, &recordingCourier{}, nil)
	pdf := "%PDF-1.4 contrato"
	if _, err := use.Execute(context.Background(), sealRequest(t, "PAdES", "visibleSignature=want",
		"&dat="+url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(pdf))))); err != nil {
		t.Fatal(err)
	}
	proposal := approver.proposals[0]
	if proposal.PlaceSeal != "want" || string(proposal.SealDocument) != pdf {
		t.Errorf("the person is asked to place the seal on the PDF: %q, %d bytes", proposal.PlaceSeal, len(proposal.SealDocument))
	}
	properties := signer.requests[0].Properties
	if properties["signaturePositionOnPageLowerLeftX"] != "300" || properties["signaturePositionOnPageUpperRightY"] != "120" || properties["signaturePage"] != "1" {
		t.Errorf("the signature is made where the seal was placed: %v", properties)
	}
}

func TestASealIsAskedOnlyWhereItCanBePlaced(t *testing.T) {
	pdf := "&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 x")))
	for name, test := range map[string]struct {
		format, properties, data, place string
		later                           bool
	}{
		"no visible seal asked":  {"PAdES", "", pdf, "", false},
		"the page placed it":     {"PAdES", "visibleSignature=want\nsignaturePositionOnPageLowerLeftX=1", pdf, "", false},
		"an XML signature":       {"XAdES", "visibleSignature=want", "&dat=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<a/>"))), "", false},
		"auto over a PDF":        {"auto", "visibleSignature=optional", pdf, "optional", false},
		"a PDF fetched later":    {"PAdES", "visibleSignature=want", "&dat=" + url.QueryEscape("https://sede.example/contrato.pdf"), "want", true},
		"a PDF the person picks": {"PAdES", "visibleSignature=want", "", "want", false},
	} {
		approver := &sequenceApprover{decisions: []application.Decision{{}}}
		use := application.NewAnswerPage(approver, &recordingSigner{}, fixedCertificate{}, &recordingFetcher{}, memoryFiles{}, &recordingCourier{}, nil)
		use.Execute(context.Background(), sealRequest(t, test.format, test.properties, test.data))
		if len(approver.proposals) == 0 {
			t.Fatalf("%s: never asked", name)
		}
		proposal := approver.proposals[0]
		said := strings.Contains(strings.Join(proposal.Warnings, "\n"), "fetched only after you approve")
		if proposal.PlaceSeal != test.place || said != test.later {
			t.Errorf("%s: place %q, warned %t", name, proposal.PlaceSeal, said)
		}
	}
}

// TestACounterSignatureIsNotSealed: counter-signatures put no seal on a
// page, whatever the page asks.
func TestACounterSignatureIsNotSealed(t *testing.T) {
	approver := &sequenceApprover{decisions: []application.Decision{{}}}
	use := application.NewAnswerPage(approver, &recordingSigner{}, fixedCertificate{}, &recordingFetcher{}, memoryFiles{}, &recordingCourier{}, nil)
	use.Execute(context.Background(), invocation(t, "afirma://countersign?format=auto&algorithm=SHA256&properties="+
		url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("visibleSignature=want")))+
		"&dat="+url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 x")))))
	if len(approver.proposals) != 1 || approver.proposals[0].PlaceSeal != "" {
		t.Errorf("a counter-signature asked for a seal: %+v", approver.proposals)
	}
}
