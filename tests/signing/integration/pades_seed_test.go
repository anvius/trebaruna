package integration_test

// A signature field's seed values (ISO 32000-1, 12.7.4.5, tables 234 and
// 235): what the field requires of a signature is met, or the signature is
// refused saying what the form asks; the encoding is the first of the
// field's that trebaruna writes.

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitorus/pdf"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
)

func TestASignatureMeetsWhatItsFieldRequires(t *testing.T) {
	fixture, authority := newFixture(t), newLocalTSA(t)
	block, _ := pem.Decode(readFile(t, fixture.certPath))
	own := fmt.Sprintf("<%X>", block.Bytes)
	other := fmt.Sprintf("<%X>", authority.ca.Raw)

	for name, check := range map[string]struct {
		seed, reason, tsa  string
		refusal, subFilter string
		// untimed keeps level B though an authority is named.
		untimed bool
	}{
		"the older encoding asked":        {seed: "/SubFilter [/adbe.pkcs7.detached /ETSI.CAdES.detached]", subFilter: "adbe.pkcs7.detached"},
		"an encoding not written, advice": {seed: "/SubFilter [/adbe.x509.rsa_sha1]", subFilter: "ETSI.CAdES.detached"},
		"an encoding not written":         {seed: "/SubFilter [/adbe.x509.rsa_sha1] /Ff 2", refusal: "encoded as adbe.x509.rsa_sha1"},
		"another handler":                 {seed: "/Filter /Other.Handler /Ff 1", refusal: "signature handler Other.Handler"},
		"SHA-1 alone":                     {seed: "/DigestMethod [/SHA1] /Ff 64", refusal: "a digest by SHA1"},
		"SHA-256 among others":            {seed: "/DigestMethod [/SHA1 /SHA256] /Ff 64", subFilter: "ETSI.CAdES.detached"},
		"a reason of the list":            {seed: "/Reasons [(Aprobado) (Rechazado)] /Ff 8", reason: "Aprobado", subFilter: "ETSI.CAdES.detached"},
		"a reason off the list":           {seed: "/Reasons [(Aprobado) (Rechazado)] /Ff 8", reason: "Visto", refusal: "Aprobado; Rechazado"},
		"no reason given":                 {seed: "/Reasons [(Aprobado)] /Ff 8", refusal: "--reason: Aprobado"},
		"no reason allowed":               {seed: "/Reasons [(.)] /Ff 8", reason: "Visto", refusal: "no reason"},
		"the reasons as advice":           {seed: "/Reasons [(Aprobado)]", reason: "Visto", subFilter: "ETSI.CAdES.detached"},
		"a certification":                 {seed: "/MDP << /P 2 >>", refusal: "certification signature (DocMDP 2)"},
		"legal attestations":              {seed: "/LegalAttestation [(x)] /Ff 16", refusal: "legal attestations"},
		"revocation inside":               {seed: "/AddRevInfo true /Ff 32", refusal: "adbe-revocationInfoArchival"},
		"a timestamp, none taken":         {seed: "/TimeStamp << /URL (http://tsa.invalid) /Ff 1 >>", refusal: "--tsa http://tsa.invalid"},
		"a timestamp from its authority":  {seed: "/TimeStamp << /URL (http://tsa.invalid) /Ff 1 >>", tsa: "http://tsa.invalid", subFilter: "ETSI.CAdES.detached"},
		"a timestamp from another":        {seed: "/TimeStamp << /URL (http://tsa.invalid) /Ff 1 >>", tsa: "http://other.invalid", refusal: "a timestamp from"},
		"its authority named, level B":    {seed: "/TimeStamp << /URL (http://tsa.invalid) /Ff 1 >>", tsa: "http://tsa.invalid", untimed: true, refusal: "sign at level T"},
		"the signer's own certificate":    {seed: "/Cert << /Subject [" + own + "] /Ff 1 >>", subFilter: "ETSI.CAdES.detached"},
		"another certificate":             {seed: "/Cert << /Subject [" + other + "] /Ff 1 >>", refusal: "among the ones it names"},
		"its issuer":                      {seed: "/Cert << /Issuer [" + own + "] /Ff 2 >>", subFilter: "ETSI.CAdES.detached"},
		"another issuer":                  {seed: "/Cert << /Issuer [" + other + "] /Ff 2 >>", refusal: "issued by one of the authorities"},
		"a policy it lacks":               {seed: "/Cert << /OID [(1.3.6.1.4.1.5734.3.5)] /Ff 4 >>", refusal: "under one of the policies 1.3.6.1.4.1.5734.3.5"},
		"its holder's name":               {seed: "/Cert << /SubjectDN [<< /CN (Mario Rossi) /O (Studio Rossi) >>] /Ff 8 >>", subFilter: "ETSI.CAdES.detached"},
		"another holder's name":           {seed: "/Cert << /SubjectDN [<< /CN (Luigi Bianchi) >>] /Ff 8 >>", refusal: "holder's name"},
		"its key usage":                   {seed: "/Cert << /KeyUsage [(11XXXXXXX)] /Ff 32 >>", subFilter: "ETSI.CAdES.detached"},
		"another key usage":               {seed: "/Cert << /KeyUsage [(1X1XXXXXX)] /Ff 32 >>", refusal: "key usage 1X1XXXXXX"},
		"a certificate as advice":         {seed: "/Cert << /Subject [" + other + "] >>", subFilter: "ETSI.CAdES.detached"},
	} {
		request := application.PadesRequest{Content: formPDFWith("/SV << /Type /SV "+check.seed+" >>", false, false), Signer: pemSigner(t, fixture),
			Level: domain.BES, Field: "Firma1", Invisible: true, Reason: check.reason, SignedAt: timeNow()}
		if check.tsa != "" {
			request.Level, request.TimestampURL = domain.T, check.tsa
		}
		if check.untimed {
			request.Level = domain.BES
		}
		signed, err := infrastructure.NewPadesSigner(authority).SignPades(context.Background(), request)
		if check.refusal != "" {
			if err == nil || !strings.Contains(err.Error(), check.refusal) {
				t.Errorf("%s: %v, want a refusal naming %q", name, err, check.refusal)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		reader, err := pdf.NewReader(bytes.NewReader(signed), int64(len(signed)))
		if err != nil {
			t.Fatal(err)
		}
		value := reader.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(0).Key("V")
		if value.Key("SubFilter").Name() != check.subFilter {
			t.Errorf("%s: encoded as %s, want %s", name, value.Key("SubFilter").Name(), check.subFilter)
		}
		if reports := verifyPDF(t, authority, signed); len(reports) != 1 || reports[0].Integrity != verificationdomain.StatusGood {
			t.Errorf("%s: %+v", name, reports)
		}
		if _, err := exec.LookPath("pdfsig"); err == nil && check.subFilter == "adbe.pkcs7.detached" {
			path := filepath.Join(t.TempDir(), "seeded.pdf")
			os.WriteFile(path, signed, 0o600)
			if output, err := exec.Command("pdfsig", path).CombinedOutput(); err != nil ||
				!strings.Contains(string(output), "Signature Validation: Signature is Valid.") || !strings.Contains(string(output), "adbe.pkcs7.detached") {
				t.Errorf("%s: pdfsig: %v\n%s", name, err, output)
			}
		}
	}
}
