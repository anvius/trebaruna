package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"codeberg.org/simplicer/firma-it/src/verification/application"
	verification "codeberg.org/simplicer/firma-it/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/firma-it/src/verification/infrastructure"
	"codeberg.org/simplicer/firma-it/src/verification/messaging"
)

// Verification exit codes. They are distinct on purpose: a script must be able
// to tell "the file was altered" from "we do not know who signed it".
const (
	exitVerified   = 0
	exitTampered   = 1
	exitUnverified = 3
)

// runVerify implements `firma-it verify`.
func runVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		format    = flags.String("format", "", "container: pdf | cades | xades (default: from the suffix)")
		territory = flags.String("territory", defaultTerritory(), "trust list to use, e.g. IT or ES")
		asJSON    = flags.Bool("json", false, "machine-readable output")
		offline   = flags.Bool("offline", true, "do not contact OCSP/CRL responders")
		lang      = flags.String("lang", "", "language for messages: es | it | en")
	)

	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: firma-it verify <document> [flags]")
		flags.PrintDefaults()
	}

	path, remaining, err := extractDocument(args)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		flags.Usage()
		return exitUsage
	}
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}

	pdfVerifier := verificationinfra.NewPDFVerifier()
	// Revocation checks reach the network, so they are opt-in: a verification
	// that silently calls OCSP is a verification that fails on a plane.
	pdfVerifier.CheckRevocation = !*offline

	useCase := application.NewVerifyDocument(
		pdfVerifier,
		verificationinfra.NewCadesVerifier(),
		verificationinfra.NewCachedTrustProvider(),
		systemClock{},
	).WithXades(verificationinfra.NewXadesVerifier())

	if !*offline {
		// Our own checker replaces the library's: it distinguishes an answered
		// "not revoked" from an unanswered query, and reports which responder
		// spoke. The library collapses both into a boolean.
		useCase = useCase.WithRevocation(verificationinfra.NewOCSPChecker())
	}

	report, err := useCase.Execute(application.Request{
		Path:      path,
		Format:    *format,
		Territory: *territory,
	})
	if err != nil {
		fmt.Fprintf(stderr, "verification failed: %v\n", err)
		return exitUnverified
	}

	catalogue := messaging.For(firstNonEmptyString(*lang, os.Getenv("LANG")))

	if *asJSON {
		encodeVerificationJSON(stdout, report)
	} else {
		printVerification(stdout, report, catalogue)
	}

	switch report.Verdict() {
	case verification.TrustBroken:
		return exitTampered
	case verification.TrustUntrusted, verification.TrustUnknown:
		return exitUnverified
	}
	return exitVerified
}

// systemClock is the production clock.
type systemClock struct{}

// Now returns the current time.
func (systemClock) Now() time.Time { return time.Now() }

// defaultTerritory guesses from the locale, defaulting to the EU list.
func defaultTerritory() string {
	locale := firstNonEmptyString(os.Getenv("LC_ALL"), os.Getenv("LANG"))
	if len(locale) >= 2 {
		switch strings.ToUpper(locale[:2]) {
		case "IT", "ES", "DE", "FR", "PT", "NL", "BE", "AT", "PL", "SE":
			return strings.ToUpper(locale[:2])
		}
	}
	return "EU"
}

// firstNonEmptyString returns the first non-empty value.
func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// verificationJSON is the stable shape consumed by scripts and agents.
type verificationJSON struct {
	Path       string        `json:"path"`
	Format     string        `json:"format"`
	Signed     bool          `json:"signed"`
	Verdict    string        `json:"verdict"`
	VerifiedAt string        `json:"verified_at"`
	Signers    []signerJSON  `json:"signers"`
	Warnings   []findingJSON `json:"warnings,omitempty"`
}

// signerJSON is one signature in the JSON output.
type signerJSON struct {
	Field     string `json:"field"`
	Signer    string `json:"signer"`
	ID        string `json:"identifier,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	Format    string `json:"format"`
	SignedAt  string `json:"signed_at,omitempty"`
	Timestamp bool   `json:"timestamped"`
	TSA       string `json:"timestamp_authority,omitempty"`
	Integrity string `json:"integrity"`
	Trust     string `json:"trust"`
	Qualified bool   `json:"qualified"`
	// Qualification explains the QES verdict: which condition held and which
	// did not. A boolean alone cannot be audited.
	Qualification *qualificationJSON `json:"qualification,omitempty"`
	// Revocation is the outcome of a status check, including the case where none
	// could be made. A boolean would hide that difference.
	Revocation *revocationJSON `json:"revocation,omitempty"`
	// TimestampProof is the evidence about the authority behind the token. It
	// is separate from "timestamped" because a token can be bound without its
	// authority being accredited.
	TimestampProof *timestampJSON `json:"timestamp,omitempty"`
	Expired        bool           `json:"certificate_expired_now"`
	ExpiredAt      string         `json:"certificate_expired_at_signing"`
	SelfSign       bool           `json:"self_signed"`
	Findings       []findingJSON  `json:"findings"`
}

// revocationJSON is the outcome of an OCSP or CRL query.
type revocationJSON struct {
	Status    string `json:"status"`
	Checked   bool   `json:"checked"`
	RevokedAt string `json:"revoked_at,omitempty"`
	Source    string `json:"source,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// timestampJSON is what was proven about the timestamp authority.
type timestampJSON struct {
	Bound        bool     `json:"bound"`
	Accredited   bool     `json:"accredited"`
	TimeStamping bool     `json:"time_stamping_certificate"`
	Service      string   `json:"service,omitempty"`
	Provider     string   `json:"provider,omitempty"`
	GrantedSince string   `json:"granted_since,omitempty"`
	Missing      []string `json:"missing,omitempty"`
}

// qualificationJSON is the evidence behind a QES verdict.
type qualificationJSON struct {
	CertificateQualified bool     `json:"certificate_qualified"`
	DeviceQualified      bool     `json:"device_qualified"`
	DeviceSource         string   `json:"device_source,omitempty"`
	ServiceListed        bool     `json:"service_listed"`
	ServiceProvider      string   `json:"service_provider,omitempty"`
	ServiceName          string   `json:"service_name,omitempty"`
	ServiceGrantedSince  string   `json:"service_granted_since,omitempty"`
	Missing              []string `json:"missing,omitempty"`
}

// findingJSON is one statement.
type findingJSON struct {
	Code    string `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// encodeVerificationJSON writes the report for machines.
func encodeVerificationJSON(writer io.Writer, report verification.DocumentReport) {
	payload := verificationJSON{
		Path:       report.Path,
		Format:     report.Format,
		Signed:     report.Signed,
		Verdict:    string(report.Verdict()),
		VerifiedAt: report.VerifiedAt.Format(time.RFC3339),
	}

	for _, signer := range report.Signers {
		entry := signerJSON{
			Field:     signer.FieldName,
			Signer:    signer.SignerName,
			ID:        signer.Identifier,
			Issuer:    signer.Issuer,
			Format:    signer.Format,
			Timestamp: signer.Timestamped,
			TSA:       signer.TimestampAuthority,
			Integrity: string(signer.Integrity),
			Trust:     string(signer.Trust),
			Qualified: signer.Qualified,
			Expired:   signer.ExpiredNow,
			SelfSign:  signer.SelfSigned,
		}
		if evidence := signer.Qualification; evidence.CertificateQualified || evidence.ServiceListed || evidence.DeviceQualified {
			entry.Qualification = &qualificationJSON{
				CertificateQualified: evidence.CertificateQualified,
				DeviceQualified:      evidence.DeviceQualified,
				DeviceSource:         evidence.DeviceSource,
				ServiceListed:        evidence.ServiceListed,
				ServiceProvider:      evidence.ServiceProvider,
				ServiceName:          evidence.ServiceName,
				Missing:              evidence.Missing(signer.SignedAt),
			}
			if !evidence.ServiceGrantedSince.IsZero() {
				entry.Qualification.ServiceGrantedSince = evidence.ServiceGrantedSince.Format(time.RFC3339)
			}
		}
		if status := signer.Revocation.Status; status.Status != "" {
			entry.Revocation = &revocationJSON{
				Status:  string(status.Status),
				Checked: signer.Revocation.Checked,
				Source:  status.Source,
				Reason:  status.Reason,
			}
			if !status.RevokedAt.IsZero() {
				entry.Revocation.RevokedAt = status.RevokedAt.Format(time.RFC3339)
			}
		}
		if stamp := signer.TimestampEvidence; stamp.Bound {
			entry.TimestampProof = &timestampJSON{
				Bound:        stamp.Bound,
				Accredited:   stamp.Accredited,
				TimeStamping: stamp.CertificateCanTimestamp,
				Service:      stamp.ServiceName,
				Provider:     stamp.ProviderName,
			}
			if !stamp.GrantedSince.IsZero() {
				entry.TimestampProof.GrantedSince = stamp.GrantedSince.Format(time.RFC3339)
			}
			if !stamp.Accredited {
				entry.TimestampProof.Missing = timestampMissing(stamp, signer.SignedAt)
			}
		}
		if !signer.SignedAt.IsZero() {
			entry.SignedAt = signer.SignedAt.Format(time.RFC3339)
		}
		if signer.ExpiredAtSigning {
			entry.ExpiredAt = signer.SignedAt.Format(time.RFC3339)
		}
		for _, finding := range signer.Findings {
			entry.Findings = append(entry.Findings, findingJSON{
				Code: finding.Code, Status: string(finding.Status),
				Message: finding.Message, Detail: finding.Detail,
			})
		}
		payload.Signers = append(payload.Signers, entry)
	}

	for _, warning := range report.Warnings {
		payload.Warnings = append(payload.Warnings, findingJSON{
			Code: warning.Code, Status: string(warning.Status),
			Message: warning.Message, Detail: warning.Detail,
		})
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)
}

// printVerification writes the human report.
func printVerification(writer io.Writer, report verification.DocumentReport, catalogue messaging.Catalogue) {
	fmt.Fprintf(writer, "%s\n", report.Path)
	fmt.Fprintf(writer, "  %s: %s\n", catalogue.LabelFormat, report.Format)

	if !report.Signed {
		fmt.Fprintf(writer, "  %s\n", catalogue.NoSignatures)
		return
	}

	fmt.Fprintf(writer, "  %s: %s\n", catalogue.LabelVerdict, catalogue.VerdictName(report.Verdict()))

	for index, signer := range report.Signers {
		fmt.Fprintf(writer, "\n  %s %d — %s\n", catalogue.LabelSignature, index+1, signer.FieldName)
		fmt.Fprintf(writer, "    %-14s %s\n", catalogue.LabelSigner, signer.SignerName)
		if signer.Identifier != "" {
			fmt.Fprintf(writer, "    %-14s %s\n", catalogue.LabelIdentifier, signer.Identifier)
		}
		if signer.Issuer != "" {
			fmt.Fprintf(writer, "    %-14s %s\n", catalogue.LabelIssuer, signer.Issuer)
		}
		if !signer.SignedAt.IsZero() {
			label := catalogue.LabelSignedAt
			if signer.Timestamped {
				label = catalogue.LabelTimestamped
			}
			fmt.Fprintf(writer, "    %-14s %s\n", label, signer.SignedAt.Format("2006-01-02 15:04:05 -07:00"))
		}
		fmt.Fprintf(writer, "    %-14s %s\n", catalogue.LabelIntegrity, catalogue.StatusName(signer.Integrity))

		for _, finding := range signer.Findings {
			if finding.Status == verification.StatusGood {
				continue
			}
			fmt.Fprintf(writer, "    %s %s\n", catalogue.StatusMark(finding.Status),
				catalogue.FindingName(finding.Code, finding.Message))
		}
	}

	for _, warning := range report.Warnings {
		fmt.Fprintf(writer, "\n  %s %s\n", catalogue.StatusMark(warning.Status),
			catalogue.FindingName(warning.Code, warning.Message))
	}
}

// timestampMissing explains what keeps a timestamp from being accredited.
//
// The reasons are repeated here rather than imported from the domain so the JSON
// stays stable even if the internal wording changes.
func timestampMissing(evidence verification.TimestampEvidence, at time.Time) []string {
	var missing []string
	if !evidence.CertificateCanTimestamp {
		missing = append(missing, "the timestamp certificate lacks the time-stamping key usage")
	}
	if !evidence.ServiceListed {
		missing = append(missing, "no granted TSA/QTST in the authenticated trust list issued it")
	}
	if !evidence.GrantedSince.IsZero() {
		switch {
		case at.IsZero():
			missing = append(missing, "the token time is unknown, so the grant cannot be checked")
		case at.Before(evidence.GrantedSince):
			missing = append(missing, "the authority was not granted yet when the token was issued")
		}
	}
	return missing
}
