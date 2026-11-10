package infrastructure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/dss"
	"codeberg.org/simplicer/trebaruna/src/signing/infrastructure/pdffield"
	verificationdomain "codeberg.org/simplicer/trebaruna/src/verification/domain"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign"
)

// PadesSigner produces signed PDFs with pdfsign, adding the visible seal.
//
// pdfsign v1.0.0 supports PAdES B and B-T natively; B-LT and B-LTA return
// "signature format N is not currently supported". Rather than emit a file
// with the wrong profile, this adapter refuses and explains the alternative.
type PadesSigner struct {
	timestamps Timestamper
}

// NewPadesSigner wires the PDF adapter.
func NewPadesSigner(timestamps Timestamper) *PadesSigner {
	return &PadesSigner{timestamps: timestamps}
}

// SignPades signs the PDF and returns the new document bytes.
//
// Levels that embed revocation are produced in two steps: pdfsign signs, then
// this adapter appends a /DSS dictionary in an incremental update. The library
// has no /DSS writer (its only revocation path is a vendor attribute that ETSI
// EN 319 142-1 forbids for PAdES), but it does not need one: the store lives
// outside the signature.
func (s *PadesSigner) SignPades(ctx context.Context, request application.PadesRequest) ([]byte, error) {
	if request.Level.NeedsTimestamp() && request.TimestampURL == "" {
		return nil, fmt.Errorf(
			"%s needs a timestamp authority: pass --tsa <url>", request.Level)
	}

	if request.Level.EmbedsRevocation() && !request.EmbedRevocation {
		return nil, fmt.Errorf(
			"%s needs embedded revocation (DSS) and a source for it.\n"+
				"  options:\n"+
				"    --level lt --online-revocation   query OCSP and embed the answers in /DSS\n"+
				"    --level t                        sign PAdES-B-T (timestamp, no DSS)",
			request.Level,
		)
	}

	if encrypted, err := signable(request); err != nil {
		return nil, err
	} else if encrypted && request.Level.EmbedsRevocation() {
		// The validation material's update would have to be encrypted too,
		// which its writer does not do.
		return nil, fmt.Errorf("%w: level %s on an encrypted PDF; sign it at level T, or decrypt it first", ErrEncryptedPDF, request.Level)
	}

	keyPair, err := LoadKeyPair(request.Signer)
	if err != nil {
		return nil, err
	}
	defer keyPair.Close()

	// trebaruna writes the signature itself when it goes in an existing
	// field, declares a policy (signed attributes the PDF library's builder
	// cannot add) or shows a seal: the library draws the standard fonts
	// with every glyph 500 units wide and writes UTF-8 into WinAnsi
	// strings, so its seals came out spaced apart, "·" as "Â·".
	if request.Field != "" || !request.Policy.IsZero() || len(sealPlacementsOf(request)) > 0 {
		signed, err := s.signOwn(ctx, request, keyPair)
		if err != nil {
			return nil, err
		}
		return s.complete(ctx, signed, request, keyPair)
	}

	document, err := pdfsign.OpenWithPassword(bytes.NewReader(request.Content), int64(len(request.Content)), request.Password)
	if err != nil {
		return nil, fmt.Errorf("open PDF: %w", err)
	}

	// The PDF library writes only invisible signatures without a policy.
	builder := document.Sign(keyPair.Signer, keyPair.Certificate).
		Format(pdfFormatFor(request.Level)).
		Digest(crypto.SHA256).
		SignerName(keyPair.Name).
		Context(ctx)

	if request.Reason != "" {
		builder = builder.Reason(request.Reason)
	}
	if request.Location != "" {
		builder = builder.Location(request.Location)
	}
	if len(keyPair.Chain) > 0 {
		builder = builder.CertificateChains([][]*x509.Certificate{keyPair.Certificates()})
	}
	if request.Level.NeedsTimestamp() && request.TimestampURL != "" {
		builder = builder.Timestamp(request.TimestampURL)
		if request.TimestampUser != "" {
			builder = builder.TimestampAuth(request.TimestampUser, request.TimestampSecret)
		}
	}

	var output bytes.Buffer
	if _, err := document.Write(&output); err != nil {
		return nil, fmt.Errorf("write signed PDF: %w", err)
	}

	return s.complete(ctx, output.Bytes(), request, keyPair)
}

// ErrEncryptedPDF marks what an encrypted PDF does not allow.
var ErrEncryptedPDF = errors.New("encrypted PDF")

// signable opens the document as both writers will, an encrypted one with
// its password, and reports it encrypted; it refuses one whose author
// allows no signature: its permissions, or a certification against any
// change, which a signature would break.
func signable(request application.PadesRequest) (bool, error) {
	given := false
	reader, err := pdf.NewReaderEncrypted(bytes.NewReader(request.Content), int64(len(request.Content)), func() string {
		if given {
			return ""
		}
		given = true
		return request.Password
	})
	switch {
	case errors.Is(err, pdf.ErrInvalidPassword) && request.Password == "":
		return true, fmt.Errorf("%w: it opens only with its password; give it in TREBARUNA_PDF_PASSWORD", ErrEncryptedPDF)
	case errors.Is(err, pdf.ErrInvalidPassword):
		return true, fmt.Errorf("%w: the password given does not open it", ErrEncryptedPDF)
	case err != nil:
		return false, fmt.Errorf("open PDF: %w", err)
	case reader.IsEncrypted() && !pdffield.SigningPermitted(reader):
		return true, fmt.Errorf("%w: its author's permissions allow neither filling in forms nor signing", ErrEncryptedPDF)
	case pdffield.CertifiedAgainstChanges(reader):
		return reader.IsEncrypted(), fmt.Errorf("%w: its author certified it against any change", pdffield.ErrUnsupported)
	case pdffield.LockedAgainstChanges(reader):
		return reader.IsEncrypted(), fmt.Errorf("%w: an earlier signer locked it against any change", pdffield.ErrUnsupported)
	}
	return reader.IsEncrypted(), nil
}

// complete adds what levels LT and LTA ask for to a signed PDF.
func (s *PadesSigner) complete(ctx context.Context, signed []byte, request application.PadesRequest, keyPair KeyPair) ([]byte, error) {
	if !request.Level.EmbedsRevocation() || !request.EmbedRevocation {
		return signed, nil
	}

	// PAdES B-LT: the signature is complete at this point, so the validation
	// material goes in a second, appended update that leaves its bytes intact.
	withStore, err := s.embedRevocation(ctx, signed, keyPair)
	if err != nil {
		return nil, err
	}

	if !request.Level.Archival() {
		return withStore, nil
	}

	// PAdES B-LTA adds a document timestamp over everything written so far,
	// including the /DSS: that is what protects the validation material itself
	// from becoming worthless as its own certificates expire.
	return s.addArchiveTimestamp(ctx, withStore, request)
}

// addArchiveTimestamp appends a DocTimeStamp over the whole document.
//
// ETSI EN 319 142-1 §6.4: the archive timestamp covers the entire file as it
// stands, so anything appended afterwards breaks it. It is a signature in its own
// right, with /Type /DocTimeStamp and /SubFilter /ETSI.RFC3161, and carries no
// signing certificate — only the token.
func (s *PadesSigner) addArchiveTimestamp(
	ctx context.Context,
	document []byte,
	request application.PadesRequest,
) ([]byte, error) {
	if request.TimestampURL == "" {
		return nil, fmt.Errorf("PAdES B-LTA needs a timestamp authority: pass --tsa <url>")
	}

	handler, err := pdfsign.Open(bytes.NewReader(document), int64(len(document)))
	if err != nil {
		return nil, fmt.Errorf("reopen the signed PDF for archival: %w", err)
	}

	builder := handler.Sign(nil, nil).
		Type(pdfsign.DocumentTimestamp).
		Format(pdfsign.DefaultFormat).
		Digest(crypto.SHA256).
		Timestamp(request.TimestampURL).
		Context(ctx)

	if request.TimestampUser != "" {
		builder = builder.TimestampAuth(request.TimestampUser, request.TimestampSecret)
	}

	var output bytes.Buffer
	if _, err := handler.Write(&output); err != nil {
		return nil, fmt.Errorf("write the archive timestamp: %w", err)
	}
	return output.Bytes(), nil
}

// embedRevocation collects status data and appends it as a /DSS dictionary.
//
// Every answer is obtained over the network, so this runs only when the caller
// asked for it. A certificate without a responder contributes nothing and is
// skipped: a /DSS with a hole in it is worse than no /DSS, because a validator
// reads it as complete.
func (s *PadesSigner) embedRevocation(
	ctx context.Context,
	signed []byte,
	keyPair KeyPair,
) ([]byte, error) {
	checker := verificationinfra.NewOCSPChecker()

	var (
		certificates []*x509.Certificate
		responses    [][]byte
		warnings     []string
	)

	chain := keyPair.Certificates()
	if len(chain) == 0 {
		return nil, fmt.Errorf("the signer carries no certificate chain to embed")
	}
	certificates = append(certificates, chain...)

	for index, certificate := range chain {
		issuer := chain[0]
		if index+1 < len(chain) {
			issuer = chain[index+1]
		}
		if index == len(chain)-1 {
			// The root revokes itself by definition; nothing to ask.
			break
		}

		status := checker.Check(ctx, certificate, issuer)
		switch {
		case status.IsRevoked():
			return nil, fmt.Errorf(
				"refusing to sign: the certificate for %q is revoked since %s",
				certificate.Subject.CommonName, status.RevokedAt.Format(time.RFC3339))
		case status.Status == verificationdomain.RevocationGood && len(status.RawResponse) > 0:
			responses = append(responses, status.RawResponse)
		default:
			warnings = append(warnings, fmt.Sprintf("%s: %s",
				certificate.Subject.CommonName, status.Reason))
		}
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf(
			"no revocation answer could be obtained, so %s cannot embed a complete /DSS:\n  %s",
			"PAdES B-LT", strings.Join(warnings, "\n  "))
	}

	// The VRI key is the uppercase hex SHA-1 of the signature value, which is how
	// a validator matches this material to this signature.
	key, err := signatureValueDigest(signed)
	if err != nil {
		return nil, err
	}

	updated, err := dss.Append(signed, dss.Validation{
		Certificates:  certificates,
		OCSPResponses: responses,
		VRI: []dss.VRIEntry{{
			Key:           key,
			Certificates:  certificates,
			OCSPResponses: responses,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("append the /DSS dictionary: %w", err)
	}
	return updated, nil
}

// signatureValueDigest returns the SHA-1 of the latest signature's
// /Contents, in the uppercase hex form the VRI dictionary requires.
//
// EN 319 142-1 keys the VRI entry by the digest of the signature value, not of
// the whole CMS container, so the /Contents string is read from the document and
// hashed as it stands.
func signatureValueDigest(signed []byte) (string, error) {
	reader, err := pdf.NewReader(bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		return "", fmt.Errorf("reopen the signed PDF: %w", err)
	}

	contents, err := latestSignatureContents(reader)
	if err != nil {
		return "", err
	}

	digest := sha1.Sum(contents)
	return strings.ToUpper(hex.EncodeToString(digest[:])), nil
}

// latestSignatureContents is the /Contents of the signature just made:
// among every signature field, nested ones too, the one whose /ByteRange
// reaches furthest into the file. The first field was taken before, which
// in a form signed earlier is someone else's signature.
func latestSignatureContents(reader *pdf.Reader) ([]byte, error) {
	var latest []byte
	reach := int64(-1)
	var visit func(fields pdf.Value, depth int)
	visit = func(fields pdf.Value, depth int) {
		if depth > 16 {
			return
		}
		for index := 0; index < fields.Len(); index++ {
			field := fields.Index(index)
			value := field.Key("V")
			raw := value.Key("Contents").RawString()
			byteRange := value.Key("ByteRange")
			if value.Kind() == pdf.Dict && raw != "" && byteRange.Len() == 4 {
				if end := byteRange.Index(2).Int64() + byteRange.Index(3).Int64(); end > reach {
					latest, reach = []byte(raw), end
				}
			}
			visit(field.Key("Kids"), depth+1)
		}
	}
	visit(reader.Trailer().Key("Root").Key("AcroForm").Key("Fields"), 0)
	if latest == nil {
		return nil, fmt.Errorf("the signed PDF carries no signature value")
	}
	return latest, nil
}

// pdfFormatFor maps the domain level onto the library format.
func pdfFormatFor(level domain.Level) pdfsign.Format {
	if level.NeedsTimestamp() {
		return pdfsign.PAdES_B_T
	}
	return pdfsign.PAdES_B
}

// sealPlacementsOf is every seal the request asks for, the single
// placement field folded in.
func sealPlacementsOf(request application.PadesRequest) []domain.SealPlacement {
	if len(request.Placements) == 0 && !request.Placement.IsZero() {
		return []domain.SealPlacement{request.Placement}
	}
	return request.Placements
}

// placeOnPages resolves the default corner seal against the real size of its
// page: an A4 assumption put the seal in the middle of a Letter page's margin
// and off the visible area of a landscape one.
func placeOnPages(content []byte, placements []domain.SealPlacement) ([]domain.SealPlacement, error) {
	needed := false
	for _, placement := range placements {
		needed = needed || placement.IsCorner()
	}
	if !needed {
		return placements, nil
	}

	reader, err := pdf.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("read the PDF to place the seal: %w", err)
	}
	resolved := make([]domain.SealPlacement, 0, len(placements))
	for _, placement := range placements {
		if !placement.IsCorner() {
			resolved = append(resolved, placement)
			continue
		}
		if placement.Page() > reader.NumPage() {
			return nil, fmt.Errorf("the document has %d pages, the seal asks for page %d", reader.NumPage(), placement.Page())
		}
		left, bottom, right, top, ok := visibleBox(reader.Page(placement.Page()))
		if !ok {
			// No usable box: keep the A4 coordinates rather than refuse.
			resolved = append(resolved, placement)
			continue
		}
		resolved = append(resolved, placement.OnPage(left, bottom, right, top))
	}
	return resolved, nil
}

// visibleBox returns the page's CropBox, or its MediaBox, following the page
// tree upwards as the PDF specification allows both to be inherited.
func visibleBox(page pdf.Page) (left, bottom, right, top float64, ok bool) {
	for _, name := range []string{"CropBox", "MediaBox"} {
		for node := page.V; node.Kind() == pdf.Dict; node = node.Key("Parent") {
			box := node.Key(name)
			if box.Kind() != pdf.Array || box.Len() != 4 {
				continue
			}
			x0, y0 := box.Index(0).Float64(), box.Index(1).Float64()
			x1, y1 := box.Index(2).Float64(), box.Index(3).Float64()
			return math.Min(x0, x1), math.Min(y0, y1), math.Max(x0, x1), math.Max(y0, y1), true
		}
	}
	return 0, 0, 0, 0, false
}

// compile-time check.
var _ application.PadesSigner = (*PadesSigner)(nil)
