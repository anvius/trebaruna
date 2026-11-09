package domain

import (
	"net/url"
	"strconv"
	"strings"
)

// MaximumVersion is the highest operation protocol version answered, as
// AutoFirma 1.9 (A.10).
const MaximumVersion = 4

// ClaimedVersion is the AutoFirma version trebaruna answers mcv checks with:
// the protocol of AutoFirma 1.9 is what it implements.
const ClaimedVersion = "1.9"

// Channel is where the answer goes back: the site's storage servlet, with
// the session id it is stored under, the key that ciphers it, and whether
// the page asked to hear "#WAIT" while the person decides.
type Channel struct {
	SessionID     string
	StorageURL    string
	Key           string
	Cipher        string
	ActiveWaiting bool
}

// Ciphered reports whether the answer is encrypted.
func (c Channel) Ciphered() bool { return c.Key != "" }

// Common holds what every operation carries (A.5).
type Common struct {
	Channel  Channel
	Version  int
	AppName  string
	Keystore string
	// Properties are the decoded extraParams (A.7).
	Properties map[string]string
	// Sticky asks to keep the key chosen now for the page's next request
	// in this process; ResetSticky forgets a key kept earlier.
	Sticky      bool
	ResetSticky bool
}

// Site names the page for the person approving: the host of its storage
// servlet, which is where the answer goes, and the name it gives itself.
func (c Common) Site() string {
	if parsed, err := url.Parse(c.Channel.StorageURL); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return c.AppName
}

// SignRequest is sign, cosign, countersign or signandsave (A.6).
type SignRequest struct {
	Common
	Operation Operation
	// Crypto is the operation actually performed: for signandsave, cop.
	Crypto    Operation
	Format    Format
	Algorithm string
	Data      Payload
	// FileName is signandsave's suggested name.
	FileName string
}

// CounterTarget is what a counter-signature signs (properties target): the
// whole tree ("all") for target=tree, the leaves otherwise.
func CounterTarget(properties map[string]string) string {
	if strings.EqualFold(properties["target"], "tree") {
		return "all"
	}
	return "leaves"
}

// ReadCommon validates what every operation carries.
func ReadCommon(invocation Invocation, servicesRequired bool) (Common, error) {
	common := Common{
		AppName:     invocation.Param("appname"),
		Properties:  DecodeProperties(invocation.Param("properties")),
		Sticky:      strings.EqualFold(invocation.Param("sticky"), "true"),
		ResetSticky: strings.EqualFold(invocation.Param("resetsticky"), "true"),
	}

	version, err := readVersion(invocation.Param("ver"))
	if err != nil {
		return Common{}, err
	}
	common.Version = version
	if minimum := invocation.Param("mcv"); minimum != "" && newerThan(minimum, ClaimedVersion) {
		return Common{}, Failure{Code: MinimumVersion}
	}

	key := invocation.Param("key")
	if key != "" && len(key) != 8 {
		return Common{}, Failure{Code: Params, Cause: "the key must have 8 characters"}
	}
	common.Channel.Key = key
	common.Channel.Cipher = invocation.Param("cipher")
	common.Channel.ActiveWaiting = invocation.Param("aw") == "true"

	id := invocation.Param("id")
	if id != "" {
		if err := validSessionID(id); err != nil {
			return Common{}, err
		}
		common.Channel.SessionID = id
	}
	if storage := invocation.Param("stservlet"); storage != "" {
		if err := ValidServletURL(storage); err != nil {
			return Common{}, err
		}
		common.Channel.StorageURL = storage
	}
	if servicesRequired && id != "" && common.Channel.StorageURL == "" {
		return Common{}, Failure{Code: Params, Cause: "an id needs stservlet"}
	}

	common.Keystore = invocation.Param("keystore")
	if common.Keystore == "" && invocation.Param("ksb64") != "" {
		if decoded, err := DecodeBase64(invocation.Param("ksb64")); err == nil {
			common.Keystore = string(decoded)
		}
	}
	return common, nil
}

// ReadSignRequest validates sign, cosign, countersign and signandsave.
func ReadSignRequest(invocation Invocation, servicesRequired bool) (SignRequest, error) {
	common, err := ReadCommon(invocation, servicesRequired)
	if err != nil {
		return SignRequest{}, err
	}
	request := SignRequest{Common: common, Operation: invocation.Operation, Crypto: invocation.Operation}
	if invocation.Operation == SignAndSave {
		switch Operation(strings.ToLower(invocation.Param("cop"))) {
		case Sign:
			request.Crypto = Sign
		case Cosign:
			request.Crypto = Cosign
		case Countersign:
			request.Crypto = Countersign
		default:
			return SignRequest{}, Failure{Code: SignatureFailed, Cause: "signandsave without a known cop"}
		}
		name := invocation.Param("filename")
		if strings.ContainsAny(name, `\/:*?"<>|`) {
			return SignRequest{}, Failure{Code: Params, Cause: "invalid filename"}
		}
		request.FileName = name
	}

	if invocation.Param("format") == "" {
		return SignRequest{}, Failure{Code: Params, Cause: "format is required"}
	}
	format, err := ParseFormat(invocation.Param("format"))
	if err != nil {
		return SignRequest{}, err
	}
	request.Format = format

	algorithm := invocation.Param("algorithm")
	if !signatureAlgorithms[algorithm] {
		return SignRequest{}, Failure{Code: Params, Cause: "unknown algorithm " + algorithm}
	}
	request.Algorithm = algorithm

	payload, err := ResolvePayload(invocation.Param("dat"), invocation.Param("gzip") == "true")
	if err != nil {
		return SignRequest{}, err
	}
	request.Data = payload
	return request, nil
}

// readVersion parses ver: absent 0, unparsable 1, above the maximum SAF_21.
func readVersion(text string) (int, error) {
	if text == "" {
		return 0, nil
	}
	version, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		version = 1
	}
	if version > MaximumVersion {
		return 0, Failure{Code: UnsupportedProcedure}
	}
	return version, nil
}

// validSessionID allows at most 20 ASCII letters and digits (A.5).
func validSessionID(id string) error {
	if len(id) > 20 {
		return Failure{Code: Params, Cause: "session id longer than 20 characters"}
	}
	for _, r := range strings.ToLower(id) {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return Failure{Code: Params, Cause: "session id with characters other than letters and digits"}
		}
	}
	return nil
}

// ValidServletURL applies A.5's servlet checks: http or https, not this
// machine (SAF_13), and neither "?" nor "=" anywhere.
func ValidServletURL(raw string) error {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	parsed, err := url.Parse(decoded)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return Failure{Code: Params, Cause: "invalid servlet URL"}
	}
	if host := parsed.Hostname(); host == "localhost" || host == "127.0.0.1" {
		return Failure{Code: LocalAccessBlocked}
	}
	if strings.ContainsAny(decoded, "?=") {
		return Failure{Code: Params, Cause: "servlet URL with a query"}
	}
	return nil
}

// newerThan compares dotted versions part by part, ignoring text suffixes.
func newerThan(candidate, reference string) bool {
	left, right := strings.Split(candidate, "."), strings.Split(reference, ".")
	for index := 0; index < len(left) || index < len(right); index++ {
		a, b := versionPart(left, index), versionPart(right, index)
		if a != b {
			return a > b
		}
	}
	return false
}

func versionPart(parts []string, index int) int {
	if index >= len(parts) {
		return 0
	}
	digits := strings.TrimRightFunc(parts[index], func(r rune) bool { return r < '0' || r > '9' })
	value, _ := strconv.Atoi(digits)
	return value
}
