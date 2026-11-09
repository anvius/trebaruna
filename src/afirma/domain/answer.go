package domain

import "strings"

// Answer is the text a page receives for a successful operation (B.1), before
// any cipher: the cipher, when a key was given, applies to each "|" element.
type Answer struct {
	// Elements are the parts joined by "|", already encoded.
	Elements []string
	// Plain marks answers that are never ciphered (save's OK, CANCEL,
	// failures).
	Plain bool
	// Failure marks a "SAF_NN" answer, which the storage servlet must receive
	// URL-encoded (B.3).
	Failure bool
}

// Text joins the elements.
func (a Answer) Text() string { return strings.Join(a.Elements, "|") }

// SignAnswer is "cert|signature[|{"filename": "name"}]" in URL-safe Base64;
// the file name appears only when the person chose the file and the protocol
// is 3 or later.
func SignAnswer(certificate, signature []byte, chosenFile string, version int) Answer {
	elements := []string{EncodeBase64URL(certificate), EncodeBase64URL(signature)}
	if chosenFile != "" && version >= 3 {
		elements = append(elements, EncodeBase64URL([]byte(`{"filename": "`+chosenFile+`"}`)))
	}
	return Answer{Elements: elements}
}

// CertificateAnswer is selectcert's answer.
func CertificateAnswer(certificate []byte) Answer {
	return Answer{Elements: []string{EncodeBase64URL(certificate)}}
}

// BatchAnswer is "result[|cert]": the post-signer's result first and the
// certificate only when the page asked for it (needcert).
func BatchAnswer(result, certificate []byte, needCertificate bool) Answer {
	elements := []string{EncodeBase64URL(result)}
	if needCertificate {
		elements = append(elements, EncodeBase64URL(certificate))
	}
	return Answer{Elements: elements}
}

// SavedAnswer is save's answer, never ciphered.
func SavedAnswer() Answer { return Answer{Elements: []string{"OK"}, Plain: true} }
