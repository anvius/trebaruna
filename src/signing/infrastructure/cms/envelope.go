package cms

// Encrypted envelopes: CMS EnvelopedData (RFC 5652, section 6) with key
// transport to each recipient's RSA certificate and AES-256-CBC content
// encryption: the .p7e of Italian practice and AutoFirma's digital envelope
// (ADR-0011).
//
// Written here rather than taken from a library: the one at hand decrypts
// only with an in-memory RSA key, so a card could never open an envelope,
// knows no OAEP, and defaults to DES through a global variable.

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Envelope object identifiers.
var (
	OIDEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	OIDMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	OIDAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	OIDAES128CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDAES192CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OIDSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

var (
	// ErrNotAnEnvelope means the bytes are not CMS EnvelopedData.
	ErrNotAnEnvelope = errors.New("not an encrypted envelope (CMS EnvelopedData)")
	// ErrNotARecipient means the envelope was not made for this certificate.
	ErrNotARecipient = errors.New("the envelope was not encrypted for this certificate")
	// ErrRecipientKey means a recipient certificate cannot receive a key.
	ErrRecipientKey = errors.New("this certificate cannot receive an encrypted envelope")

	errBadPadding = errors.New("the decrypted content has bad padding: wrong key or damaged envelope")
)

// KeyTransport is how the content key travels to a recipient.
type KeyTransport string

const (
	// PKCS1v15 is RSA PKCS#1 v1.5, which every tool reads.
	PKCS1v15 KeyTransport = "pkcs1"
	// OAEP is RSA-OAEP with SHA-256 and MGF1-SHA-256.
	OAEP KeyTransport = "oaep"
)

// RecipientID names a recipient by its certificate's issuer and serial.
type RecipientID struct {
	Issuer []byte
	Serial *big.Int
}

// Matches reports whether the certificate is this recipient's.
func (r RecipientID) Matches(certificate *x509.Certificate) bool {
	return bytes.Equal(r.Issuer, certificate.RawIssuer) && r.Serial.Cmp(certificate.SerialNumber) == 0
}

// Seal encrypts content for each recipient certificate.
func Seal(content []byte, recipients []*x509.Certificate, transport KeyTransport) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("an envelope needs at least one recipient")
	}
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pad(content, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)

	d := &der{}
	infos := make([][]byte, 0, len(recipients))
	for _, recipient := range recipients {
		info, err := keyTransportRecipient(d, recipient, key, transport)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}

	// Version 0: no originator information, issuer-and-serial recipients only.
	envelope := d.seq(
		d.integer(0),
		d.set(sortSet(infos)...),
		d.seq(
			d.oid(OIDData),
			d.seq(d.oid(OIDAES256CBC), d.octetString(iv)),
			d.tagged(0x80, encrypted), // encryptedContent [0] IMPLICIT
		),
	)
	return d.seq(d.oid(OIDEnvelopedData), d.tagged(0xa0, envelope)), nil
}

// keyTransportRecipient encrypts the content key to one certificate.
func keyTransportRecipient(d *der, recipient *x509.Certificate, key []byte, transport KeyTransport) ([]byte, error) {
	public, ok := recipient.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s has a %T key; only RSA keys receive envelopes",
			ErrRecipientKey, recipient.Subject.CommonName, recipient.PublicKey)
	}
	var encryptedKey, algorithm []byte
	switch transport {
	case OAEP:
		value, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, key, nil)
		if err != nil {
			return nil, err
		}
		encryptedKey = value
		sha := d.seq(d.oid(OIDSHA256))
		algorithm = d.seq(d.oid(OIDRSAESOAEP), d.seq(
			d.tagged(0xa0, sha),                        // hashAlgorithm [0]
			d.tagged(0xa1, d.seq(d.oid(OIDMGF1), sha)), // maskGenAlgorithm [1]
		))
	default:
		//nolint:staticcheck // PKCS#1 v1.5 key transport is what the recipients' tools read.
		value, err := rsa.EncryptPKCS1v15(rand.Reader, public, key)
		if err != nil {
			return nil, err
		}
		encryptedKey = value
		algorithm = d.seq(d.oid(OIDRSAEncryption), d.null())
	}

	serial, err := asn1.Marshal(recipient.SerialNumber)
	if err != nil {
		return nil, err
	}
	return d.seq(
		d.integer(0),
		d.seq(recipient.RawIssuer, serial), // IssuerAndSerialNumber
		algorithm,
		d.octetString(encryptedKey),
	), nil
}

// envelopedData is the parsed structure Open needs.
type envelopedData struct {
	recipients []keyTransport
	algorithm  asn1.ObjectIdentifier
	parameters []byte
	encrypted  []byte
}

type keyTransport struct {
	id         RecipientID
	algorithm  pkix.AlgorithmIdentifier
	encrypted  []byte
	identified bool
}

// IsEnvelope reports whether the bytes are EnvelopedData.
func IsEnvelope(data []byte) bool {
	_, err := parseEnvelope(data)
	return err == nil
}

// Recipients lists who the envelope was encrypted for.
func Recipients(data []byte) ([]RecipientID, error) {
	parsed, err := parseEnvelope(data)
	if err != nil {
		return nil, err
	}
	var ids []RecipientID
	for _, recipient := range parsed.recipients {
		if recipient.identified {
			ids = append(ids, recipient.id)
		}
	}
	return ids, nil
}

// Open decrypts the envelope with the key of a recipient certificate. The key
// only decrypts the content key, so a card's key never leaves the card.
func Open(data []byte, certificate *x509.Certificate, key crypto.Decrypter) ([]byte, error) {
	parsed, err := parseEnvelope(data)
	if err != nil {
		return nil, err
	}
	for _, recipient := range parsed.recipients {
		if !recipient.identified || !recipient.id.Matches(certificate) {
			continue
		}
		var options crypto.DecrypterOpts
		switch {
		case recipient.algorithm.Algorithm.Equal(OIDRSAEncryption):
			options = &rsa.PKCS1v15DecryptOptions{}
		case recipient.algorithm.Algorithm.Equal(OIDRSAESOAEP):
			hash, err := oaepHash(recipient.algorithm.Parameters.FullBytes)
			if err != nil {
				return nil, err
			}
			options = &rsa.OAEPOptions{Hash: hash, MGFHash: hash}
		default:
			return nil, fmt.Errorf("unsupported key transport %v", recipient.algorithm.Algorithm)
		}
		contentKey, err := key.Decrypt(rand.Reader, recipient.encrypted, options)
		if err != nil {
			return nil, fmt.Errorf("decrypt the content key: %w", err)
		}
		defer clear(contentKey)
		return decryptContent(parsed, contentKey)
	}
	return nil, ErrNotARecipient
}

// decryptContent decrypts AES-CBC content and removes its padding.
func decryptContent(parsed envelopedData, key []byte) ([]byte, error) {
	sizes := map[string]int{OIDAES128CBC.String(): 16, OIDAES192CBC.String(): 24, OIDAES256CBC.String(): 32}
	size, known := sizes[parsed.algorithm.String()]
	if !known {
		return nil, fmt.Errorf("unsupported content encryption %v", parsed.algorithm)
	}
	if len(key) != size {
		return nil, errors.New("the content key has the wrong length")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(parsed.parameters, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("the envelope's IV is unreadable")
	}
	if len(parsed.encrypted) == 0 || len(parsed.encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("the encrypted content has the wrong length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(parsed.encrypted))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, parsed.encrypted)
	return unpad(plain, aes.BlockSize)
}

// parseEnvelope reads ContentInfo { envelopedData, [0] EnvelopedData }.
func parseEnvelope(data []byte) (envelopedData, error) {
	var outer struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}
	if _, err := asn1.Unmarshal(data, &outer); err != nil || !outer.Type.Equal(OIDEnvelopedData) ||
		outer.Content.Class != asn1.ClassContextSpecific || outer.Content.Tag != 0 {
		return envelopedData{}, ErrNotAnEnvelope
	}
	var sequence asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &sequence); err != nil {
		return envelopedData{}, ErrNotAnEnvelope
	}

	var version int
	rest, err := asn1.Unmarshal(sequence.Bytes, &version)
	if err != nil {
		return envelopedData{}, ErrNotAnEnvelope
	}
	var parsed envelopedData
	for len(rest) > 0 {
		var field asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return envelopedData{}, fmt.Errorf("%w: %v", ErrNotAnEnvelope, err)
		}
		switch {
		case field.Class == asn1.ClassContextSpecific:
			// originatorInfo [0] and unprotectedAttrs [1] carry nothing Open needs.
		case field.Tag == asn1.TagSet:
			parsed.recipients = readRecipients(field.Bytes)
		case field.Tag == asn1.TagSequence:
			if err := readEncryptedContent(field.Bytes, &parsed); err != nil {
				return envelopedData{}, err
			}
		}
	}
	if parsed.algorithm == nil {
		return envelopedData{}, fmt.Errorf("%w: no encrypted content", ErrNotAnEnvelope)
	}
	return parsed, nil
}

// readRecipients reads the key-transport recipients; other kinds (key
// agreement, passwords) are skipped: Open cannot use them.
func readRecipients(set []byte) []keyTransport {
	var recipients []keyTransport
	for len(set) > 0 {
		var item asn1.RawValue
		var err error
		if set, err = asn1.Unmarshal(set, &item); err != nil {
			return recipients
		}
		if item.Class != asn1.ClassUniversal || item.Tag != asn1.TagSequence {
			continue
		}
		var info struct {
			Version   int
			ID        asn1.RawValue
			Algorithm pkix.AlgorithmIdentifier
			Encrypted []byte
		}
		if _, err := asn1.Unmarshal(item.FullBytes, &info); err != nil {
			continue
		}
		recipient := keyTransport{algorithm: info.Algorithm, encrypted: info.Encrypted}
		if info.ID.Tag == asn1.TagSequence && info.ID.Class == asn1.ClassUniversal {
			var issuerSerial struct {
				Issuer asn1.RawValue
				Serial *big.Int
			}
			if _, err := asn1.Unmarshal(info.ID.FullBytes, &issuerSerial); err == nil {
				recipient.id = RecipientID{Issuer: issuerSerial.Issuer.FullBytes, Serial: issuerSerial.Serial}
				recipient.identified = true
			}
		}
		recipients = append(recipients, recipient)
	}
	return recipients
}

// readEncryptedContent reads EncryptedContentInfo; content given in pieces
// (constructed OCTET STRING) is joined.
func readEncryptedContent(body []byte, parsed *envelopedData) error {
	var contentType asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(body, &contentType)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotAnEnvelope, err)
	}
	var algorithm pkix.AlgorithmIdentifier
	if rest, err = asn1.Unmarshal(rest, &algorithm); err != nil {
		return fmt.Errorf("%w: %v", ErrNotAnEnvelope, err)
	}
	parsed.algorithm = algorithm.Algorithm
	parsed.parameters = algorithm.Parameters.FullBytes
	if len(rest) == 0 {
		return nil
	}
	var content asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &content); err != nil {
		return fmt.Errorf("%w: %v", ErrNotAnEnvelope, err)
	}
	if !content.IsCompound {
		parsed.encrypted = content.Bytes
		return nil
	}
	for pieces := content.Bytes; len(pieces) > 0; {
		var piece []byte
		if pieces, err = asn1.Unmarshal(pieces, &piece); err != nil {
			return fmt.Errorf("%w: %v", ErrNotAnEnvelope, err)
		}
		parsed.encrypted = append(parsed.encrypted, piece...)
	}
	return nil
}

// oaepHash reads the hash of RSAES-OAEP-params; absent means SHA-1.
func oaepHash(parameters []byte) (crypto.Hash, error) {
	var params struct {
		Hash asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}
	if len(parameters) > 0 {
		if _, err := asn1.Unmarshal(parameters, &params); err != nil {
			return 0, fmt.Errorf("unreadable OAEP parameters: %w", err)
		}
	}
	if len(params.Hash.FullBytes) == 0 {
		return crypto.SHA1, nil
	}
	// Depending on how the explicit tag was read, the algorithm is the raw
	// value's content or the raw value itself; both are tried.
	var algorithm pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.Hash.Bytes, &algorithm); err != nil {
		if _, err := asn1.Unmarshal(params.Hash.FullBytes, &algorithm); err != nil {
			return 0, fmt.Errorf("unreadable OAEP hash: %w", err)
		}
	}
	switch {
	case algorithm.Algorithm.Equal(OIDSHA256):
		return crypto.SHA256, nil
	case algorithm.Algorithm.Equal(OIDSHA1):
		return crypto.SHA1, nil
	}
	return 0, fmt.Errorf("unsupported OAEP hash %v", algorithm.Algorithm)
}

// pad adds PKCS#7 padding.
func pad(data []byte, size int) []byte {
	count := size - len(data)%size
	return append(append([]byte{}, data...), bytes.Repeat([]byte{byte(count)}, count)...)
}

// unpad removes PKCS#7 padding after checking it.
func unpad(data []byte, size int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty content")
	}
	count := int(data[len(data)-1])
	if count == 0 || count > size || count > len(data) {
		return nil, errBadPadding
	}
	for _, value := range data[len(data)-count:] {
		if int(value) != count {
			return nil, errBadPadding
		}
	}
	return data[:len(data)-count], nil
}
