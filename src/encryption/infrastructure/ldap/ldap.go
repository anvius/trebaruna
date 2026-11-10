// Package ldap is the part of LDAPv3 (RFC 4511) trebaruna needs to find a
// recipient's certificate in a directory: an anonymous bind, one search by
// e-mail address or common name, the certificate attributes of the entries
// found, and an unbind. Messages are BER with definite lengths, as RFC 4511
// requires.
package ldap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Limits on what a directory may send back.
const (
	sizeLimit  = 20
	timeLimit  = 15
	maxMessage = 4 << 20
)

// CertificateAttributes are the attributes a directory keeps certificates
// in (RFC 4523): ;binary is how most directories hand them out.
var CertificateAttributes = []string{"userCertificate;binary", "userCertificate"}

// ErrDirectory is a directory that answered with an error.
var ErrDirectory = errors.New("the directory refused")

// Search binds anonymously on connection, searches the subtree under base
// for entries whose mail or cn is who, and returns the values of their
// certificate attributes, each a DER certificate as the directory keeps it.
// The connection is the caller's to close.
func Search(ctx context.Context, connection net.Conn, base, who string) ([][]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	} else {
		_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	}
	reader := bufio.NewReader(connection)

	bind := sequence(integer(1), tagged(0x60, integer(3), octets(nil), tagged(0x80, nil)))
	if _, err := connection.Write(bind); err != nil {
		return nil, err
	}
	operation, body, err := readMessage(reader, 1)
	if err != nil {
		return nil, err
	}
	if operation != 0x61 {
		return nil, fmt.Errorf("ldap: the directory answered the bind with operation %#x", operation)
	}
	if err := result(body); err != nil {
		return nil, fmt.Errorf("%w the anonymous bind: %v", ErrDirectory, err)
	}

	var attributes [][]byte
	for _, name := range CertificateAttributes {
		attributes = append(attributes, octets([]byte(name)))
	}
	filter := tagged(0xa1,
		tagged(0xa3, octets([]byte("mail")), octets([]byte(who))),
		tagged(0xa3, octets([]byte("cn")), octets([]byte(who))))
	search := sequence(integer(2), tagged(0x63,
		octets([]byte(base)), enumerated(2), enumerated(0), integer(sizeLimit), integer(timeLimit), boolean(false),
		filter, sequence(attributes...)))
	if _, err := connection.Write(search); err != nil {
		return nil, err
	}

	var certificates [][]byte
	for {
		operation, body, err := readMessage(reader, 2)
		if err != nil {
			return nil, err
		}
		switch operation {
		case 0x64: // SearchResultEntry
			found, err := entryCertificates(body)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, found...)
		case 0x73: // SearchResultReference: another server, not followed
		case 0x65: // SearchResultDone
			_, _ = connection.Write(sequence(integer(3), []byte{0x42, 0x00}))
			if err := result(body); err != nil && !(errors.Is(err, errSizeLimit) && len(certificates) > 0) {
				return nil, fmt.Errorf("%w the search: %v", ErrDirectory, err)
			}
			return certificates, nil
		default:
			return nil, fmt.Errorf("ldap: unexpected operation %#x in a search", operation)
		}
	}
}

// errSizeLimit is resultCode 4: more entries matched than were sent.
var errSizeLimit = errors.New("more entries matched than the directory sent (sizeLimitExceeded)")

// result reads an LDAPResult: nil for success, the code and message
// otherwise.
func result(body []byte) error {
	tag, value, _, err := readTLV(body)
	if err != nil || tag != 0x0a || len(value) == 0 {
		return fmt.Errorf("ldap: an unreadable result")
	}
	code := 0
	for _, octet := range value {
		code = code<<8 | int(octet)
	}
	if code == 0 {
		return nil
	}
	if code == 4 {
		return errSizeLimit
	}
	return fmt.Errorf("result code %d", code)
}

// entryCertificates are the certificate attribute values of a
// SearchResultEntry's body.
func entryCertificates(body []byte) ([][]byte, error) {
	_, _, rest, err := readTLV(body) // objectName
	if err != nil {
		return nil, err
	}
	_, list, _, err := readTLV(rest) // attributes
	if err != nil {
		return nil, err
	}
	var certificates [][]byte
	for len(list) > 0 {
		var attribute []byte
		if _, attribute, list, err = readTLV(list); err != nil {
			return nil, err
		}
		_, name, values, err := readTLV(attribute)
		if err != nil {
			return nil, err
		}
		wanted := false
		for _, certificateAttribute := range CertificateAttributes {
			wanted = wanted || strings.EqualFold(string(name), certificateAttribute)
		}
		_, set, _, err := readTLV(values)
		if err != nil {
			return nil, err
		}
		for wanted && len(set) > 0 {
			var value []byte
			if _, value, set, err = readTLV(set); err != nil {
				return nil, err
			}
			certificates = append(certificates, value)
		}
	}
	return certificates, nil
}

// readMessage reads one LDAPMessage and returns its operation's tag and
// body, refusing another message id.
func readMessage(reader *bufio.Reader, id int) (byte, []byte, error) {
	message, err := readElement(reader)
	if err != nil {
		return 0, nil, err
	}
	_, content, _, err := readTLV(message)
	if err != nil {
		return 0, nil, err
	}
	tag, idBytes, rest, err := readTLV(content)
	if err != nil || tag != 0x02 {
		return 0, nil, fmt.Errorf("ldap: a message without its id")
	}
	got := 0
	for _, octet := range idBytes {
		got = got<<8 | int(octet)
	}
	if got != id {
		return 0, nil, fmt.Errorf("ldap: an answer to message %d while waiting for %d", got, id)
	}
	operation, body, _, err := readTLV(rest)
	return operation, body, err
}

// readElement reads one whole BER element from the stream.
func readElement(reader *bufio.Reader) ([]byte, error) {
	tag, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	first, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	header := []byte{tag, first}
	length := int(first)
	if first&0x80 != 0 {
		count := int(first & 0x7f)
		if count == 0 || count > 4 {
			return nil, fmt.Errorf("ldap: an indefinite or oversized length")
		}
		length = 0
		for index := 0; index < count; index++ {
			octet, err := reader.ReadByte()
			if err != nil {
				return nil, err
			}
			header = append(header, octet)
			length = length<<8 | int(octet)
		}
	}
	if length > maxMessage {
		return nil, fmt.Errorf("ldap: a message of %d bytes", length)
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(reader, content); err != nil {
		return nil, err
	}
	return append(header, content...), nil
}

// readTLV splits the first element of data: its tag, its content and what
// follows it.
func readTLV(data []byte) (byte, []byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("ldap: a truncated element")
	}
	tag, length, offset := data[0], int(data[1]), 2
	if data[1]&0x80 != 0 {
		count := int(data[1] & 0x7f)
		if count == 0 || count > 4 || len(data) < 2+count {
			return 0, nil, nil, fmt.Errorf("ldap: an unreadable length")
		}
		length = 0
		for _, octet := range data[2 : 2+count] {
			length = length<<8 | int(octet)
		}
		offset += count
	}
	if length < 0 || offset+length > len(data) {
		return 0, nil, nil, fmt.Errorf("ldap: a truncated element")
	}
	return tag, data[offset : offset+length], data[offset+length:], nil
}

func tagged(tag byte, parts ...[]byte) []byte {
	var content []byte
	for _, part := range parts {
		content = append(content, part...)
	}
	return append(append([]byte{tag}, length(len(content))...), content...)
}

func length(size int) []byte {
	if size < 0x80 {
		return []byte{byte(size)}
	}
	var octets []byte
	for ; size > 0; size >>= 8 {
		octets = append([]byte{byte(size)}, octets...)
	}
	return append([]byte{0x80 | byte(len(octets))}, octets...)
}

func sequence(parts ...[]byte) []byte { return tagged(0x30, parts...) }
func octets(value []byte) []byte      { return tagged(0x04, value) }
func boolean(value bool) []byte {
	if value {
		return []byte{0x01, 0x01, 0xff}
	}
	return []byte{0x01, 0x01, 0x00}
}
func enumerated(value int) []byte { return tagged(0x0a, []byte{byte(value)}) }

// integer encodes the small non-negative integers this client sends (ids,
// version, limits), all below 128.
func integer(value int) []byte { return tagged(0x02, []byte{byte(value)}) }
