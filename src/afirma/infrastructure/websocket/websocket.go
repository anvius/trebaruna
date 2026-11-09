// Package websocket is the part of RFC 6455 the afirma:// local channel
// needs: the opening handshake, text messages (fragmented or not), ping,
// pong and close, server and client side. AutoFirma's page script sends one
// text message per request and reads one per answer.
package websocket

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// acceptGUID is the handshake's fixed suffix (RFC 6455, 1.3).
const acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// MaxMessage bounds one message: a document to sign travels inside one, in
// Base64.
const MaxMessage = 256 << 20

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// ErrProtocol is a frame RFC 6455 does not allow.
var ErrProtocol = errors.New("websocket protocol error")

// Conn is an open WebSocket connection.
type Conn struct {
	conn    net.Conn
	reader  *bufio.Reader
	client  bool
	writing sync.Mutex
}

// Accept completes the opening handshake of a request the server took.
func Accept(writer http.ResponseWriter, request *http.Request) (*Conn, error) {
	if request.Method != http.MethodGet || !headerHas(request.Header, "Upgrade", "websocket") ||
		!headerHas(request.Header, "Connection", "upgrade") || request.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(writer, "a WebSocket handshake is expected", http.StatusBadRequest)
		return nil, fmt.Errorf("%w: not a WebSocket handshake", ErrProtocol)
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	if decoded, err := base64.StdEncoding.DecodeString(key); err != nil || len(decoded) != 16 {
		http.Error(writer, "bad Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, fmt.Errorf("%w: bad Sec-WebSocket-Key", ErrProtocol)
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		return nil, errors.New("the connection cannot be taken over")
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
	response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptFor(key) + "\r\n\r\n"
	if _, err := connection.Write([]byte(response)); err != nil {
		connection.Close()
		return nil, err
	}
	return &Conn{conn: connection, reader: buffered.Reader}, nil
}

// Dial opens a client connection to wss://address/path (or ws:// without a
// TLS configuration).
func Dial(ctx context.Context, address, path string, config *tls.Config) (*Conn, error) {
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if config != nil {
		if config.ServerName == "" {
			host, _, _ := net.SplitHostPort(address)
			config = config.Clone()
			config.ServerName = host
		}
		secured := tls.Client(connection, config)
		if err := secured.HandshakeContext(ctx); err != nil {
			connection.Close()
			return nil, err
		}
		connection = secured
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	key := base64.StdEncoding.EncodeToString(nonce)
	request := "GET " + path + " HTTP/1.1\r\nHost: " + address + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := connection.Write([]byte(request)); err != nil {
		connection.Close()
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		connection.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Sec-WebSocket-Accept") != acceptFor(key) {
		connection.Close()
		return nil, fmt.Errorf("%w: the server answered %s", ErrProtocol, response.Status)
	}
	return &Conn{conn: connection, reader: reader, client: true}, nil
}

// RemoteAddr is the peer's address.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// ReadMessage returns the next text (or binary) message, answering pings
// on the way; io.EOF when the peer closed.
func (c *Conn) ReadMessage() (string, error) {
	var message []byte
	started := false
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return "", err
		}
		switch opcode {
		case opClose:
			_ = c.writeFrame(opClose, payload[:min(len(payload), 2)])
			return "", io.EOF
		case opPing:
			if err := c.writeFrame(opPong, payload); err != nil {
				return "", err
			}
			continue
		case opPong:
			continue
		case opText, opBinary:
			if started {
				return "", fmt.Errorf("%w: a new message inside another", ErrProtocol)
			}
			started, message = true, payload
		case opContinuation:
			if !started {
				return "", fmt.Errorf("%w: a continuation without a message", ErrProtocol)
			}
			message = append(message, payload...)
		default:
			return "", fmt.Errorf("%w: opcode %d", ErrProtocol, opcode)
		}
		if len(message) > MaxMessage {
			return "", fmt.Errorf("%w: message over %d bytes", ErrProtocol, MaxMessage)
		}
		if fin {
			return string(message), nil
		}
	}
}

// WriteText sends one text message.
func (c *Conn) WriteText(text string) error { return c.writeFrame(opText, []byte(text)) }

// Close sends a close frame and closes the connection.
func (c *Conn) Close() error {
	_ = c.writeFrame(opClose, []byte{0x03, 0xE8}) // 1000, normal closure
	return c.conn.Close()
}

// readFrame reads one frame; a client's frames are masked, a server's not.
func (c *Conn) readFrame() (bool, byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return false, 0, nil, err
	}
	fin, opcode := header[0]&0x80 != 0, header[0]&0x0F
	if header[0]&0x70 != 0 {
		return false, 0, nil, fmt.Errorf("%w: reserved bits set", ErrProtocol)
	}
	masked := header[1]&0x80 != 0
	if masked == c.client {
		return false, 0, nil, fmt.Errorf("%w: masking from the wrong side", ErrProtocol)
	}
	length := uint64(header[1] & 0x7F)
	switch length {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, extended); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, extended); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended)
	}
	if opcode >= opClose && (length > 125 || !fin) {
		return false, 0, nil, fmt.Errorf("%w: a fragmented or long control frame", ErrProtocol)
	}
	if length > MaxMessage {
		return false, 0, nil, fmt.Errorf("%w: frame over %d bytes", ErrProtocol, MaxMessage)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for index := range payload {
			payload[index] ^= mask[index%4]
		}
	}
	return fin, opcode, payload, nil
}

// writeFrame sends one final frame, masked when this side is the client.
func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	c.writing.Lock()
	defer c.writing.Unlock()
	frame := []byte{0x80 | opcode}
	maskBit := byte(0)
	if c.client {
		maskBit = 0x80
	}
	switch length := len(payload); {
	case length < 126:
		frame = append(frame, maskBit|byte(length))
	case length <= 0xFFFF:
		frame = append(frame, maskBit|126, byte(length>>8), byte(length))
	default:
		frame = append(frame, maskBit|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(length))
	}
	if c.client {
		var mask [4]byte
		_, _ = rand.Read(mask[:])
		frame = append(frame, mask[:]...)
		masked := make([]byte, len(payload))
		for index := range payload {
			masked[index] = payload[index] ^ mask[index%4]
		}
		payload = masked
	}
	_, err := c.conn.Write(append(frame, payload...))
	return err
}

func acceptFor(key string) string {
	digest := sha1.Sum([]byte(key + acceptGUID))
	return base64.StdEncoding.EncodeToString(digest[:])
}

// headerHas reports a comma-separated header holding a token.
func headerHas(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}
