package infrastructure

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"codeberg.org/simplicer/trebaruna/src/transparency/domain"
)

// Dial opens a TCP connection that is not HTTP, such as LDAP's, and records
// it under purpose when it closes, or at once when it cannot be opened: the
// destination as scheme://address, the bytes each way and how long it
// lasted. With a TLS configuration the connection is secured before it is
// handed out.
func Dial(ctx context.Context, purpose domain.Purpose, scheme, address string, secured *tls.Config) (net.Conn, error) {
	started := time.Now()
	entry := domain.Connection{Purpose: purpose, Method: scheme, URL: scheme + "://" + address + "/", StartedAt: started}
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err == nil && secured != nil {
		client := tls.Client(connection, secured)
		if err = client.HandshakeContext(ctx); err != nil {
			connection.Close()
		} else {
			connection = client
		}
	}
	if err != nil {
		entry.Error, entry.DurationMS = err.Error(), time.Since(started).Milliseconds()
		record(entry)
		return nil, err
	}
	return &recordedConnection{Conn: connection, entry: entry}, nil
}

// recordedConnection counts what crosses it and records itself once, when
// closed.
type recordedConnection struct {
	net.Conn
	entry domain.Connection
	once  sync.Once
}

func (c *recordedConnection) Read(buffer []byte) (int, error) {
	read, err := c.Conn.Read(buffer)
	c.entry.Received += int64(read)
	return read, err
}

func (c *recordedConnection) Write(buffer []byte) (int, error) {
	written, err := c.Conn.Write(buffer)
	c.entry.SentBytes += int64(written)
	return written, err
}

func (c *recordedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.entry.DurationMS = time.Since(c.entry.StartedAt).Milliseconds()
		record(c.entry)
	})
	return err
}
