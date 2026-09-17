package postgres

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Request codes that may appear in place of a protocol version in the first
// packet of a connection.
const (
	codeCancel = 80877102
	codeSSL    = 80877103
	codeGSSENC = 80877104
)

const (
	maxStartupLen = 10000    // same bound the Postgres server applies
	maxAuditLen   = 64 << 10 // query text beyond this is forwarded but not logged
)

// Proxy serves one client connection: it completes the startup negotiation,
// checks that the client is logging in as role to database, obtains an
// upstream connection from dial, and relays traffic until either side
// disconnects. Every SQL statement the client sends is passed to audit before
// it is forwarded.
//
// Authentication itself is end-to-end between the client and Postgres; the
// proxy only observes it. Proxy closes client before returning.
func Proxy(ctx context.Context, client net.Conn, dial func(context.Context) (net.Conn, error), role, database string, audit func(query string)) error {
	defer client.Close()

	pkt, err := readStartup(client)
	if err != nil {
		return err
	}
	if binary.BigEndian.Uint32(pkt[4:]) == codeCancel {
		// The key in a cancel request is the upstream's own, so it can be
		// forwarded verbatim on a fresh connection.
		upstream, err := dial(ctx)
		if err != nil {
			return err
		}
		defer upstream.Close()
		_, err = upstream.Write(pkt)
		return err
	}

	params, err := parseStartup(pkt)
	if err != nil {
		return err
	}
	// Without these checks a session would be a tunnel to any role whose
	// password the user happens to know.
	if params["user"] != role {
		writeFatal(client, "28000", fmt.Sprintf("this session only permits logging in as %q", role))
		return fmt.Errorf("postgres: client attempted login as %q, want %q", params["user"], role)
	}
	if db := params["database"]; db != database {
		writeFatal(client, "3D000", fmt.Sprintf("this session only permits database %q", database))
		return fmt.Errorf("postgres: client requested database %q, want %q", db, database)
	}

	upstream, err := dial(ctx)
	if err != nil {
		writeFatal(client, "08001", "tunnel could not reach the database: "+err.Error())
		return err
	}
	defer upstream.Close()
	if _, err := upstream.Write(pkt); err != nil {
		return err
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(client, upstream)
		errc <- err
	}()
	go func() { errc <- relay(upstream, client, audit) }()
	err = <-errc
	client.Close()
	upstream.Close()
	<-errc
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

// Connect opens a raw connection to the server, ready for a startup packet,
// having negotiated TLS as the DSN's sslmode demands.
func (s *Server) Connect(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.Addr())
	if err != nil {
		return nil, err
	}
	if s.cfg.TLSConfig == nil {
		return conn, nil
	}
	var resp [1]byte
	_, err = conn.Write(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, codeSSL))
	if err == nil {
		_, err = io.ReadFull(conn, resp[:])
	}
	switch {
	case err != nil:
	case resp[0] == 'S':
		tc := tls.Client(conn, s.cfg.TLSConfig)
		if err = tc.HandshakeContext(ctx); err == nil {
			return tc, nil
		}
	case s.plaintextOK():
		return conn, nil
	default:
		err = errors.New("postgres: server refused TLS")
	}
	conn.Close()
	return nil, err
}

// plaintextOK reports whether the DSN's sslmode permits an unencrypted
// connection when the server refuses TLS (sslmode=prefer).
func (s *Server) plaintextOK() bool {
	for _, f := range s.cfg.Fallbacks {
		if f.TLSConfig == nil {
			return true
		}
	}
	return false
}

// readStartup returns the client's first real packet, a StartupMessage or
// CancelRequest, declining any requests for encryption that precede it: the
// client's hop to the coordinator is already inside TLS.
func readStartup(client net.Conn) ([]byte, error) {
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		code := binary.BigEndian.Uint32(hdr[4:])
		if n < 8 || n > maxStartupLen {
			return nil, fmt.Errorf("postgres: invalid startup packet length %d", n)
		}
		if n == 8 && (code == codeSSL || code == codeGSSENC) {
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, err
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, hdr[:])
		if _, err := io.ReadFull(client, pkt[8:]); err != nil {
			return nil, err
		}
		return pkt, nil
	}
}

// parseStartup returns the parameters of a StartupMessage.
func parseStartup(pkt []byte) (map[string]string, error) {
	if v := binary.BigEndian.Uint32(pkt[4:]); v>>16 != 3 {
		return nil, fmt.Errorf("postgres: unsupported protocol version %d.%d", v>>16, v&0xffff)
	}
	params := make(map[string]string)
	body := pkt[8:]
	for len(body) > 1 {
		var key, val []byte
		var ok bool
		if key, body, ok = bytes.Cut(body, []byte{0}); ok {
			val, body, ok = bytes.Cut(body, []byte{0})
		}
		if !ok {
			return nil, errors.New("postgres: malformed startup packet")
		}
		params[string(key)] = string(val)
	}
	if params["database"] == "" {
		params["database"] = params["user"] // the server's own default
	}
	return params, nil
}

// relay forwards frontend messages from src to dst, reporting the text of
// each Query and Parse message to audit before it is forwarded.
//
// ponytail: Bind parameter values are not audited, only statement text.
// Decode 'B' messages here if the values matter.
func relay(dst io.Writer, src io.Reader, audit func(string)) error {
	br := bufio.NewReader(src)
	bw := bufio.NewWriter(dst)
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return err
		}
		n := int64(binary.BigEndian.Uint32(hdr[1:])) - 4
		if n < 0 {
			return fmt.Errorf("postgres: invalid length in %q message", hdr[0])
		}
		bw.Write(hdr[:])

		if hdr[0] == 'Q' || hdr[0] == 'P' {
			head := make([]byte, min(n, maxAuditLen))
			if _, err := io.ReadFull(br, head); err != nil {
				return err
			}
			audit(statementText(hdr[0], head, n > maxAuditLen))
			bw.Write(head)
			n -= int64(len(head))
		}
		if _, err := io.CopyN(bw, br, n); err != nil {
			return err
		}
		// Flush only once the client has nothing more queued, so pipelined
		// messages share a write.
		if br.Buffered() == 0 {
			if err := bw.Flush(); err != nil {
				return err
			}
		}
	}
}

// statementText extracts the SQL from the leading bytes of a Query ('Q') or
// Parse ('P') message body.
func statementText(typ byte, body []byte, truncated bool) string {
	if typ == 'P' { // skip the prepared statement's name
		_, body, _ = bytes.Cut(body, []byte{0})
	}
	body, _, _ = bytes.Cut(body, []byte{0})
	if truncated {
		return string(body) + " [truncated]"
	}
	return string(body)
}

// writeFatal sends the client a FATAL ErrorResponse with the given SQLSTATE.
func writeFatal(w io.Writer, sqlstate, msg string) {
	var body []byte
	for _, f := range []string{"SFATAL", "VFATAL", "C" + sqlstate, "M" + msg} {
		body = append(append(body, f...), 0)
	}
	body = append(body, 0)
	pkt := binary.BigEndian.AppendUint32([]byte{'E'}, uint32(len(body)+4))
	w.Write(append(pkt, body...))
}
