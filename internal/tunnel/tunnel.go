// Package tunnel carries raw byte streams over HTTP/1.1 connection upgrades,
// so that the coordinator needs only a single HTTPS port for its API, client
// streams and exit node streams.
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// protocol is the Upgrade token spoken by both ends.
const protocol = "tunneler"

// Dial connects to rawURL, which must have an http or https scheme, and
// upgrades the connection to a raw stream. The header is sent with the
// upgrade request and may be nil.
func Dial(ctx context.Context, rawURL string, header http.Header) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	addr := u.Host
	var d interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
	switch u.Scheme {
	case "http":
		if u.Port() == "" {
			addr = net.JoinHostPort(u.Hostname(), "80")
		}
		d = &net.Dialer{}
	case "https":
		if u.Port() == "" {
			addr = net.JoinHostPort(u.Hostname(), "443")
		}
		// Upgrades do not exist in HTTP/2, so never negotiate it.
		d = &tls.Dialer{Config: &tls.Config{NextProtos: []string{"http/1.1"}}}
	default:
		return nil, fmt.Errorf("tunnel: unsupported scheme %q", u.Scheme)
	}

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, err := upgrade(conn, u, header)
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func upgrade(conn net.Conn, u *url.URL, header http.Header) (net.Conn, error) {
	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Host:   u.Host,
		Header: header.Clone(),
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", protocol)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		resp.Body.Close()
		return nil, &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

// StatusError is returned by Dial when the server answers the upgrade request
// with an ordinary HTTP response instead.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("tunnel: server refused upgrade: %d %s: %s", e.Code, http.StatusText(e.Code), e.Body)
}

// Accept upgrades an incoming request to a raw stream. On failure it writes
// an error response and the caller should simply return.
func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), protocol) {
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return nil, errors.New("tunnel: not an upgrade request")
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "connection cannot be upgraded", http.StatusInternalServerError)
		return nil, err
	}
	_, err = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + protocol + "\r\n\r\n")
	if err == nil {
		err = brw.Flush()
	}
	if err == nil {
		// Drop whatever deadlines the HTTP server had set.
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &bufferedConn{Conn: conn, r: brw.Reader}, nil
}

// bufferedConn is a net.Conn whose first reads are served from the buffer
// that parsed the HTTP handshake, which may already hold stream data.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Splice copies between a and b until either side fails or is closed, then
// closes both.
func Splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		// ponytail: no half-close; tearing down both directions is right for
		// request/response protocols like Postgres and Redis.
		dst.Close()
		src.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
