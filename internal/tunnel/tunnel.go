// Package tunnel carries byte streams between tunneler's parts over
// WebSocket connections, so that the coordinator needs only a single HTTPS
// port for its API, client streams and exit node streams, and so that the
// streams pass through any proxy, ingress or service mesh without special
// configuration. A Session carries many streams over one such connection.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"
)

// Dial connects to rawURL, which must have an http or https scheme, and
// returns a stream to the server. The header is sent with the handshake and
// may be nil.
func Dial(ctx context.Context, rawURL string, header http.Header) (net.Conn, error) {
	ws, resp, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
			return nil, &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
		}
		return nil, err
	}
	return stream(ws), nil
}

// stream adapts a WebSocket to a net.Conn carrying one binary message per
// Write.
func stream(ws *websocket.Conn) net.Conn {
	ws.SetReadLimit(-1) // a stream, not messages: the peer's writes have no meaningful size
	// The stream's life is governed by Close, not by a context.
	return &conn{Conn: websocket.NetConn(context.Background(), ws, websocket.MessageBinary), ws: ws}
}

// conn makes Close prompt. A WebSocket closes with a handshake, which lets
// the peer read a clean EOF, but which waits seconds for a peer that has
// gone away. Callers close streams while holding locks, and to revoke access
// at once, so the handshake runs in the background.
type conn struct {
	net.Conn
	ws   *websocket.Conn
	once sync.Once
}

func (c *conn) Close() error {
	c.once.Do(func() { go c.Conn.Close() })
	return nil
}

// StatusError is returned by Dial when the server answers the handshake with
// an ordinary HTTP response instead.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("tunnel: server refused the stream: %d %s: %s", e.Code, http.StatusText(e.Code), e.Body)
}

// Accept turns an incoming request into a stream. On failure it writes an
// error response and the caller should simply return.
func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	// The peer is a tunneler binary, never a browser, so the Origin check
	// that protects cookie-authenticated sites has nothing to protect.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return nil, err // Accept has already responded
	}
	return stream(ws), nil
}

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
