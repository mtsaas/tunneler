package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// Session carries many streams over one connection, so that a new stream
// costs one message rather than a handshake. Either side may open streams,
// and the other accepts them. Keepalives from both sides, every 30 seconds,
// keep idle proxies from cutting the connection and end the session when
// the path dies.
type Session struct {
	mux *yamux.Session
}

// Client starts a session on conn for the side that dialed it, and Server
// for the side that accepted it. The session's own reports go to log at
// debug level: what matters surfaces as errors from Open and Accept, and
// the rest is mostly streams ending with data still in flight.
func Client(conn net.Conn, log *slog.Logger) *Session { return newSession(yamux.Client, conn, log) }

// Server starts a session on conn for the side that accepted it; see
// Client.
func Server(conn net.Conn, log *slog.Logger) *Session { return newSession(yamux.Server, conn, log) }

func newSession(start func(io.ReadWriteCloser, *yamux.Config) (*yamux.Session, error), nc net.Conn, log *slog.Logger) *Session {
	cfg := yamux.DefaultConfig()
	// ponytail: a fixed window. A stream moves at most a window per round
	// trip, 80 MB/s at 50 ms, and a stream whose reader stalls holds up to a
	// window in memory. Raise it for faster long-haul links.
	cfg.MaxStreamWindowSize = 4 << 20
	// A keepalive's reply queues behind whatever the streams are sending, so
	// a busy, slow link needs longer than the default 10 seconds. A dead one
	// is still noticed within a minute.
	cfg.ConnectionWriteTimeout = 30 * time.Second
	cfg.LogOutput = nil
	cfg.Logger = slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	if c, ok := nc.(*conn); ok {
		nc = abruptConn{c}
	}
	mux, err := start(nc, cfg)
	if err != nil {
		panic(err) // the configuration is fixed, and valid
	}
	return &Session{mux: mux}
}

// Open opens a stream to the peer.
func (s *Session) Open() (net.Conn, error) {
	st, err := s.mux.OpenStream()
	if err != nil {
		return nil, err
	}
	return &muxStream{Stream: st}, nil
}

// Accept waits for the peer to open a stream.
func (s *Session) Accept(ctx context.Context) (net.Conn, error) {
	st, err := s.mux.AcceptStreamWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &muxStream{Stream: st}, nil
}

// Close ends the session and every stream on it.
func (s *Session) Close() error { return s.mux.Close() }

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.mux.CloseChan() }

// abruptConn closes a session's WebSocket at once, without the close
// handshake, which waits seconds for a peer that has gone away. A session's
// end is abrupt anyway, since it cuts off every stream, and until its
// connection is closed yamux spins each goroutine blocked on one of them.
type abruptConn struct{ *conn }

func (c abruptConn) Close() error {
	c.ws.CloseNow()
	return c.conn.Conn.Close() // stops the adapter's timers; the WebSocket is closed already
}

// errSessionEnded is what a stream reads when the session under it ends
// before the peer has closed it, as when the path to the peer dies.
var errSessionEnded = errors.New("tunnel: the session carrying the stream ended")

// muxStream holds a yamux stream to net.Conn's contract, under which Close
// unblocks a Read or Write in progress, and to this package's rule that
// Close returns at once, since callers close streams while holding locks.
// A yamux stream's own Close only tells the peer that nothing more will be
// written, and waits until that is sent; reads go on until the peer closes
// too, which a stalled peer may never do. Whoever closes a stream here is
// done with both directions.
type muxStream struct {
	*yamux.Stream
	closed atomic.Bool
}

func (s *muxStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	return n, s.explain(err)
}

func (s *muxStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	return n, s.explain(err)
}

// explain returns err as the stream's user should see it.
func (s *muxStream) explain(err error) error {
	switch {
	case err == nil:
		return nil
	case s.closed.Load():
		return net.ErrClosed
	case err == io.EOF && s.Stream.Session().IsClosed():
		return errSessionEnded
	}
	return err
}

func (s *muxStream) Close() error {
	if !s.closed.Swap(true) {
		s.Stream.SetDeadline(time.Now()) // wakes a Read or Write in progress
		go s.Stream.Close()
	}
	return nil
}

// maxMessage bounds a message, so that a peer cannot make the reader
// allocate without limit. An exit node's hello listing thousands of
// services fits many times over.
const maxMessage = 4 << 20

// WriteMessage writes v as JSON, framed with its length, for ReadMessage.
// Unlike a line of JSON, a frame is read without reading past its end, so
// whatever follows it on the stream is left for the next reader.
func WriteMessage(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > maxMessage {
		return fmt.Errorf("tunnel: message of %d bytes exceeds the limit of %d", len(data), maxMessage)
	}
	frame := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(data)), uint32(len(data)))
	_, err = w.Write(append(frame, data...))
	return err
}

// ReadMessage reads a message that WriteMessage wrote into v.
func ReadMessage(r io.Reader, v any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > maxMessage {
		return fmt.Errorf("tunnel: message of %d bytes exceeds the limit of %d", n, maxMessage)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
