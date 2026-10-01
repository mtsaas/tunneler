package coordinator

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

func (c *Coordinator) shareHandler(control http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := c.shares
		m.mu.Lock()
		routing := m.routing
		m.mu.Unlock()
		if routing == nil {
			control.ServeHTTP(w, r)
			return
		}
		host := strings.ToLower(strings.TrimSuffix(hostOf(r.Host), "."))
		m.mu.Lock()
		match, found := m.hosts[host]
		m.mu.Unlock()
		if found {
			c.serveShareHTTP(w, r, match)
			return
		}
		cfg := *routing
		if host == cfg.Domain || strings.HasSuffix(host, "."+cfg.Domain) {
			http.NotFound(w, r)
			return
		}
		for _, allowed := range cfg.ControlHosts {
			if strings.EqualFold(r.Host, allowed) || strings.EqualFold(host, allowed) {
				control.ServeHTTP(w, r)
				return
			}
		}
		if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && (r.Method == "GET" || r.Method == "HEAD") && r.URL.Path == "/healthz" {
			writeJSON(w, 200, map[string]string{"status": "ok"})
			return
		}
		http.NotFound(w, r)
	})
}

type shareHTTPProxy struct {
	proxy     *httputil.ReverseProxy
	transport *http.Transport
}

type shareHTTPRequestContextKey struct{}

type shareHTTPBufferPool struct{ buffers sync.Pool }

func (p *shareHTTPBufferPool) Get() []byte    { return p.buffers.Get().([]byte) }
func (p *shareHTTPBufferPool) Put(buf []byte) { p.buffers.Put(buf) }

var shareHTTPBuffers = shareHTTPBufferPool{buffers: sync.Pool{New: func() any { return make([]byte, 32<<10) }}}

func (c *Coordinator) newShareHTTPProxy(s *sharedServiceSet, service api.ShareService) *shareHTTPProxy {
	cfg := c.config().sharingConfig()
	limit := min(cfg.MaxConnectionsPerShare, cfg.MaxConnectionsPerUser, cfg.MaxConnections)
	transport := &http.Transport{
		DialContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return s.dialHTTP(ctx, service.ID) },
		MaxIdleConnsPerHost: limit, MaxConnsPerHost: limit,
		IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true,
	}
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		BufferPool:    &shareHTTPBuffers,
		ErrorLog:      slog.NewLogLogger(c.log.Handler(), slog.LevelError),
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", service.ID
			pr.Out.Host = pr.In.Host
			for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP"} {
				pr.Out.Header.Del(header)
			}
			pr.Out.Header.Set("X-Forwarded-For", c.remote(pr.In))
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			// All public URLs are HTTPS; TLS may terminate at the trusted edge.
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			status := http.StatusBadGateway
			message := "preview service is unavailable"
			if cause := context.Cause(r.Context()); cause != nil {
				err = cause
			}
			var ae *api.Error
			if errors.As(err, &ae) && ae.Code == "quota_exceeded" {
				status = http.StatusServiceUnavailable
				message = ae.Message
			}
			http.Error(w, message, status)
		},
	}
	return &shareHTTPProxy{proxy: proxy, transport: transport}
}

func (s *sharedServiceSet) dialHTTP(ctx context.Context, serviceID string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	// Transport detaches cancellation while dialing. Keep an unused tunnel
	// dial from consuming capacity after its visitor has gone away.
	if request, ok := ctx.Value(shareHTTPRequestContextKey{}).(context.Context); ok {
		stop := context.AfterFunc(request, cancel)
		defer stop()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m := s.manager
		m.mu.Lock()
		changed := m.capacity
		m.mu.Unlock()
		conn, err := s.dial(ctx, serviceID)
		var ae *api.Error
		if !errors.As(err, &ae) || ae.Code != "quota_exceeded" {
			return conn, err
		}
		s.closeIdleHTTPConnections(serviceID)
		select {
		case <-changed:
		case <-s.ctx.Done():
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, shareAPIError(503, "quota_exceeded", "preview connection queue timed out")
		}
	}
}

// Reclaim idle pools only when they consume the exhausted socket budget.
// This lets another service or share use an owner's available capacity.
func (s *sharedServiceSet) closeIdleHTTPConnections(serviceID string) {
	m := s.manager
	m.mu.Lock()
	cfg := m.c.config().sharingConfig()
	owner := shareOwnerKey(&s.owner)
	globalFull := m.connections >= cfg.MaxConnections
	ownerFull := m.ownerConnections[owner] >= cfg.MaxConnectionsPerUser
	shareFull := s.connections >= cfg.MaxConnectionsPerShare
	if !globalFull && !ownerFull && !shareFull {
		m.mu.Unlock()
		return
	}
	var transports []*http.Transport
	for _, other := range m.shares {
		if globalFull || (ownerFull && shareOwnerKey(&other.owner) == owner) || (shareFull && other == s) {
			for id, proxy := range other.proxies {
				if other != s || id != serviceID {
					transports = append(transports, proxy.transport)
				}
			}
		}
	}
	m.mu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

func (c *Coordinator) serveShareHTTP(w http.ResponseWriter, r *http.Request, match shareHost) {
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT is not supported", http.StatusMethodNotAllowed)
		return
	}
	s := match.share
	m := c.shares
	m.mu.Lock()
	if !s.liveLocked() || s.info.State != "ready" {
		m.mu.Unlock()
		http.Error(w, "publisher is unavailable", http.StatusServiceUnavailable)
		return
	}
	controller := http.NewResponseController(w)
	frontend := &shareFrontend{setDeadline: func(deadline time.Time) error {
		return errors.Join(controller.SetReadDeadline(deadline), controller.SetWriteDeadline(deadline))
	}}
	if err := s.reserveFrontendLocked(frontend); err != nil {
		m.mu.Unlock()
		http.Error(w, "preview request limit reached", http.StatusServiceUnavailable)
		return
	}
	proxy := s.proxies[match.service]
	if proxy == nil {
		for _, service := range s.info.Services {
			if service.ID == match.service {
				proxy = c.newShareHTTPProxy(s, service)
				s.proxies[match.service] = proxy
				break
			}
		}
	}
	frontend.setDeadline(s.connectionDeadlineLocked())
	audit := c.audit.With("share", s.info.ID, "service", match.service, "issuer", s.owner.Issuer, "subject", s.owner.Subject, "user", s.owner.Username, "remote", c.remote(r))
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		s.releaseFrontendLocked(frontend)
		// Synchronize reset with end/renewal so a completed request cannot
		// receive a late deadline that affects the next keep-alive request.
		frontend.setDeadline(time.Time{})
		m.mu.Unlock()
	}()
	if proxy == nil {
		http.NotFound(w, r)
		return
	}
	// A request can stream or upgrade indefinitely. Record its admission
	// before forwarding any application bytes to the publisher.
	if mustAudit(r.Context(), audit, "share request opened") != nil {
		http.Error(w, "the audit trail could not record this request", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	stopCancel := context.AfterFunc(s.ctx, func() { cancel(net.ErrClosed) })
	defer stopCancel()
	queueTimer := time.AfterFunc(callTimeout, func() {
		cancel(shareAPIError(503, "quota_exceeded", "preview request queue timed out"))
	})
	defer queueTimer.Stop()
	ctx = context.WithValue(ctx, shareHTTPRequestContextKey{}, ctx)
	request := r.Clone(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { queueTimer.Stop() }}))
	recorder := &shareResponseWriter{ResponseWriter: w, share: s}
	start := time.Now()
	defer func() {
		audit.Info("share request closed", "status", recorder.status, "duration", time.Since(start))
	}()
	proxy.proxy.ServeHTTP(recorder, request)
}

// ReverseProxy reads from the hijacked net.Conn rather than brw.Reader.
// Preserve bytes already buffered with the client's upgrade handshake.
type shareBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *shareBufferedConn) Read(p []byte) (int, error) { return conn.reader.Read(p) }

type shareResponseWriter struct {
	http.ResponseWriter
	share  *sharedServiceSet
	status int
}

func (w *shareResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *shareResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *shareResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(p)
}
func (w *shareResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, nil, err
	}
	buffered := &shareBufferedConn{Conn: conn, reader: brw.Reader}
	m := w.share.manager
	m.mu.Lock()
	if !w.share.liveLocked() {
		m.mu.Unlock()
		conn.Close()
		return nil, nil, net.ErrClosed
	}
	tracked := w.share.trackLocked(buffered, false)
	m.mu.Unlock()
	w.status = http.StatusSwitchingProtocols
	return tracked, brw, nil
}
