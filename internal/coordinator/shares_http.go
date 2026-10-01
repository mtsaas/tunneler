package coordinator

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
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

func (c *Coordinator) newShareHTTPProxy(s *sharedServiceSet, service api.ShareService) *shareHTTPProxy {
	transport := &http.Transport{
		DialContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return s.dial(ctx, service.ID) },
		MaxIdleConnsPerHost: 4, MaxConnsPerHost: c.config().sharingConfig().MaxConnectionsPerShare,
		IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true,
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
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
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			status := http.StatusBadGateway
			var ae *api.Error
			if errors.As(err, &ae) && ae.Code == "quota_exceeded" {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, "preview service is unavailable", status)
		},
	}
	return &shareHTTPProxy{proxy: proxy, transport: transport}
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
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stopCancel := context.AfterFunc(s.ctx, cancel)
	defer stopCancel()
	request := r.Clone(ctx)
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
