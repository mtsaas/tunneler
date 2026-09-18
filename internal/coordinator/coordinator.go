// Package coordinator implements the central server: it authenticates users,
// decides what they may reach, has exit nodes provision short-lived accounts
// on the target service, and proxies and audits the resulting connections.
package coordinator

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/postgres"
)

// A proxyFunc serves one client connection to a service of some kind. It
// speaks the service's protocol with the client, admits only the session's
// account, obtains its upstream connection from dial, reports everything the
// client does to audit, and closes client before returning.
type proxyFunc func(ctx context.Context, client net.Conn, dial func(context.Context) (net.Conn, error), s *api.Session, audit *slog.Logger) error

// proxies maps the kind a service is advertised with to the proxy that
// understands its protocol. Supporting a new kind of service means an entry
// here and a backend in package exit.
var proxies = map[string]proxyFunc{
	"postgres": func(ctx context.Context, client net.Conn, dial func(context.Context) (net.Conn, error), s *api.Session, audit *slog.Logger) error {
		return postgres.Proxy(ctx, client, dial, s.Username, s.Database, func(query string) {
			audit.Info("query", "sql", query)
		})
	},
}

// Coordinator is the central server.
type Coordinator struct {
	cfg   *Config
	auth  Authenticator
	hub   *hub
	store *store
	kube  *kubeVerifier
	log   *slog.Logger
	audit *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session
}

// New returns a Coordinator serving cfg, resuming any sessions saved by a
// previous run.
//
// Operational messages go to log. The access trail — sessions, connections
// and every statement — goes to audit; to store it somewhere other than the
// process log, hand New a logger with a different slog.Handler.
func New(cfg *Config, auth Authenticator, log, audit *slog.Logger) (*Coordinator, error) {
	kube, err := newKubeVerifier(cfg)
	if err != nil {
		return nil, err
	}
	st, err := openStore(cfg.Database)
	if err != nil {
		return nil, err
	}
	sessions, err := st.load()
	if err != nil {
		st.db.Close()
		return nil, err
	}
	c := &Coordinator{
		cfg:      cfg,
		auth:     auth,
		hub:      newHub(log),
		store:    st,
		kube:     kube,
		log:      log,
		audit:    audit,
		sessions: make(map[string]*session),
	}
	c.hub.onConnect = c.retryDrops
	log.Info("session database opened", "path", cfg.Database, "saved_sessions", len(sessions))
	for _, s := range sessions {
		if s.revoked {
			continue // awaiting retryDrops
		}
		// A session that expired while the coordinator was down fires at once.
		c.sessions[s.info.ID] = s
		s.expiry = time.AfterFunc(time.Until(s.info.ExpiresAt), func() { c.revoke(s.info.ID, "expired") })
	}
	return c, nil
}

// Close disconnects every session and closes the session database. Sessions
// stay valid and resume when a coordinator next starts on the same database.
func (c *Coordinator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sessions {
		s.expiry.Stop()
		s.interrupt()
	}
	clear(c.sessions)
	return c.store.db.Close()
}

// session is a provisioned account and the connections using it.
type session struct {
	info    api.Session       // never holds the password
	subject string            // owner's Identity.Subject
	labels  map[string]string // of the service, as advertised at creation
	expiry  *time.Timer

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	watchers map[chan string]struct{} // told the reason when the session ends
	revoked  bool
}

// track registers a connection so that revocation closes it. It reports
// false if the session is already revoked.
func (s *session) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *session) untrack(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

// watch returns a channel that receives the reason once the session ends,
// and a function to stop watching.
func (s *session) watch() (<-chan string, func()) {
	ch := make(chan string, 1)
	s.mu.Lock()
	if s.watchers == nil {
		s.watchers = make(map[chan string]struct{})
	}
	s.watchers[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.watchers, ch)
		s.mu.Unlock()
	}
}

// end closes the session's connections, refuses new ones, and tells
// watchers why.
func (s *session) end(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = true
	for conn := range s.conns {
		conn.Close()
	}
	for ch := range s.watchers {
		ch <- reason
		delete(s.watchers, ch)
	}
}

// interrupt closes the session's connections and watch streams without
// ending the session, as at a coordinator shutdown.
func (s *session) interrupt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.conns {
		conn.Close()
	}
	for ch := range s.watchers {
		close(ch)
		delete(s.watchers, ch)
	}
}

func (s *session) attrs() slog.Attr {
	return slog.Group("session",
		"id", s.info.ID,
		"subject", s.subject,
		"owner", s.info.Owner,
		"cluster", s.info.Cluster,
		"service", s.info.Service,
		"username", s.info.Username,
	)
}

// createSession has an exit node provision an account for id on svc, and
// returns the session including its password.
func (c *Coordinator) createSession(ctx context.Context, id *Identity, cluster string, svc api.Service, roles []string) (*api.Session, error) {
	if proxies[svc.Kind] == nil {
		return nil, fmt.Errorf("this coordinator cannot proxy services of kind %q", svc.Kind)
	}
	ttl := time.Duration(c.cfg.SessionTTL)
	s := &session{
		info: api.Session{
			ID:        rand.Text(),
			Owner:     id.Username,
			Cluster:   cluster,
			Service:   svc.Name,
			Kind:      svc.Kind,
			Database:  svc.Database,
			Username:  roleName(id.Username),
			ExpiresAt: time.Now().Add(ttl).Truncate(time.Second),
		},
		subject: id.Subject,
		labels:  svc.Labels,
		conns:   make(map[net.Conn]struct{}),
	}
	// Record the session before the account exists, never the reverse: a
	// crash in between must not leave an account that nothing will revoke.
	if err := c.store.insert(s); err != nil {
		return nil, err
	}
	password := rand.Text()
	_, err := c.hub.call(ctx, cluster, api.ExitRequest{
		Op:      api.OpCreateRole,
		Service: svc.Name,
		Role:    &api.Role{Name: s.info.Username, Password: password, ValidUntil: s.info.ExpiresAt, MemberOf: roles},
	})
	if err != nil {
		if err := c.store.delete(s.info.ID); err != nil {
			c.log.Error("deleting session", s.attrs(), "err", err)
		}
		return nil, err
	}

	c.mu.Lock()
	c.sessions[s.info.ID] = s
	s.expiry = time.AfterFunc(ttl, func() { c.revoke(s.info.ID, "expired") })
	c.mu.Unlock()
	c.audit.Info("session created", s.attrs(), "roles", roles, "expires_at", s.info.ExpiresAt)

	info := s.info
	info.Password = password
	return &info, nil
}

// revoke ends a session: its connections are closed and its account dropped.
// It reports whether the session existed.
func (c *Coordinator) revoke(id, reason string) bool {
	c.mu.Lock()
	s, ok := c.sessions[id]
	delete(c.sessions, id)
	c.mu.Unlock()
	if !ok {
		return false
	}
	s.expiry.Stop()
	s.end(reason)
	c.audit.Info("session revoked", s.attrs(), "reason", reason)

	if err := c.dropAccount(s); err != nil {
		// Keep the session on record as a pending drop, to be retried when an
		// exit node for its cluster next connects. Until then the account is
		// unreachable through the tunnel, and Postgres refuses it after its
		// VALID UNTIL regardless.
		c.log.Warn("could not drop the session's account; will retry when the cluster's exit node reconnects", s.attrs(), "err", err)
		if err := c.store.markRevoked(id); err != nil {
			c.log.Error("recording pending drop", s.attrs(), "err", err)
		}
		return true
	}
	if err := c.store.delete(id); err != nil {
		c.log.Error("deleting session", s.attrs(), "err", err)
	}
	return true
}

func (c *Coordinator) dropAccount(s *session) error {
	// The request that led here may be long gone, hence no caller context.
	_, err := c.hub.call(context.Background(), s.info.Cluster, api.ExitRequest{
		Op:      api.OpDropRole,
		Service: s.info.Service,
		Role:    &api.Role{Name: s.info.Username},
	})
	return err
}

// retryDrops runs when an exit node connects. It drops the accounts of the
// cluster's sessions that ended while no exit node could be reached, which
// includes sessions that expired while the coordinator itself was down.
func (c *Coordinator) retryDrops(cluster string) {
	sessions, err := c.store.load()
	if err != nil {
		c.log.Error("loading pending drops", "err", err)
		return
	}
	for _, s := range sessions {
		if !s.revoked || s.info.Cluster != cluster {
			continue
		}
		if err := c.dropAccount(s); err != nil {
			c.log.Warn("pending drop failed again", s.attrs(), "err", err)
			continue
		}
		c.log.Info("pending drop completed: account dropped", s.attrs())
		if err := c.store.delete(s.info.ID); err != nil {
			c.log.Error("deleting session", s.attrs(), "err", err)
		}
	}
	if err := c.store.pruneRevoked(time.Now()); err != nil {
		c.log.Error("pruning expired pending drops", "err", err)
	}
}

// serveSession proxies one client connection on behalf of a session. It
// closes conn before returning.
func (c *Coordinator) serveSession(ctx context.Context, s *session, conn net.Conn) {
	defer conn.Close()
	proxy := proxies[s.info.Kind]
	if proxy == nil { // a session resumed from a newer coordinator's database
		c.log.Error("no proxy for session's kind", s.attrs(), "kind", s.info.Kind)
		return
	}
	if !s.track(conn) {
		return
	}
	defer s.untrack(conn)

	dial := func(ctx context.Context) (net.Conn, error) {
		return c.hub.call(ctx, s.info.Cluster, api.ExitRequest{Op: api.OpDial, Service: s.info.Service})
	}
	log := c.audit.With(s.attrs(), "remote", conn.RemoteAddr().String())
	log.Info("connection opened")
	start := time.Now()
	err := proxy(ctx, conn, dial, &s.info, log)
	if errors.Is(err, net.ErrClosed) {
		err = nil // we closed it: the session was revoked
	}
	log.Info("connection closed", "duration", time.Since(start).Round(time.Millisecond).String(), "err", err)
}

// roleName derives a unique account name from a username. Postgres truncates
// identifiers at 63 bytes, so the readable part is kept short of that.
func roleName(username string) string {
	var b strings.Builder
	b.WriteString(postgres.RolePrefix)
	for _, r := range strings.ToLower(username) {
		if b.Len() == 50 {
			break
		}
		if 'a' <= r && r <= 'z' || '0' <= r && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	// The suffix keeps concurrent sessions of one user, and usernames that
	// sanitize to the same text, from sharing a role.
	b.WriteByte('_')
	b.WriteString(strings.ToLower(rand.Text()[:8]))
	return b.String()
}
