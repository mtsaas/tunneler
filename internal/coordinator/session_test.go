package coordinator_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

// TestNarrowedGrantRevokesSession gives alice a session whose account has
// the roles readonly and readwrite, and then takes readwrite out of her
// grant. Her next connection is refused and the session ends, although the
// grant still reaches the service: the account holds a role that her grants
// no longer give.
func TestNarrowedGrantRevokesSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newSessionRig(ctx, t)
	s := r.createSession(ctx, t)
	if created := r.exit.asked(api.OpCreateRole); len(created) != 1 || !slices.Equal(created[0].Role.MemberOf, []string{"readonly", "readwrite"}) {
		t.Fatalf("the exit node was asked to create %+v", created)
	}
	r.connect(ctx, t, s.ID)

	cfg := r.cfg
	cfg.Grants = []coordinator.Grant{{User: "alice@example.com", Labels: shop, Roles: []string{"readonly"}}}
	r.c.Reload(&cfg)
	r.refused(ctx, t, s, `["readwrite"]`)
}

// TestRelabelledServiceRevokesSession gives alice a session on a service,
// whose exit node then offers it under labels that none of her grants
// select. Her next connection is refused and the session ends, although the
// labels the service had when the session was created still match.
func TestRelabelledServiceRevokesSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newSessionRig(ctx, t)
	s := r.createSession(ctx, t)

	r.exit.offer(t, orders(map[string]string{"team": "finance"}))
	r.await(ctx, t) // alice reaches nothing now
	r.refused(ctx, t, s, "no longer reach the service")
}

// TestUnchangedGrantKeepsSession reloads the configuration with alice's
// grants as they were, and then with a role added. Her session connects
// after each: only a role taken away ends it.
func TestUnchangedGrantKeepsSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newSessionRig(ctx, t)
	s := r.createSession(ctx, t)

	cfg := r.cfg
	r.c.Reload(&cfg)
	r.connect(ctx, t, s.ID)
	cfg.Grants = []coordinator.Grant{{User: "alice@example.com", Labels: shop, Roles: []string{"admin", "readonly", "readwrite"}}}
	r.c.Reload(&cfg)
	r.connect(ctx, t, s.ID)
	if sessions, err := r.alice.Sessions(ctx); err != nil || len(sessions) != 1 {
		t.Errorf("alice's sessions: %+v, %v; want the one", sessions, err)
	}
}

// TestSessionOutlastsExitNodeAbsence disconnects the exit node that offers
// a session's service. While no node offers it, a connection is refused as
// unavailable but the session is kept, for an exit node that restarts must
// not end every session of its cluster. Once the service is offered again,
// the session connects.
func TestSessionOutlastsExitNodeAbsence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newSessionRig(ctx, t)
	s := r.createSession(ctx, t)

	r.exit.sess.Close()
	r.await(ctx, t)
	conn, err := r.alice.DialSession(ctx, s.ID)
	if err == nil {
		conn.Close()
	}
	if e := (*api.Error)(nil); !errors.As(err, &e) || e.Status != http.StatusServiceUnavailable {
		t.Errorf("connecting while no exit node offers the service: %v; want 503", err)
	}
	r.exit = startFakeExit(ctx, t, r.srv.URL, orders(shop))
	r.await(ctx, t, "orders")
	r.connect(ctx, t, s.ID)
}

// shop is the label of the services that alice's grant selects.
var shop = map[string]string{"team": "shop"}

// orders is the postgres service that the stand-in exit node offers.
func orders(labels map[string]string) api.Service {
	return api.Service{Name: "orders", Kind: "postgres", Database: "orders", Labels: labels, Ready: true}
}

// sessionRig is a coordinator whose one grant gives alice the roles
// readonly and readwrite on the services of the team shop, and a stand-in
// for an exit node of the cluster prod, which offers one of them.
type sessionRig struct {
	cfg   coordinator.Config
	c     *coordinator.Coordinator
	srv   *httptest.Server
	alice *coordinator.Client
	exit  *fakeExit
	audit syncBuffer
}

func newSessionRig(ctx context.Context, t *testing.T) *sessionRig {
	t.Helper()
	r := &sessionRig{cfg: coordinator.Config{
		Database:         filepath.Join(t.TempDir(), "t.db"),
		SessionTTL:       coordinator.Duration(time.Hour),
		InsecureExitAuth: true,
		Grants:           []coordinator.Grant{{User: "alice@example.com", Labels: shop, Roles: []string{"readonly", "readwrite"}}},
	}}
	auth := func(_ context.Context, token string) (*coordinator.Identity, error) {
		if token == "alice" {
			return &coordinator.Identity{Subject: "1", Username: "alice@example.com"}, nil
		}
		return nil, errors.New("bad token")
	}
	cfg := r.cfg
	c, err := coordinator.New(&cfg, auth, slog.New(slog.DiscardHandler), slog.NewJSONHandler(&r.audit, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	r.c = c
	r.srv = httptest.NewServer(c.Handler())
	t.Cleanup(r.srv.Close)
	r.alice = &coordinator.Client{Server: r.srv.URL, Token: func(context.Context) (string, error) { return "alice", nil }}
	r.exit = startFakeExit(ctx, t, r.srv.URL, orders(shop))
	r.await(ctx, t, "orders")
	return r
}

func (r *sessionRig) createSession(ctx context.Context, t *testing.T) *api.Session {
	t.Helper()
	s, err := r.alice.CreateSession(ctx, map[string]string{"name": "orders"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// connect opens a connection to the session as alice, and closes it.
func (r *sessionRig) connect(ctx context.Context, t *testing.T, id string) {
	t.Helper()
	conn, err := r.alice.DialSession(ctx, id)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	conn.Close()
}

// refused checks that alice's next connection to the session is forbidden,
// and that the session has ended, its account dropped, for a reason that
// says why.
func (r *sessionRig) refused(ctx context.Context, t *testing.T, s *api.Session, why string) {
	t.Helper()
	conn, err := r.alice.DialSession(ctx, s.ID)
	if err == nil {
		conn.Close()
	}
	if e := (*api.Error)(nil); !errors.As(err, &e) || e.Status != http.StatusForbidden {
		t.Fatalf("connecting: %v; want 403", err)
	}
	if sessions, err := r.alice.Sessions(ctx); err != nil || len(sessions) != 0 {
		t.Errorf("alice's sessions: %+v, %v; want none", sessions, err)
	}
	if !slices.ContainsFunc(r.exit.asked(api.OpDropRole), func(req api.ExitRequest) bool { return req.Role.Name == s.Username }) {
		t.Errorf("the exit node was not asked to drop %s", s.Username)
	}
	for _, rec := range auditRecords(t, r.audit.String()) {
		if rec["msg"] == "session revoked" {
			if reason, _ := rec["reason"].(string); !strings.Contains(reason, why) {
				t.Errorf("the session was revoked because %q; want it to say %q", reason, why)
			}
			return
		}
	}
	t.Errorf("the revocation is not on the audit trail:\n%s", r.audit.String())
}

// await waits until the services alice can reach are the named ones.
func (r *sessionRig) await(ctx context.Context, t *testing.T, names ...string) {
	t.Helper()
	var reached []string
	for ctx.Err() == nil {
		clusters, _ := r.alice.Services(ctx)
		reached = nil
		for _, cl := range clusters {
			for _, svc := range cl.Services {
				reached = append(reached, svc.Name)
			}
		}
		if slices.Equal(reached, names) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("alice can reach %v, never %v", reached, names)
}

// fakeExit stands in for an exit node of the cluster prod. It offers what it
// is told to, does whatever it is asked to, and keeps the requests.
type fakeExit struct {
	sess    *tunnel.Session
	adverts net.Conn // the stream it advertises its services on

	mu       sync.Mutex
	requests []api.ExitRequest
}

func startFakeExit(ctx context.Context, t *testing.T, server string, services ...api.Service) *fakeExit {
	t.Helper()
	sess, err := (&coordinator.ExitClient{Server: server, Cluster: "prod"}).Connect(ctx, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	adverts, err := sess.Open()
	if err != nil {
		t.Fatal(err)
	}
	e := &fakeExit{sess: sess, adverts: adverts}
	e.offer(t, services...)
	go e.serve()
	return e
}

// offer advertises services in place of those offered before.
func (e *fakeExit) offer(t *testing.T, services ...api.Service) {
	t.Helper()
	if err := tunnel.WriteMessage(e.adverts, api.Hello{Services: services}); err != nil {
		t.Fatal(err)
	}
}

// serve answers every request of the coordinator with success.
func (e *fakeExit) serve() {
	for {
		stream, err := e.sess.Accept(context.Background())
		if err != nil {
			return
		}
		var req api.ExitRequest
		if tunnel.ReadMessage(stream, &req) == nil {
			e.mu.Lock()
			e.requests = append(e.requests, req)
			e.mu.Unlock()
			tunnel.WriteMessage(stream, api.ExitResult{})
		}
		stream.Close()
	}
}

// asked returns the requests for op that the node has answered.
func (e *fakeExit) asked(op string) []api.ExitRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(e.requests), func(req api.ExitRequest) bool { return req.Op != op })
}
