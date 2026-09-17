// Package exit implements the exit node: an agent inside a cluster that dials
// out to the coordinator, advertises the cluster's services, and on request
// provisions accounts on them and connects the coordinator to them.
//
// Administrative credentials live only here, inside the cluster.
package exit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/postgres"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

// Config is the exit node's configuration file.
type Config struct {
	Services []ServiceConfig `json:"services"`
}

// ServiceConfig describes one service the exit node offers.
type ServiceConfig struct {
	Name string `json:"name"` // unique within the cluster
	Kind string `json:"kind"` // only "postgres" so far
	// DSN is the administrative connection string, using in-cluster DNS.
	// $VAR references are expanded from the environment, so credentials can
	// come from a Secret via secretKeyRef rather than sit in the file.
	DSN string `json:"dsn"`
	// Labels are what grants match and what users select services by. The
	// labels "cluster", "kind" and "name" are attached automatically.
	Labels map[string]string `json:"labels"`
	// Roles are the database roles the coordinator may grant to provisioned
	// accounts. Anything else is refused, which bounds what a compromised
	// coordinator can give itself.
	Roles []string `json:"roles"`
}

// A backend manages one service of some kind from inside its cluster.
type backend interface {
	// Addr is the service's address, for logs.
	Addr() string
	// Ping checks that the service is reachable with the administrative
	// credentials.
	Ping(ctx context.Context) error
	// Database is the single database sessions are confined to, if the kind
	// has such a notion.
	Database() string
	// Connect opens a connection ready for the coordinator's proxy of this
	// kind to speak over, with any transport security already negotiated.
	Connect(ctx context.Context) (net.Conn, error)
	// CreateRole provisions an account; DropRole removes one and whatever
	// connections it has; Reap removes accounts past their expiry that were
	// never dropped.
	CreateRole(ctx context.Context, r api.Role) error
	DropRole(ctx context.Context, name string) error
	Reap(ctx context.Context) (dropped []string, err error)
}

// backends maps the kind a service declares to what can manage it. The kind
// is advertised to the coordinator, which picks its protocol proxy by it.
var backends = map[string]func(dsn string) (backend, error){
	"postgres": func(dsn string) (backend, error) {
		s, err := postgres.NewServer(dsn)
		return postgresBackend{s}, err
	},
}

type postgresBackend struct{ *postgres.Server }

func (b postgresBackend) CreateRole(ctx context.Context, r api.Role) error {
	return b.Server.CreateRole(ctx, postgres.Role(r))
}

type service struct {
	advert  api.Service
	roles   []string
	backend backend
}

// A TokenFunc returns the bearer token that proves to the coordinator which
// cluster the exit node speaks for. It is called for every request, so it
// should cache.
type TokenFunc func(ctx context.Context) (string, error)

// Agent is an exit node.
type Agent struct {
	Server  string // coordinator base URL
	Cluster string
	Token   TokenFunc // nil sends no credentials, which only a coordinator in insecure_exit_auth mode accepts
	Log     *slog.Logger

	services  atomic.Pointer[map[string]*service]
	connected atomic.Bool // a control stream is up
	control   atomic.Pointer[net.Conn]
}

// Healthy reports whether the agent is connected to the coordinator, for
// readiness probes.
func (a *Agent) Healthy() bool { return a.connected.Load() }

// LoadConfig reads the services the agent offers from the file at path.
//
// ponytail: read once at startup. Roll the Deployment when the file changes
// (a checksum annotation does it), or add a watcher here.
func (a *Agent) LoadConfig(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var cfg Config
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(cfg.Services) == 0 {
		return fmt.Errorf("%s: no services defined", path)
	}

	services := make(map[string]*service)
	for i, sc := range cfg.Services {
		svc, err := newService(sc)
		if err == nil && services[sc.Name] != nil {
			err = errors.New("duplicate name")
		}
		if err != nil {
			return fmt.Errorf("%s: services[%d] (%q): %w", path, i, sc.Name, err)
		}
		services[sc.Name] = svc
		// Never the DSN: it holds the administrative password.
		a.Log.Info("service loaded", "service", sc.Name, "kind", sc.Kind, "addr", svc.backend.Addr(),
			"database", svc.advert.Database, "labels", sc.Labels, "grantable_roles", sc.Roles)
	}
	a.services.Store(&services)
	return nil
}

// CheckServices tries the administrative credentials of every service and
// logs the outcome, so that a bad password or address shows up at startup
// rather than at the first user's session. It does not fail: the database
// may simply not be up yet.
func (a *Agent) CheckServices(ctx context.Context) {
	for name, svc := range *a.services.Load() {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := svc.backend.Ping(ctx)
		cancel()
		if err != nil {
			a.Log.Warn("service is not reachable with its administrative credentials; sessions on it will fail until it is",
				"service", name, "addr", svc.backend.Addr(), "err", err)
			continue
		}
		a.Log.Info("service reachable", "service", name, "addr", svc.backend.Addr())
	}
}

// WatchConfig reloads the configuration file whenever it changes, until ctx
// is done. On a change the control stream is dropped so that reconnecting
// advertises the new services; connections in flight are unaffected. A file
// that fails to load is logged and ignored.
//
// ponytail: polls the modification time. Kubernetes updates a mounted
// ConfigMap within about a minute anyway.
func (a *Agent) WatchConfig(ctx context.Context, path string) {
	mtime := func() time.Time {
		fi, err := os.Stat(path)
		if err != nil {
			return time.Time{}
		}
		return fi.ModTime()
	}
	last := mtime()
	for {
		select {
		case <-time.After(15 * time.Second):
		case <-ctx.Done():
			return
		}
		if now := mtime(); !now.IsZero() && !now.Equal(last) {
			last = now
			a.Log.Info("configuration file changed; reloading", "file", path)
			if err := a.LoadConfig(path); err != nil {
				a.Log.Error("configuration reload failed; keeping the previous services", "err", err)
				continue
			}
			a.CheckServices(ctx)
			if conn := a.control.Load(); conn != nil {
				(*conn).Close() // Run reconnects and advertises the new set
			}
		}
	}
}

func newService(sc ServiceConfig) (*service, error) {
	if sc.Name == "" {
		return nil, errors.New("name is required")
	}
	for _, reserved := range []string{"cluster", "kind", "name"} {
		if _, ok := sc.Labels[reserved]; ok {
			return nil, fmt.Errorf("label %q is attached automatically and cannot be set", reserved)
		}
	}
	open := backends[sc.Kind]
	if open == nil {
		return nil, fmt.Errorf("unsupported kind %q", sc.Kind)
	}
	b, err := open(os.ExpandEnv(sc.DSN))
	if err != nil {
		return nil, err
	}
	return &service{
		advert:  api.Service{Name: sc.Name, Kind: sc.Kind, Database: b.Database(), Labels: sc.Labels},
		roles:   sc.Roles,
		backend: b,
	}, nil
}

// Run keeps a control stream open to the coordinator, reconnecting with
// backoff, until ctx is done.
func (a *Agent) Run(ctx context.Context) error {
	go a.reapLoop(ctx)
	backoff := time.Second
	for {
		start := time.Now()
		err := a.serve(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second // it was a healthy connection
		}
		a.Log.Warn("control stream lost; reconnecting", "err", err, "in", backoff.String())
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

// reap drops the service's accounts that are past their expiry.
func (s *service) reap(ctx context.Context, log *slog.Logger) {
	dropped, err := s.backend.Reap(ctx)
	if len(dropped) > 0 {
		log.Info("dropped expired accounts that were never revoked", "service", s.advert.Name, "accounts", dropped)
	}
	if err != nil {
		log.Warn("could not drop all expired accounts", "service", s.advert.Name, "err", err)
	}
}

// reapInterval is how often accounts past their expiry are swept up.
const reapInterval = time.Hour

// reapLoop drops expired accounts at startup and periodically after. It is
// the cleanup of last resort, needing nothing from the coordinator: whatever
// crashed or lost its state, no account outlives its expiry by much.
func (a *Agent) reapLoop(ctx context.Context) {
	for {
		for _, svc := range *a.services.Load() {
			svc.reap(ctx, a.Log)
		}
		select {
		case <-time.After(reapInterval):
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) url(path, id string) string {
	q := url.Values{"cluster": {a.Cluster}}
	if id != "" {
		q.Set("id", id)
	}
	return a.Server + path + "?" + q.Encode()
}

// header returns the credentials to send with a request to the coordinator.
func (a *Agent) header(ctx context.Context) (http.Header, error) {
	if a.Token == nil {
		return nil, nil
	}
	token, err := a.Token(ctx)
	if err != nil {
		return nil, err
	}
	return http.Header{"Authorization": {"Bearer " + token}}, nil
}

// dial opens an upgraded stream to the coordinator.
func (a *Agent) dial(ctx context.Context, path, id string) (net.Conn, error) {
	header, err := a.header(ctx)
	if err != nil {
		return nil, err
	}
	return tunnel.Dial(ctx, a.url(path, id), header)
}

// serve runs one control stream until it fails.
func (a *Agent) serve(ctx context.Context) error {
	conn, err := a.dial(ctx, "/v1/exit/control", "")
	if err != nil {
		return err
	}
	defer conn.Close()
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	a.control.Store(&conn)

	services := *a.services.Load()
	var hello api.Hello
	for _, svc := range services {
		hello.Services = append(hello.Services, svc.advert)
	}
	if err := json.NewEncoder(conn).Encode(hello); err != nil {
		return err
	}
	a.connected.Store(true)
	defer a.connected.Store(false)
	a.Log.Info("connected to coordinator; advertised services and awaiting requests",
		"server", a.Server, "cluster", a.Cluster, "services", slices.Sorted(maps.Keys(services)))

	dec := json.NewDecoder(conn)
	for {
		// The coordinator pings far more often than this; silence means the
		// path is dead even if TCP has not noticed.
		conn.SetReadDeadline(time.Now().Add(3 * time.Minute))
		var req api.ExitRequest
		if err := dec.Decode(&req); err != nil {
			return err
		}
		if req.ID != "" {
			go a.handle(ctx, req)
		}
	}
}

// handle performs one request and reports its outcome to the coordinator.
func (a *Agent) handle(ctx context.Context, req api.ExitRequest) {
	log := a.Log.With("op", req.Op, "service", req.Service, "request", req.ID)
	start := time.Now()
	err := a.do(ctx, req, log)
	log.Debug("request handled", "took", time.Since(start).Round(time.Millisecond).String(), "err", err)
	if err == nil && req.Op == api.OpDial {
		return // the data stream was the answer
	}
	res := api.ExitResult{}
	if err != nil {
		log.Warn("request failed", "err", err)
		res.Error = err.Error()
	}
	// Best effort: the coordinator's call times out on its own otherwise.
	body, _ := json.Marshal(res)
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url("/v1/exit/result", req.ID), bytes.NewReader(body))
	if err != nil {
		return
	}
	if post.Header, err = a.header(ctx); err != nil {
		log.Warn("could not report result: no token", "err", err)
		return
	}
	resp, err := http.DefaultClient.Do(post)
	if err != nil {
		log.Warn("could not report result", "err", err)
		return
	}
	resp.Body.Close()
}

func (a *Agent) do(ctx context.Context, req api.ExitRequest, log *slog.Logger) error {
	svc := (*a.services.Load())[req.Service]
	if svc == nil {
		return fmt.Errorf("no such service %q", req.Service)
	}
	if req.Op != api.OpDial && req.Role == nil {
		return errors.New("request has no role")
	}

	switch req.Op {
	case api.OpDial:
		target, err := svc.backend.Connect(ctx)
		if err != nil {
			return fmt.Errorf("connecting to %s: %w", svc.backend.Addr(), err)
		}
		stream, err := a.dial(ctx, "/v1/exit/data", req.ID)
		if err != nil {
			target.Close()
			log.Warn("opening data stream", "err", err)
			return nil // the coordinator is unreachable; there is no one to tell
		}
		go func() {
			log.Info("connection opened", "addr", svc.backend.Addr())
			start := time.Now()
			tunnel.Splice(stream, target)
			log.Info("connection closed", "addr", svc.backend.Addr(), "duration", time.Since(start).Round(time.Millisecond).String())
		}()
		return nil

	case api.OpCreateRole:
		for _, r := range req.Role.MemberOf {
			if !slices.Contains(svc.roles, r) {
				return fmt.Errorf("role %q is not grantable on service %q", r, req.Service)
			}
		}
		// Sweep up after sessions that were never revoked, for example
		// because this node was down when they ended.
		svc.reap(ctx, a.Log)
		log.Info("provisioning account", "account", req.Role.Name, "member_of", req.Role.MemberOf, "valid_until", req.Role.ValidUntil)
		return svc.backend.CreateRole(ctx, *req.Role)

	case api.OpDropRole:
		log.Info("dropping account and disconnecting it", "account", req.Role.Name)
		return svc.backend.DropRole(ctx, req.Role.Name)
	}
	return fmt.Errorf("unknown operation %q", req.Op)
}
