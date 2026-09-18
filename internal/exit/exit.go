// Package exit implements the exit node: an agent inside a cluster that dials
// out to the coordinator, advertises the cluster's services, and on request
// provisions accounts on them and connects the coordinator to them.
//
// Administrative credentials live only here, inside the cluster.
package exit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
	"github.com/mtsaas/tunneler/internal/kube"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

// Config is the exit node's configuration file.
type Config struct {
	Services []ServiceConfig `json:"services"`
}

// ServiceConfig describes one service the exit node offers.
type ServiceConfig struct {
	Name string `json:"name"` // unique within the cluster
	Kind string `json:"kind"` // "postgres" or "kubernetes"; see kinds
	// DSN is the administrative connection string of a postgres service,
	// using in-cluster DNS. $VAR references are expanded from the
	// environment, so credentials can come from a Secret via secretKeyRef
	// rather than sit in the file.
	DSN string `json:"dsn,omitempty"`
	// Kubernetes says how to reach the API server of a kubernetes service.
	// The zero value, the cluster the exit node runs in, is nearly always
	// right.
	Kubernetes kube.Config `json:"kubernetes,omitzero"`
	// Labels are what grants match and what users select services by. The
	// labels "cluster", "kind" and "name" are attached automatically.
	Labels map[string]string `json:"labels"`
	// Roles are what the coordinator may grant a user here: database roles
	// for postgres, groups to impersonate for kubernetes. Anything else is
	// refused, which bounds what a compromised coordinator can give itself.
	Roles []string `json:"roles"`
}

type service struct {
	advert  api.Service
	roles   []string
	backend backend
	// report, if set, is told whenever the service's readiness is decided,
	// for example to write status on the TunnelService it came from.
	report func(ctx context.Context, ready bool, reason, message string)
}

// Agent is an exit node.
type Agent struct {
	Server  string // coordinator base URL
	Cluster string
	// Token proves to the coordinator which cluster this is. Nil presents
	// nothing, which only a coordinator in insecure_exit_auth mode accepts.
	Token coordinator.TokenFunc
	Log   *slog.Logger

	mu      sync.Mutex
	sources map[string]map[string]*service // desired services, by the source that defined them
	health  map[*service]string            // last check of each desired service: "" if reachable, else why not
	kick    chan struct{}                  // wakes reconcile early

	advertised atomic.Pointer[map[string]*service] // desired services, by name
	adverts    atomic.Pointer[[]api.Service]       // what the coordinator is told, sorted by name
	changed    chan struct{}                       // wakes the session's advertiser when adverts change
	connected  atomic.Bool                         // a session is up
}

// Healthy reports whether the agent is connected to the coordinator, for
// readiness probes.
func (a *Agent) Healthy() bool { return a.connected.Load() }

// SetServices replaces the services defined by one source, such as "file" or
// "kubernetes". Sources are merged; a name defined twice is an error logged
// and the later definition ignored. Nothing is advertised until reconcile
// has reached it.
func (a *Agent) SetServices(source string, services map[string]*service) {
	a.mu.Lock()
	if a.sources == nil {
		a.sources = make(map[string]map[string]*service)
		a.health = make(map[*service]string)
		a.kick = make(chan struct{}, 1)
		a.changed = make(chan struct{}, 1)
	}
	a.sources[source] = services
	a.mu.Unlock()
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// desired merges every source's services.
func (a *Agent) desired() map[string]*service {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]*service)
	for src, services := range a.sources {
		for name, svc := range services {
			if _, dup := out[name]; dup {
				a.Log.Error("service defined by more than one source; ignoring one", "service", name, "source", src)
				continue
			}
			out[name] = svc
		}
	}
	return out
}

// reconcileInterval is how often every service's reachability is checked.
const reconcileInterval = 30 * time.Second

// reconcileLoop keeps the advertised set equal to the desired services that
// are reachable, until ctx is done.
func (a *Agent) reconcileLoop(ctx context.Context) {
	for {
		a.reconcile(ctx)
		select {
		case <-a.kick:
		case <-time.After(reconcileInterval):
		case <-ctx.Done():
			return
		}
	}
}

// reconcile checks that every desired service is reachable with its
// credentials, then advertises them all, each marked ready or not and why.
// The coordinator refuses sessions on a service that is not ready, so a
// broken credential shows up as a clear message rather than a failed login.
// If what would be advertised changed, the coordinator is told again.
func (a *Agent) reconcile(ctx context.Context) {
	desired := a.desired()

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[*service]string, len(desired))
	for _, svc := range desired {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			var status string
			if err := svc.backend.Ping(ctx); err != nil {
				status = err.Error()
			}
			mu.Lock()
			results[svc] = status
			mu.Unlock()
		})
	}
	wg.Wait()

	a.mu.Lock()
	changed := make([]*service, 0)
	for svc, status := range results {
		if prev, seen := a.health[svc]; !seen || prev != status {
			changed = append(changed, svc)
		}
		a.health[svc] = status
	}
	for svc := range a.health { // forget services no longer desired
		if s, ok := desired[svc.advert.Name]; !ok || s != svc {
			delete(a.health, svc)
		}
	}
	a.mu.Unlock()

	for _, svc := range changed {
		log := a.Log.With("service", svc.advert.Name, "addr", svc.backend.Addr())
		if status := results[svc]; status != "" {
			log.Warn("service is not reachable with its credentials; advertised as not ready", "err", status)
			if svc.report != nil {
				svc.report(ctx, false, "Unreachable", status)
			}
			continue
		}
		log.Info("service reachable; advertised as ready")
		if svc.report != nil {
			svc.report(ctx, true, "Connected", "reachable with its credentials; advertised to the coordinator")
		}
	}

	adverts := make([]api.Service, 0, len(desired))
	for _, name := range slices.Sorted(maps.Keys(desired)) {
		svc := desired[name]
		advert := svc.advert
		advert.Status = results[svc]
		advert.Ready = advert.Status == ""
		adverts = append(adverts, advert)
	}
	a.advertised.Store(&desired)
	if prev := a.adverts.Swap(&adverts); prev != nil && !reflect.DeepEqual(*prev, adverts) {
		a.Log.Info("advertised services changed; republishing to the coordinator", "services", slices.Sorted(maps.Keys(desired)))
		select {
		case a.changed <- struct{}{}:
		default:
		}
	}
}

// LoadConfig defines the services in the file at path as the "file" source.
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
		sc.DSN = os.ExpandEnv(sc.DSN)
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
	a.SetServices("file", services)
	return nil
}

// WatchConfig reloads the configuration file whenever it changes, until ctx
// is done. A file that fails to load is logged and ignored.
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
	open := kinds[sc.Kind]
	if open == nil {
		return nil, fmt.Errorf("unsupported kind %q", sc.Kind)
	}
	b, err := open(sc)
	if err != nil {
		return nil, err
	}
	svc := &service{
		advert:  api.Service{Name: sc.Name, Kind: sc.Kind, Labels: sc.Labels},
		roles:   sc.Roles,
		backend: b,
	}
	if d, ok := b.(describer); ok {
		d.describe(&svc.advert)
	}
	return svc, nil
}

// Run keeps a session open with the coordinator, reconnecting with backoff,
// until ctx is done.
func (a *Agent) Run(ctx context.Context) error {
	if a.sources == nil {
		a.SetServices("none", nil) // initialize even with no source
	}
	a.reconcile(ctx) // so that the first hello already carries reachable services
	go a.reconcileLoop(ctx)
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
		a.Log.Warn("session with the coordinator lost; reconnecting", "err", err, "in", backoff.String())
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
	accts, ok := s.backend.(accounts)
	if !ok {
		return // a kind without accounts leaves nothing behind
	}
	dropped, err := accts.Reap(ctx)
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
		for _, svc := range *a.advertised.Load() {
			svc.reap(ctx, a.Log)
		}
		select {
		case <-time.After(reapInterval):
		case <-ctx.Done():
			return
		}
	}
}

// coordinator returns the agent's client of the coordinator's API.
func (a *Agent) coordinator() *coordinator.ExitClient {
	return &coordinator.ExitClient{Server: a.Server, Cluster: a.Cluster, Token: a.Token}
}

// serve runs one session with the coordinator until it fails.
func (a *Agent) serve(ctx context.Context) error {
	sess, err := a.coordinator().Connect(ctx, a.Log)
	if err != nil {
		return err
	}
	// The advertiser must be gone before the next session begins, lest it
	// swallow a change that the next session's hello would miss.
	var wg sync.WaitGroup
	defer wg.Wait()
	defer sess.Close()

	adverts, err := sess.Open()
	if err != nil {
		return err
	}
	select {
	case <-a.changed: // the hello carries every change so far
	default:
	}
	hello, err := a.hello(ctx)
	if err != nil {
		return err
	}
	if err := tunnel.WriteMessage(adverts, hello); err != nil {
		return err
	}
	a.connected.Store(true)
	defer a.connected.Store(false)
	var ready, notReady []string
	for _, svc := range hello.Services {
		if svc.Ready {
			ready = append(ready, svc.Name)
		} else {
			notReady = append(notReady, svc.Name)
		}
	}
	a.Log.Info("connected to coordinator; advertised services and awaiting requests",
		"server", a.Server, "cluster", a.Cluster, "ready", ready, "not_ready", notReady)
	wg.Go(func() { a.readvertise(ctx, sess, adverts) })

	for {
		stream, err := sess.Accept(ctx)
		if err != nil {
			return err
		}
		go a.handle(ctx, stream)
	}
}

// readvertise tells the coordinator the services again, on the stream that
// carried the hello, each time they change, until the session ends.
func (a *Agent) readvertise(ctx context.Context, sess *tunnel.Session, adverts net.Conn) {
	for {
		select {
		case <-a.changed:
		case <-sess.Done():
			return
		}
		hello, err := a.hello(ctx)
		if err == nil {
			err = tunnel.WriteMessage(adverts, hello)
		}
		if err != nil {
			a.Log.Warn("could not republish services; reconnecting", "err", err)
			sess.Close()
			return
		}
	}
}

// hello returns the services to advertise, with the proof of this node's
// cluster that the coordinator requires of all it is told.
func (a *Agent) hello(ctx context.Context) (api.Hello, error) {
	token, err := a.token(ctx)
	return api.Hello{Services: *a.adverts.Load(), Token: token}, err
}

// requestTimeout bounds the wait for a request on a stream the coordinator
// has opened, which it writes at once.
const requestTimeout = 10 * time.Second

// handle performs the request that the coordinator opened stream for, and
// answers on it. A dial goes on to carry the connection over the stream.
func (a *Agent) handle(ctx context.Context, stream net.Conn) {
	defer stream.Close()
	var req api.ExitRequest
	stream.SetReadDeadline(time.Now().Add(requestTimeout))
	if err := tunnel.ReadMessage(stream, &req); err != nil {
		a.Log.Warn("could not read the coordinator's request", "err", err)
		return
	}
	stream.SetReadDeadline(time.Time{})

	log := a.Log.With("op", req.Op, "service", req.Service)
	start := time.Now()
	svc := (*a.advertised.Load())[req.Service]
	target, err := a.do(ctx, svc, req, log)
	log.Debug("request handled", "took", time.Since(start).Round(time.Millisecond).String(), "err", err)
	res := api.ExitResult{}
	if err != nil {
		log.Warn("request failed", "err", err)
		res.Error = err.Error()
	}
	// The coordinator disconnects a node whose answer does not prove its
	// cluster, so a node that cannot prove it leaves the request unanswered.
	// The token is fetched now, after the work, so that it is fresh.
	if res.Token, err = a.token(ctx); err != nil {
		log.Warn("could not obtain the credentials to answer the coordinator", "err", err)
	} else if err = tunnel.WriteMessage(stream, res); err != nil {
		log.Warn("could not answer the coordinator; it gave up waiting, or the session ended", "err", err)
	}
	if err != nil {
		if target != nil {
			target.Close()
		}
		return
	}
	if target != nil {
		log.Info("connection opened", "addr", svc.backend.Addr())
		tunnel.Splice(stream, target)
		log.Info("connection closed", "addr", svc.backend.Addr(), "duration", time.Since(start).Round(time.Millisecond).String())
	}
}

// token returns what proves this node's cluster to the coordinator, if
// there is anything to present.
func (a *Agent) token(ctx context.Context) (string, error) {
	if a.Token == nil {
		return "", nil
	}
	return a.Token(ctx)
}

// do performs req on svc, which is nil if the node does not offer the
// service. For a dial, it returns the connection to the service.
func (a *Agent) do(ctx context.Context, svc *service, req api.ExitRequest, log *slog.Logger) (net.Conn, error) {
	if svc == nil {
		return nil, fmt.Errorf("no such service %q", req.Service)
	}
	accts, _ := svc.backend.(accounts)
	if req.Op != api.OpDial {
		switch {
		case accts == nil:
			return nil, fmt.Errorf("services of kind %q have no accounts to manage", svc.advert.Kind)
		case req.Role == nil:
			return nil, errors.New("request has no role")
		}
	}

	switch req.Op {
	case api.OpDial:
		target, err := svc.backend.Connect(ctx)
		if err != nil {
			return nil, fmt.Errorf("connecting to %s: %w", svc.backend.Addr(), err)
		}
		return target, nil

	case api.OpCreateRole:
		for _, r := range req.Role.MemberOf {
			if !slices.Contains(svc.roles, r) {
				return nil, fmt.Errorf("role %q is not grantable on service %q", r, req.Service)
			}
		}
		// Sweep up after sessions that were never revoked, for example
		// because this node was down when they ended.
		svc.reap(ctx, a.Log)
		log.Info("provisioning account", "account", req.Role.Name, "member_of", req.Role.MemberOf, "valid_until", req.Role.ValidUntil)
		return nil, accts.CreateRole(ctx, *req.Role)

	case api.OpDropRole:
		log.Info("dropping account and disconnecting it", "account", req.Role.Name)
		return nil, accts.DropRole(ctx, req.Role.Name)
	}
	return nil, fmt.Errorf("unknown operation %q", req.Op)
}
