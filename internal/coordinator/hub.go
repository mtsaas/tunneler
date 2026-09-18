package coordinator

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

const (
	helloTimeout = 10 * time.Second
	callTimeout  = 30 * time.Second
)

// hub tracks connected exit nodes and the services they advertise, and
// carries the coordinator's requests to them.
//
// Exit nodes cannot be dialed; they sit behind cluster ingress. Each holds a
// tunnel.Session open to the coordinator. On the first stream the node
// opens, it advertises its services: once at the start, and again whenever
// they change. For each request, the coordinator opens a stream to the node
// and writes an api.ExitRequest; the node answers with an api.ExitResult,
// and the stream of a successful dial goes on to carry the connection.
//
// Every hello and every answer carries the node's credentials afresh. A
// node they no longer admit is disconnected, and must be admitted anew to
// return.
type hub struct {
	log *slog.Logger
	// admit checks that token, from something an exit node sent, proves the
	// node to be of cluster under the coordinator's current rules.
	admit   func(ctx context.Context, cluster, token string) error
	onOffer func(cluster string) // called, on its own goroutine, whenever an exit node begins to offer a service

	mu      sync.Mutex
	exits   map[string]map[*exitConn]struct{} // by cluster
	pending map[string]pendingCall            // of legacy exit nodes, by request ID
}

// exitConn is one connected exit node.
type exitConn struct {
	remote   string
	session  *tunnel.Session
	legacy   *legacyControl         // instead of session, for an exit node of v0.3.1 or earlier
	services map[string]api.Service // guarded by hub.mu; replaced whole when the node re-advertises
}

func newHub(log *slog.Logger) *hub {
	return &hub{
		log:     log,
		exits:   make(map[string]map[*exitConn]struct{}),
		pending: make(map[string]pendingCall),
	}
}

// nodes returns how many exit nodes of the cluster are connected.
func (h *hub) nodes(cluster string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.exits[cluster])
}

// clusters returns the names of clusters with a connected exit node, sorted.
func (h *hub) clusters() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var names []string
	for name, exits := range h.exits {
		if len(exits) > 0 {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// services returns the services advertised by the cluster's connected exit
// nodes, sorted by name.
func (h *hub) services(cluster string) []api.Service {
	h.mu.Lock()
	byName := make(map[string]api.Service)
	for e := range h.exits[cluster] {
		maps.Copy(byName, e.services)
	}
	h.mu.Unlock()
	return slices.SortedFunc(maps.Values(byName), func(a, b api.Service) int { return cmp.Compare(a.Name, b.Name) })
}

// service returns one of the cluster's advertised services.
func (h *hub) service(cluster, name string) (api.Service, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for e := range h.exits[cluster] {
		if svc, ok := e.services[name]; ok {
			return svc, true
		}
	}
	return api.Service{}, false
}

// serve registers an exit node of the cluster, connected from remote, and
// serves its session until the session ends.
func (h *hub) serve(cluster, remote string, sess *tunnel.Session) error {
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), helloTimeout)
	defer cancel()
	adverts, err := sess.Accept(ctx)
	if err != nil {
		return fmt.Errorf("awaiting hello: %w", err)
	}
	go func() {
		// A stream the node opens after this one breaks the protocol, and the
		// coordinator would buffer what it carries without ever reading it.
		if _, err := sess.Accept(context.Background()); err == nil {
			h.log.Warn("exit node opened an unexpected stream; disconnecting it", "cluster", cluster, "remote", remote)
			sess.Close()
		}
	}()

	e := &exitConn{remote: remote, session: sess}
	defer h.remove(cluster, e)
	adverts.SetReadDeadline(time.Now().Add(helloTimeout))
	for {
		var hello api.Hello
		if err := tunnel.ReadMessage(adverts, &hello); err != nil {
			return err
		}
		// Later advertisements come when they come; the session's
		// keepalives notice a dead path.
		adverts.SetReadDeadline(time.Time{})
		if err := h.vouch(cluster, e, hello.Token); err != nil {
			return err
		}
		h.advertise(cluster, e, hello)
	}
}

// vouch checks that token, which e sent, still admits e as an exit node of
// the cluster, and disconnects e if it does not.
func (h *hub) vouch(cluster string, e *exitConn, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	if err := h.admit(ctx, cluster, token); err != nil {
		h.log.Warn("exit node's credentials no longer admit it; disconnecting it", "cluster", cluster, "remote", e.remote, "err", err)
		e.session.Close()
		return fmt.Errorf("exit node for cluster %q is not admitted: %w", cluster, err)
	}
	return nil
}

// advertise makes e routable as an exit node of the cluster, offering the
// services in hello in place of any it offered before. Connections in
// flight are unaffected.
func (h *hub) advertise(cluster string, e *exitConn, hello api.Hello) {
	services := make(map[string]api.Service, len(hello.Services))
	for _, svc := range hello.Services {
		// An exit node describes its services however it likes, but which
		// cluster it speaks for was settled by its token.
		svc.Labels = maps.Clone(svc.Labels)
		if svc.Labels == nil {
			svc.Labels = make(map[string]string)
		}
		svc.Labels["cluster"] = cluster
		svc.Labels["kind"] = svc.Kind
		svc.Labels["name"] = svc.Name
		svc.Access = kinds[svc.Kind].access() // ours to say: it is how this coordinator fronts the kind
		services[svc.Name] = svc
	}

	h.mu.Lock()
	if h.exits[cluster] == nil {
		h.exits[cluster] = make(map[*exitConn]struct{})
	}
	_, known := h.exits[cluster][e]
	offersMore := false
	for name := range services {
		if _, ok := e.services[name]; !ok {
			offersMore = true
		}
	}
	h.exits[cluster][e] = struct{}{}
	e.services = services
	nodes := len(h.exits[cluster])
	h.mu.Unlock()

	log := h.log.With("cluster", cluster, "remote", e.remote, "services", slices.Sorted(maps.Keys(services)))
	if known {
		log.Info("exit node re-advertised its services")
	} else {
		log.Info("exit node connected; its services are now routable", "nodes_in_cluster", nodes)
	}
	if offersMore && h.onOffer != nil {
		go h.onOffer(cluster)
	}
}

// remove makes e unroutable once it has disconnected.
func (h *hub) remove(cluster string, e *exitConn) {
	h.mu.Lock()
	_, known := h.exits[cluster][e]
	delete(h.exits[cluster], e)
	nodes := len(h.exits[cluster])
	h.mu.Unlock()
	if known {
		h.log.Warn("exit node disconnected", "cluster", cluster, "remote", e.remote, "nodes_in_cluster", nodes)
	}
}

// call has an exit node of the cluster that advertises req.Service perform
// req, and waits for the outcome. For a dial, the returned connection
// reaches the service.
func (h *hub) call(ctx context.Context, cluster string, req api.ExitRequest) (net.Conn, error) {
	h.mu.Lock()
	var exit *exitConn
	for e := range h.exits[cluster] {
		if _, ok := e.services[req.Service]; ok {
			exit = e
			break
		}
	}
	h.mu.Unlock()
	if exit == nil {
		return nil, fmt.Errorf("no connected exit node in cluster %q offers service %q", cluster, req.Service)
	}

	ask := h.ask
	if exit.legacy != nil {
		ask = h.askLegacy
	}
	log := h.log.With("cluster", cluster, "service", req.Service, "op", req.Op, "exit", exit.remote)
	log.Debug("asking exit node")
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	conn, err := ask(ctx, cluster, exit, req)
	if err != nil && ctx.Err() != nil {
		log.Warn("exit node did not answer", "waited", time.Since(start).Round(time.Millisecond).String())
		return nil, fmt.Errorf("exit node for cluster %q: %s: %w", cluster, req.Op, ctx.Err())
	}
	log.Debug("exit node answered", "took", time.Since(start).Round(time.Millisecond).String(), "err", err)
	return conn, err
}

// ask performs req on a stream of e's session, which for a successful dial
// is returned to carry the connection.
func (h *hub) ask(ctx context.Context, cluster string, e *exitConn, req api.ExitRequest) (net.Conn, error) {
	stream, err := e.session.Open()
	if err != nil {
		return nil, fmt.Errorf("exit node for cluster %q: %w", cluster, err)
	}
	stop := context.AfterFunc(ctx, func() { stream.SetDeadline(time.Now()) })
	var res api.ExitResult
	err = tunnel.WriteMessage(stream, req)
	if err == nil {
		err = tunnel.ReadMessage(stream, &res)
	}
	switch {
	case !stop():
		err = ctx.Err() // the stream's deadline has passed, whatever the exchange came to
	case errors.Is(err, io.EOF):
		err = fmt.Errorf("exit node for cluster %q closed the request unanswered; its log says why", cluster)
	case err != nil:
		err = fmt.Errorf("exit node for cluster %q: %w", cluster, err)
	default:
		// Even a failure needs proof: its message reaches users.
		if err = h.vouch(cluster, e, res.Token); err == nil && res.Error != "" {
			err = errors.New(res.Error)
		}
	}
	if err != nil || req.Op != api.OpDial {
		stream.Close()
		return nil, err
	}
	return stream, nil
}
