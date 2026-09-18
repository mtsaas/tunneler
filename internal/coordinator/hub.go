package coordinator

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
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
)

const (
	pingInterval = 30 * time.Second
	helloTimeout = 10 * time.Second
	callTimeout  = 30 * time.Second
)

// hub tracks connected exit nodes, the services they advertise, and the
// requests outstanding against them.
//
// Exit nodes cannot be dialed; they sit behind cluster ingress. Each holds a
// control stream open to the coordinator, over which it receives requests.
// It answers a dial by connecting back with a fresh data stream, and anything
// else with a plain HTTP request carrying the result.
//
// ponytail: one TCP connection per proxied connection rather than a
// multiplexer. Swap in yamux if connection setup latency ever matters.
type hub struct {
	log       *slog.Logger
	onConnect func(cluster string) // called, on its own goroutine, once an exit node is routable

	mu      sync.Mutex
	exits   map[string]map[*exitConn]struct{} // by cluster
	pending map[string]pendingCall            // by request ID
}

type exitConn struct {
	services map[string]api.Service // immutable

	mu   sync.Mutex // serializes writes
	conn net.Conn
}

func (e *exitConn) send(req api.ExitRequest) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn.SetWriteDeadline(time.Now().Add(helloTimeout))
	return json.NewEncoder(e.conn).Encode(req)
}

type pendingCall struct {
	cluster string
	result  chan callResult // buffered; written at most once
}

type callResult struct {
	conn net.Conn
	err  error
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

// serveControl registers conn as the control stream of one of the cluster's
// exit nodes and blocks until the stream fails.
func (h *hub) serveControl(cluster string, conn net.Conn) error {
	defer conn.Close()

	var hello api.Hello
	conn.SetReadDeadline(time.Now().Add(helloTimeout))
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&hello); err != nil {
		return fmt.Errorf("reading hello: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	e := &exitConn{conn: conn, services: make(map[string]api.Service)}
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
		e.services[svc.Name] = svc
	}

	h.mu.Lock()
	if h.exits[cluster] == nil {
		h.exits[cluster] = make(map[*exitConn]struct{})
	}
	h.exits[cluster][e] = struct{}{}
	nodes := len(h.exits[cluster])
	h.mu.Unlock()

	log := h.log.With("cluster", cluster, "remote", conn.RemoteAddr().String())
	log.Info("exit node connected; its services are now routable",
		"services", slices.Sorted(maps.Keys(e.services)), "nodes_in_cluster", nodes)
	if h.onConnect != nil {
		go h.onConnect(cluster)
	}
	defer func() {
		h.mu.Lock()
		delete(h.exits[cluster], e)
		nodes := len(h.exits[cluster])
		h.mu.Unlock()
		log.Warn("exit node disconnected", "nodes_in_cluster", nodes)
	}()

	// The exit node writes nothing further; reading notices a closed stream.
	closed := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, io.MultiReader(dec.Buffered(), conn))
		closed <- err
	}()
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-closed:
			return err
		case <-ticker.C:
			if err := e.send(api.ExitRequest{}); err != nil {
				return err
			}
		}
	}
}

// call sends req to an exit node that advertises req.Service and waits for
// the outcome. For a dial, the returned connection reaches the service.
func (h *hub) call(ctx context.Context, cluster string, req api.ExitRequest) (net.Conn, error) {
	req.ID = rand.Text()
	p := pendingCall{cluster: cluster, result: make(chan callResult, 1)}

	h.mu.Lock()
	var exit *exitConn
	for e := range h.exits[cluster] {
		if _, ok := e.services[req.Service]; ok {
			exit = e
			h.pending[req.ID] = p
			break
		}
	}
	h.mu.Unlock()
	if exit == nil {
		return nil, fmt.Errorf("no connected exit node in cluster %q offers service %q", cluster, req.Service)
	}

	defer func() {
		h.mu.Lock()
		delete(h.pending, req.ID)
		h.mu.Unlock()
		// deliver sends under h.mu, so a result that raced with our giving up
		// is in the channel by now.
		select {
		case r := <-p.result:
			if r.conn != nil {
				r.conn.Close()
			}
		default:
		}
	}()

	log := h.log.With("cluster", cluster, "service", req.Service, "op", req.Op, "request", req.ID)
	log.Debug("asking exit node", "exit", exit.conn.RemoteAddr().String())
	start := time.Now()
	if err := exit.send(req); err != nil {
		exit.conn.Close()
		return nil, fmt.Errorf("exit node for cluster %q: %w", cluster, err)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	select {
	case r := <-p.result:
		log.Debug("exit node answered", "took", time.Since(start).Round(time.Millisecond).String(), "err", r.err)
		// Ownership of r.conn passes to the caller; the deferred drain finds
		// the channel empty.
		return r.conn, r.err
	case <-ctx.Done():
		log.Warn("exit node did not answer", "waited", time.Since(start).Round(time.Millisecond).String())
		return nil, fmt.Errorf("exit node for cluster %q: %s: %w", cluster, req.Op, ctx.Err())
	}
}

// deliver completes the cluster's pending call with the given ID. It reports
// whether the call was still waiting; if not, the caller keeps ownership of
// conn.
func (h *hub) deliver(cluster, id string, conn net.Conn, res api.ExitResult) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.pending[id]
	if !ok || p.cluster != cluster {
		return false
	}
	delete(h.pending, id)
	if res.Error != "" {
		p.result <- callResult{err: errors.New(res.Error)}
	} else {
		p.result <- callResult{conn: conn}
	}
	return true
}
