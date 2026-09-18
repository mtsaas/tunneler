package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

// Exit nodes of v0.3.1 and earlier hold a control stream rather than a
// session. On it they write an api.Hello, as a line of JSON, and read one
// api.ExitRequest per line, with empty ones as keepalives. They answer a
// dial by connecting back at routeExitData, and anything else by posting to
// routeExitResult, each naming the request's ID. Every answer comes with the
// node's credentials, which the coordinator checks as it does at connection.
//
// ponytail: kept so that a coordinator can be upgraded ahead of its exit
// nodes. Once none remain, delete this file, its three routes, the legacy
// branch of hub.call, exitConn.legacy, hub.pending and api.ExitRequest.ID,
// and move TestExitAuth and TestKubeExitAuth, which post to
// routeExitResult, to routeExitConnect.

// pingInterval is how often a legacy exit node's control stream carries a
// keepalive.
const pingInterval = 30 * time.Second

// legacyControl is the control stream of a legacy exit node.
type legacyControl struct {
	mu   sync.Mutex // serializes writes
	conn net.Conn
}

func (l *legacyControl) send(req api.ExitRequest) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.conn.SetWriteDeadline(time.Now().Add(helloTimeout))
	return json.NewEncoder(l.conn).Encode(req)
}

type pendingCall struct {
	cluster string
	result  chan callResult // buffered; written at most once
}

type callResult struct {
	conn net.Conn
	err  error
}

// serveLegacy registers conn as the control stream of a legacy exit node of
// the cluster, connected from remote, and blocks until the stream fails.
func (h *hub) serveLegacy(cluster, remote string, conn net.Conn) error {
	defer conn.Close()

	var hello api.Hello
	conn.SetReadDeadline(time.Now().Add(helloTimeout))
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&hello); err != nil {
		return fmt.Errorf("reading hello: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	control := &legacyControl{conn: conn}
	e := &exitConn{remote: remote, legacy: control}
	h.advertise(cluster, e, hello)
	defer h.remove(cluster, e)

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
			if err := control.send(api.ExitRequest{}); err != nil {
				return err
			}
		}
	}
}

// askLegacy sends req on a legacy exit node's control stream and waits for
// deliver to hand over the answer.
func (h *hub) askLegacy(ctx context.Context, cluster string, e *exitConn, req api.ExitRequest) (net.Conn, error) {
	req.ID = rand.Text()
	p := pendingCall{cluster: cluster, result: make(chan callResult, 1)}
	h.mu.Lock()
	h.pending[req.ID] = p
	h.mu.Unlock()
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

	if err := e.legacy.send(req); err != nil {
		e.legacy.conn.Close()
		return nil, err
	}
	select {
	case r := <-p.result:
		// Ownership of r.conn passes to the caller; the deferred drain finds
		// the channel empty.
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
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

func (c *Coordinator) handleExitControl(w http.ResponseWriter, r *http.Request, cluster string) {
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		return
	}
	if err := c.hub.serveLegacy(cluster, c.remote(r), conn); err != nil {
		c.log.Info("exit node control stream ended", "cluster", cluster, "remote", c.remote(r), "err", err)
	}
}

// handleExitData accepts the data stream that answers a dial.
func (c *Coordinator) handleExitData(w http.ResponseWriter, r *http.Request, cluster string) {
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		return
	}
	if !c.hub.deliver(cluster, r.URL.Query().Get("id"), conn, api.ExitResult{}) {
		conn.Close() // the dial gave up waiting
	}
}

// handleExitResult accepts the outcome of any request other than a
// successful dial.
func (c *Coordinator) handleExitResult(w http.ResponseWriter, r *http.Request, cluster string) {
	var res api.ExitResult
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&res); err != nil {
		writeError(w, http.StatusBadRequest, "malformed result: "+err.Error())
		return
	}
	c.hub.deliver(cluster, r.URL.Query().Get("id"), nil, res)
}
