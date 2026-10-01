package coordinator

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

type shareControl struct {
	conn net.Conn
	mu   sync.Mutex
	done <-chan struct{}
}

func (control *shareControl) send(message api.PublisherMessage) error {
	control.mu.Lock()
	defer control.mu.Unlock()
	select {
	case <-control.done:
		return net.ErrClosed
	default:
	}
	control.conn.SetWriteDeadline(time.Now().Add(helloTimeout))
	return json.NewEncoder(control.conn).Encode(message)
}

func (s *sharedServiceSet) liveLocked() bool {
	cfg := s.manager.c.config()
	return !s.manager.closed && s.info.State != "ended" && cfg.canPublish(&s.owner) && cfg.Sharing != nil && s.domainMatches(cfg.Sharing.Domain) && s.expiredReasonLocked(time.Now()) == ""
}

func (c *Coordinator) handlePublisherControl(w http.ResponseWriter, r *http.Request, id *Identity) {
	m := c.shares
	m.mu.Lock()
	s, err := m.findLocked(id, r.PathValue("id"), false)
	if err != nil {
		m.mu.Unlock()
		writeShareError(w, err)
		return
	}
	if !shareIdentityValid(id) || !c.config().canPublish(id) {
		m.mu.Unlock()
		writeShareError(w, shareAPIError(403, "access_denied", "publishing is denied"))
		return
	}
	if !s.liveLocked() {
		m.mu.Unlock()
		writeShareError(w, shareAPIError(409, "share_ended", "share ended"))
		return
	}
	if s.info.Generation != "" {
		m.mu.Unlock()
		writeShareError(w, shareAPIError(409, "publisher_attached", "publisher generation already attached"))
		return
	}
	s.info.Generation = "gen_" + strings.ToLower(rand.Text())
	s.owner = cloneShareIdentity(id)
	s.info.AuthorizationDeadline = earliest(id.ExpiresAt, s.info.ExpiresAt, time.Now().Add(time.Duration(c.config().sharingConfig().AuthorizationLease)))
	m.mu.Unlock()
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		s.end("setup_failed")
		return
	}
	control := &shareControl{conn: conn, done: s.ctx.Done()}
	m.mu.Lock()
	if !s.liveLocked() {
		m.mu.Unlock()
		conn.Close()
		return
	}
	s.control, s.lastPong = control, time.Now()
	if err := m.saveLedgerLocked(s, false); err != nil {
		m.mu.Unlock()
		conn.Close()
		s.end("storage_failed")
		return
	}
	s.scheduleLocked()
	info := cloneShare(s.info)
	m.mu.Unlock()
	defer s.end("control_lost")
	if err := control.send(api.PublisherMessage{Type: "attached", Generation: info.Generation, Share: &info}); err != nil {
		return
	}
	go s.prepare()
	go func() {
		ticker := time.NewTicker(time.Duration(c.config().sharingConfig().HeartbeatInterval))
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				if err := control.send(api.PublisherMessage{Type: "ping", Generation: info.Generation}); err != nil {
					s.end("control_lost")
					return
				}
			}
		}
	}()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		var reply api.PublisherReply
		if err := json.Unmarshal(scanner.Bytes(), &reply); err != nil || reply.Type != "pong" {
			s.end("invalid_control_message")
			return
		}
		m.mu.Lock()
		if !s.liveLocked() {
			m.mu.Unlock()
			return
		}
		s.lastPong = time.Now()
		s.scheduleLocked()
		m.mu.Unlock()
	}
}

func (s *sharedServiceSet) prepare() {
	m := s.manager
	m.mu.Lock()
	services := append([]api.ShareService(nil), s.info.Services...)
	deadline := s.info.StartupDeadline
	m.mu.Unlock()
	ctx, cancel := context.WithDeadline(s.ctx, deadline)
	defer cancel()
	for _, service := range services {
		conn, err := s.dial(ctx, service.ID)
		if err != nil {
			s.end("upstream_unavailable")
			return
		}
		conn.Close()
	}
	m.mu.Lock()
	if !s.liveLocked() || s.control == nil {
		m.mu.Unlock()
		return
	}
	ready := time.Now()
	s.info.State, s.info.ReadyAt = "ready", &ready
	if err := m.saveLedgerLocked(s, false); err != nil {
		m.mu.Unlock()
		s.end("storage_failed")
		return
	}
	s.scheduleLocked()
	info := cloneShare(s.info)
	control := s.control
	m.mu.Unlock()
	if err := control.send(api.PublisherMessage{Type: "ready", Generation: info.Generation, Share: &info}); err != nil {
		s.end("control_lost")
	}
}

func (c *Coordinator) publisherPendingLocked(id *Identity, shareID, generation, serviceID, connectionID string) (*sharedServiceSet, *shareDial, error) {
	m := c.shares
	s, err := m.findLocked(id, shareID, false)
	if err != nil {
		return nil, nil, err
	}
	if !shareIdentityValid(id) || !c.config().canPublish(id) {
		return nil, nil, shareAPIError(403, "access_denied", "publishing is denied")
	}
	pending := s.pending[connectionID]
	if !s.liveLocked() || generation == "" || s.info.Generation != generation || pending == nil || pending.generation != generation || pending.service != serviceID {
		return nil, nil, shareAPIError(409, "invalid_attachment", "no matching live dial request")
	}
	return s, pending, nil
}

func (c *Coordinator) handlePublisherData(w http.ResponseWriter, r *http.Request, id *Identity) {
	m := c.shares
	generation, service, connection := r.URL.Query().Get("generation"), r.URL.Query().Get("service"), r.URL.Query().Get("connection")
	m.mu.Lock()
	_, _, err := c.publisherPendingLocked(id, r.PathValue("id"), generation, service, connection)
	m.mu.Unlock()
	if err != nil {
		writeShareError(w, err)
		return
	}
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		return
	}
	m.mu.Lock()
	s, pending, err := c.publisherPendingLocked(id, r.PathValue("id"), generation, service, connection)
	if err != nil {
		m.mu.Unlock()
		conn.Close()
		return
	}
	delete(s.pending, connection)
	m.notifyCapacityLocked()
	tracked := s.trackLocked(conn, true)
	pending.result <- shareDialResult{conn: tracked}
	m.mu.Unlock()
	// The dial caller now owns the stream. Returning must not close it.
}

func (c *Coordinator) handlePublisherResult(w http.ResponseWriter, r *http.Request, id *Identity) {
	var result api.PublisherResult
	if !shareDecode(w, r, &result) {
		return
	}
	if result.Error == "" || len(result.Error) > 4096 {
		writeShareError(w, shareAPIError(400, "usage", "a bounded dial error is required"))
		return
	}
	m := c.shares
	m.mu.Lock()
	s, pending, err := c.publisherPendingLocked(id, r.PathValue("id"), result.Generation, result.ServiceID, result.ConnectionID)
	if err != nil {
		m.mu.Unlock()
		writeShareError(w, err)
		return
	}
	delete(s.pending, result.ConnectionID)
	s.releaseSlotLocked()
	pending.result <- shareDialResult{err: shareAPIError(502, "upstream_unavailable", "publisher could not reach the local service")}
	m.mu.Unlock()
	writeJSON(w, 200, map[string]bool{"accepted": true})
}
