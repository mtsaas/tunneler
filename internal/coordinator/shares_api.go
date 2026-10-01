package coordinator

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

func shareDecode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeShareError(w, shareAPIError(400, "usage", "malformed share request"))
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		writeShareError(w, shareAPIError(400, "usage", "request must contain one JSON object"))
		return false
	}
	return true
}

func (c *Coordinator) registerShareRoutes(mux *http.ServeMux) {
	mux.HandleFunc(routeShareCreate, c.user(c.handleCreateShare))
	mux.HandleFunc(routeShareList, c.user(c.handleListShares))
	mux.HandleFunc(routeShareGet, c.user(c.handleGetShare))
	mux.HandleFunc(routeShareStop, c.user(c.handleStopShare))
	mux.HandleFunc(routeShareOperation, c.user(c.handleShareOperation))
	mux.HandleFunc(routeShareRenew, c.user(c.handleRenewShare))
	mux.HandleFunc(routePublisherControl, c.user(c.handlePublisherControl))
	mux.HandleFunc(routePublisherData, c.user(c.handlePublisherData))
	mux.HandleFunc(routePublisherResult, c.user(c.handlePublisherResult))
}

func (c *Coordinator) handleCreateShare(w http.ResponseWriter, r *http.Request, id *Identity) {
	var req api.ShareRequest
	if !shareDecode(w, r, &req) {
		return
	}
	share, err := c.shares.create(id, req)
	if err != nil {
		writeShareError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, share)
}

func (c *Coordinator) handleListShares(w http.ResponseWriter, _ *http.Request, id *Identity) {
	m := c.shares
	m.mu.Lock()
	type expiredShare struct {
		share  *sharedServiceSet
		reason string
	}
	var expired []expiredShare
	for _, s := range m.shares {
		if reason := s.expiredReasonLocked(time.Now()); reason != "" {
			expired = append(expired, expiredShare{s, reason})
		}
	}
	m.mu.Unlock()
	for _, s := range expired {
		s.share.end(s.reason)
	}
	m.mu.Lock()
	if err := m.pruneLedgerLocked(time.Now()); err != nil {
		m.mu.Unlock()
		writeShareError(w, err)
		return
	}
	shares := []api.Share{}
	for _, s := range m.shares {
		if shareOwnerKey(id) == shareOwnerKey(&s.owner) || c.isAdmin(id) {
			shares = append(shares, cloneShare(s.info))
		}
	}
	m.mu.Unlock()
	slices.SortFunc(shares, func(a, b api.Share) int { return strings.Compare(a.ID, b.ID) })
	writeJSON(w, 200, shares)
}

func (c *Coordinator) handleGetShare(w http.ResponseWriter, r *http.Request, id *Identity) {
	share, err := c.shares.inspect(id, r.PathValue("id"), c.isAdmin(id))
	if err != nil {
		writeShareError(w, err)
		return
	}
	writeJSON(w, 200, share)
}

func (c *Coordinator) handleShareOperation(w http.ResponseWriter, r *http.Request, id *Identity) {
	share, err := c.shares.operation(id, r.PathValue("requestID"))
	if err != nil {
		writeShareError(w, err)
		return
	}
	writeJSON(w, 200, share)
}

func (c *Coordinator) handleStopShare(w http.ResponseWriter, r *http.Request, id *Identity) {
	m := c.shares
	m.mu.Lock()
	if err := m.pruneLedgerLocked(time.Now()); err != nil {
		m.mu.Unlock()
		writeShareError(w, err)
		return
	}
	s, err := m.findLocked(id, r.PathValue("id"), c.isAdmin(id))
	m.mu.Unlock()
	if err != nil {
		writeShareError(w, err)
		return
	}
	s.end("stopped")
	m.mu.Lock()
	info := cloneShare(s.info)
	m.mu.Unlock()
	writeJSON(w, 200, info)
}

func (c *Coordinator) handleRenewShare(w http.ResponseWriter, r *http.Request, id *Identity) {
	var req api.ShareRenewRequest
	if !shareDecode(w, r, &req) {
		return
	}
	m := c.shares
	m.mu.Lock()
	s, err := m.findLocked(id, r.PathValue("id"), false)
	if err != nil {
		m.mu.Unlock()
		writeShareError(w, err)
		return
	}
	if s.info.State == "ended" || s.info.Generation != req.Generation || req.Generation == "" || !time.Now().Before(s.info.AuthorizationDeadline) || !time.Now().Before(s.info.ExpiresAt) {
		m.mu.Unlock()
		s.checkDeadline()
		writeShareError(w, shareAPIError(409, "share_ended", "share ended or generation is no longer active"))
		return
	}
	if !shareIdentityValid(id) || !c.config().canPublish(id) {
		m.mu.Unlock()
		s.end("permission_revoked")
		writeShareError(w, shareAPIError(403, "access_denied", "publishing access withdrawn"))
		return
	}
	s.owner = cloneShareIdentity(id)
	s.info.AuthorizationDeadline = earliest(id.ExpiresAt, s.info.ExpiresAt, time.Now().Add(time.Duration(c.config().sharingConfig().AuthorizationLease)))
	if err := m.saveLedgerLocked(s, false); err != nil {
		m.mu.Unlock()
		s.end("storage_failed")
		writeShareError(w, err)
		return
	}
	s.scheduleLocked()
	info := cloneShare(s.info)
	m.mu.Unlock()
	writeJSON(w, 200, info)
}
