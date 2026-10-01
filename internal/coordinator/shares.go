package coordinator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

var shareNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,32}[a-z0-9])?$`)

type shareManager struct {
	c                     *Coordinator
	mu                    sync.Mutex
	boot                  string
	closed                bool
	shares                map[string]*sharedServiceSet
	operations            map[string]*sharedServiceSet
	hosts                 map[string]shareHost
	connections           int
	ownerConnections      map[string]int
	frontendRequests      int
	ownerFrontendRequests map[string]int
	routing               *SharingConfig
	routingError          bool
}

// A share owns generic service byte streams. HTTP is one caller of dial;
// a later public TCP listener need not participate in HTTP routing.
type sharedServiceSet struct {
	manager     *shareManager
	info        api.Share
	owner       Identity
	fingerprint string
	retainUntil time.Time
	ctx         context.Context
	cancel      context.CancelFunc
	timer       *time.Timer
	control     *shareControl
	lastPong    time.Time
	pending     map[string]*shareDial
	conns       map[*shareConn]struct{}
	frontends   map[*shareFrontend]struct{}
	proxies     map[string]*shareHTTPProxy
	connections int
}

type shareHost struct {
	share   *sharedServiceSet
	service string
}
type shareDial struct {
	service, generation string
	result              chan shareDialResult
}
type shareDialResult struct {
	conn net.Conn
	err  error
}

type shareFrontend struct{ setDeadline func(time.Time) error }

func shareOwnerKey(id *Identity) string { return id.Issuer + "\x00" + id.Subject }
func shareOperationKey(id *Identity, requestID string) string {
	return shareOwnerKey(id) + "\x00" + requestID
}

func cloneShare(info api.Share) api.Share {
	info.Services = slices.Clone(info.Services)
	if info.ReadyAt != nil {
		ready := *info.ReadyAt
		info.ReadyAt = &ready
	}
	return info
}

func cloneShareIdentity(id *Identity) Identity {
	copy := *id
	copy.Groups, copy.Roles = slices.Clone(id.Groups), slices.Clone(id.Roles)
	return copy
}

func shareAPIError(status int, code, message string) error {
	return &api.Error{Status: status, Code: code, Message: message}
}

func writeShareError(w http.ResponseWriter, err error) {
	var ae *api.Error
	if !errors.As(err, &ae) {
		ae = &api.Error{Status: 500, Code: "error", Message: "could not complete share operation"}
	}
	writeJSON(w, ae.Status, ae)
}

func shareIdentityValid(id *Identity) bool {
	return id.Issuer != "" && id.Subject != "" && id.Username != "" && !id.ExpiresAt.IsZero() && time.Now().Before(id.ExpiresAt)
}

func (c *Coordinator) initShares() error {
	if err := c.config().validateSharing(); err != nil {
		return err
	}
	m := &shareManager{c: c, boot: "boot_" + strings.ToLower(rand.Text()), shares: make(map[string]*sharedServiceSet), operations: make(map[string]*sharedServiceSet), hosts: make(map[string]shareHost), ownerConnections: make(map[string]int), ownerFrontendRequests: make(map[string]int)}
	c.shares = m
	if c.config().Sharing != nil {
		routing := c.config().sharingConfig()
		m.routing = &routing
	}
	return m.loadLedger()
}

func (c *Coordinator) closeShares() {
	if c.shares == nil {
		return
	}
	m := c.shares
	m.mu.Lock()
	m.closed = true
	sets := make([]*sharedServiceSet, 0, len(m.shares))
	for _, s := range m.shares {
		if s.info.State != "ended" {
			sets = append(sets, s)
		}
	}
	m.mu.Unlock()
	for _, s := range sets {
		s.end("coordinator_restart")
	}
}

func (c *Coordinator) reloadShares() {
	if c.shares == nil {
		return
	}
	m := c.shares
	m.mu.Lock()
	if c.config().Sharing != nil {
		routing := c.config().sharingConfig()
		if err := m.saveRoutingLocked(routing); err != nil {
			c.log.Error("recording sharing host isolation; retaining previous host restrictions", "err", err)
			m.routingError = true
			if m.routing == nil {
				m.routing = &routing
			}
		} else {
			m.routing = &routing
			m.routingError = false
		}
	}
	var denied []*sharedServiceSet
	for _, s := range m.shares {
		if s.info.State != "ended" && (!c.config().canPublish(&s.owner) || c.config().Sharing == nil || !s.domainMatches(c.config().sharingConfig().Domain)) {
			denied = append(denied, s)
		}
	}
	m.mu.Unlock()
	for _, s := range denied {
		s.end("permission_revoked")
	}
}

func (s *sharedServiceSet) domainMatches(domain string) bool {
	for _, service := range s.info.Services {
		u, _ := url.Parse(service.URL)
		if u == nil || !strings.HasSuffix(u.Hostname(), "."+domain) {
			return false
		}
	}
	return true
}

func normalizedShareRequest(req api.ShareRequest, cfg SharingConfig) (api.ShareRequest, time.Duration, string, error) {
	bad := func(message string) (api.ShareRequest, time.Duration, string, error) {
		return req, 0, "", shareAPIError(400, "usage", message)
	}
	if req.Access != "public" {
		return bad("access must explicitly be public")
	}
	if len(req.RequestID) < 8 || len(req.RequestID) > 128 || strings.ContainsAny(req.RequestID, "\x00\r\n") {
		return bad("request_id must contain 8 to 128 characters")
	}
	if req.ManifestDigest == "" || len(req.ManifestDigest) > 256 {
		return bad("manifest_digest is required and must contain at most 256 characters")
	}
	if len(req.Services) == 0 || len(req.Services) > cfg.MaxServices {
		return bad("service count exceeds the allowed range")
	}
	seen := make(map[string]bool)
	req.Services = slices.Clone(req.Services)
	for i := range req.Services {
		s := &req.Services[i]
		if !shareNamePattern.MatchString(s.Name) || seen[s.Name] {
			return bad("service names must be distinct lowercase DNS labels of at most 34 characters")
		}
		seen[s.Name] = true
		if s.Protocol == "" {
			s.Protocol = api.ShareProtocolHTTP
		}
		if s.Protocol != api.ShareProtocolHTTP {
			return bad("unsupported frontend protocol: " + s.Protocol)
		}
	}
	slices.SortFunc(req.Services, func(a, b api.ShareServiceRequest) int { return strings.Compare(a.Name, b.Name) })
	ttl := time.Duration(cfg.DefaultTTL)
	if req.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(req.TTL)
		if err != nil {
			return bad("ttl must be a duration")
		}
		req.TTL = ttl.String()
	}
	if ttl <= 0 || ttl > time.Duration(cfg.MaxTTL) {
		return bad("ttl exceeds the allowed range")
	}
	if req.StartupDeadline.IsZero() {
		return bad("startup_deadline is required")
	}
	req.StartupDeadline = req.StartupDeadline.UTC()
	encoded, _ := json.Marshal(req)
	digest := sha256.Sum256(encoded)
	return req, ttl, hex.EncodeToString(digest[:]), nil
}

func (m *shareManager) create(id *Identity, req api.ShareRequest) (*api.Share, error) {
	if !shareIdentityValid(id) {
		return nil, shareAPIError(401, "not_logged_in", "a current user token with verified expiry is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	config := m.c.config()
	if !config.canPublish(id) {
		return nil, shareAPIError(403, "access_denied", "publishing is disabled or access is denied")
	}
	cfg := config.sharingConfig()
	req, ttl, fingerprint, err := normalizedShareRequest(req, cfg)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if m.closed {
		return nil, shareAPIError(503, "upstream_unavailable", "coordinator is stopping")
	}
	if m.routingError {
		return nil, shareAPIError(503, "upstream_unavailable", "share host isolation could not be persisted")
	}
	if err := m.pruneLedgerLocked(now); err != nil {
		return nil, err
	}
	if previous := m.operations[shareOperationKey(id, req.RequestID)]; previous != nil {
		if previous.fingerprint != fingerprint {
			return nil, shareAPIError(409, "idempotency_conflict", "request_id already identifies different inputs")
		}
		return m.snapshotLocked(previous, now), nil
	}
	if !now.Before(req.StartupDeadline) || req.StartupDeadline.After(now.Add(time.Duration(cfg.SetupTTL))) {
		return nil, shareAPIError(400, "usage", "startup_deadline must be within the configured setup window")
	}
	if len(m.operations) >= cfg.MaxOperationRecords {
		return nil, shareAPIError(503, "quota_exceeded", "operation record limit reached")
	}
	owned, retainedOwned := 0, 0
	for _, s := range m.shares {
		if shareOwnerKey(&s.owner) == shareOwnerKey(id) {
			retainedOwned++
			if s.liveLocked() {
				owned++
			}
		}
	}
	if retainedOwned >= cfg.MaxOperationRecordsPerUser {
		return nil, shareAPIError(503, "quota_exceeded", "retained operation record limit reached for this user")
	}
	if owned >= cfg.MaxSharesPerUser {
		return nil, shareAPIError(503, "quota_exceeded", "active share limit reached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &sharedServiceSet{manager: m, owner: cloneShareIdentity(id), fingerprint: fingerprint, ctx: ctx, cancel: cancel, pending: make(map[string]*shareDial), conns: make(map[*shareConn]struct{}), frontends: make(map[*shareFrontend]struct{}), proxies: make(map[string]*shareHTTPProxy)}
	s.info = api.Share{SchemaVersion: 1, ID: "shr_" + strings.ToLower(rand.Text()), Owner: id.Username, RequestID: req.RequestID, BootID: m.boot, State: "pending", Access: "public", ExpiresAt: now.Add(ttl), StartupDeadline: req.StartupDeadline}
	s.info.AuthorizationDeadline = earliest(id.ExpiresAt, s.info.ExpiresAt, now.Add(time.Duration(cfg.AuthorizationLease)))
	for _, request := range req.Services {
		host := request.Name + "-" + strings.ToLower(rand.Text()) + "." + cfg.Domain
		s.info.Services = append(s.info.Services, api.ShareService{ID: "svc_" + strings.ToLower(rand.Text()), Name: request.Name, Protocol: request.Protocol, URL: "https://" + host})
	}
	if err := mustAudit(ctx, m.c.audit, "share creation authorized", "share", s.info.ID, "issuer", id.Issuer, "subject", id.Subject, "user", id.Username, "expires_at", s.info.ExpiresAt); err != nil {
		cancel()
		return nil, shareAPIError(503, "audit_unavailable", "the audit trail could not record this share")
	}
	if err := m.saveLedgerLocked(s, true); err != nil {
		cancel()
		return nil, err
	}
	m.shares[s.info.ID] = s
	m.operations[shareOperationKey(id, req.RequestID)] = s
	for _, service := range s.info.Services {
		u, _ := url.Parse(service.URL)
		m.hosts[u.Host] = shareHost{s, service.ID}
	}
	s.scheduleLocked()
	m.c.audit.Info("share created", "share", s.info.ID, "subject", id.Subject, "user", id.Username, "expires_at", s.info.ExpiresAt)
	info := cloneShare(s.info)
	return &info, nil
}

func earliest(times ...time.Time) time.Time {
	return slices.MinFunc(times, time.Time.Compare)
}

func (m *shareManager) findLocked(id *Identity, shareID string, admin bool) (*sharedServiceSet, error) {
	s := m.shares[shareID]
	if s == nil || (shareOwnerKey(&s.owner) != shareOwnerKey(id) && !admin) {
		return nil, shareAPIError(404, "unknown_share", "share not found or access denied")
	}
	return s, nil
}

func (s *sharedServiceSet) scheduleLocked() {
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.info.State == "ended" {
		return
	}
	deadline := s.connectionDeadlineLocked()
	// Socket deadlines enforce authority even if a SQLite writer delays the
	// timer's lock acquisition. Renewal and acknowledged heartbeats extend
	// these deadlines; neither can extend the absolute share lifetime.
	for conn := range s.conns {
		conn.Conn.SetDeadline(deadline)
	}
	for frontend := range s.frontends {
		frontend.setDeadline(deadline)
	}
	if s.control != nil {
		s.control.conn.SetReadDeadline(deadline)
	}
	s.timer = time.AfterFunc(max(time.Until(deadline), 0), s.checkDeadline)
}

func (s *sharedServiceSet) connectionDeadlineLocked() time.Time {
	deadline := earliest(s.info.ExpiresAt, s.info.AuthorizationDeadline)
	if s.info.State == "pending" {
		deadline = earliest(deadline, s.info.StartupDeadline)
	}
	if s.control != nil {
		deadline = earliest(deadline, s.lastPong.Add(time.Duration(s.manager.c.config().sharingConfig().HeartbeatTimeout)))
	}
	return deadline
}

func (s *sharedServiceSet) checkDeadline() {
	m := s.manager
	m.mu.Lock()
	if s.info.State == "ended" {
		m.mu.Unlock()
		return
	}
	now := time.Now()
	reason := s.expiredReasonLocked(now)
	if reason == "" {
		s.scheduleLocked()
	}
	m.mu.Unlock()
	if reason != "" {
		s.end(reason)
	}
}

func (s *sharedServiceSet) expiredReasonLocked(now time.Time) string {
	if s.info.State == "ended" {
		return ""
	}
	switch {
	case !now.Before(s.info.ExpiresAt):
		return "expired"
	case !now.Before(s.info.AuthorizationDeadline):
		return "authorization_expired"
	case s.info.State == "pending" && !now.Before(s.info.StartupDeadline):
		return "setup_expired"
	case s.control != nil && !now.Before(s.lastPong.Add(time.Duration(s.manager.c.config().sharingConfig().HeartbeatTimeout))):
		return "heartbeat_timeout"
	}
	return ""
}

func (s *sharedServiceSet) end(reason string) {
	m := s.manager
	m.mu.Lock()
	if s.info.State == "ended" {
		m.mu.Unlock()
		return
	}
	if expired := s.expiredReasonLocked(time.Now()); expired != "" {
		reason = expired
	}
	s.info.State, s.info.TerminalReason = "ended", reason
	s.retainUntil = time.Now().Add(time.Duration(m.c.config().sharingConfig().OperationRetention))
	if s.timer != nil {
		s.timer.Stop()
	}
	for _, service := range s.info.Services {
		u, _ := url.Parse(service.URL)
		delete(m.hosts, u.Host)
	}
	for connectionID, pending := range s.pending {
		delete(s.pending, connectionID)
		s.releaseSlotLocked()
		pending.result <- shareDialResult{err: shareAPIError(503, "upstream_unavailable", "share ended")}
	}
	conns := slices.Collect(maps.Keys(s.conns))
	proxies := slices.Collect(maps.Values(s.proxies))
	control := s.control
	subject := s.owner.Subject
	// SQLite can wait for another writer. Revoke traffic before recording the
	// terminal metadata, even while the database is temporarily unavailable.
	s.cancel()
	now := time.Now()
	if control != nil {
		control.conn.SetDeadline(now)
	}
	for _, conn := range conns {
		conn.Conn.SetDeadline(now)
	}
	for frontend := range s.frontends {
		frontend.setDeadline(now)
	}
	if err := m.saveLedgerLocked(s, false); err != nil {
		m.c.log.Error("recording share termination", "share", s.info.ID, "err", err)
	}
	m.mu.Unlock()
	if control != nil {
		control.conn.Close()
	}
	for _, conn := range conns {
		conn.Close()
	}
	for _, proxy := range proxies {
		proxy.transport.CloseIdleConnections()
	}
	m.c.audit.Info("share ended", "share", s.info.ID, "subject", subject, "reason", reason)
}

func (s *sharedServiceSet) reserveFrontendLocked(frontend *shareFrontend) error {
	m := s.manager
	cfg := m.c.config().sharingConfig()
	owner := shareOwnerKey(&s.owner)
	if len(s.frontends) >= cfg.MaxConnectionsPerShare || m.ownerFrontendRequests[owner] >= cfg.MaxConnectionsPerUser || m.frontendRequests >= cfg.MaxConnections {
		return shareAPIError(503, "quota_exceeded", "preview request limit reached")
	}
	s.frontends[frontend] = struct{}{}
	m.frontendRequests++
	m.ownerFrontendRequests[owner]++
	return nil
}

func (s *sharedServiceSet) releaseFrontendLocked(frontend *shareFrontend) {
	delete(s.frontends, frontend)
	m := s.manager
	m.frontendRequests--
	owner := shareOwnerKey(&s.owner)
	m.ownerFrontendRequests[owner]--
	if m.ownerFrontendRequests[owner] == 0 {
		delete(m.ownerFrontendRequests, owner)
	}
}

func (s *sharedServiceSet) reserveSlotLocked() error {
	m := s.manager
	cfg := m.c.config().sharingConfig()
	owner := shareOwnerKey(&s.owner)
	if s.connections >= cfg.MaxConnectionsPerShare || m.ownerConnections[owner] >= cfg.MaxConnectionsPerUser || m.connections >= cfg.MaxConnections {
		return shareAPIError(503, "quota_exceeded", "share connection limit reached")
	}
	s.connections++
	m.connections++
	m.ownerConnections[owner]++
	return nil
}

func (s *sharedServiceSet) releaseSlotLocked() {
	s.connections--
	s.manager.connections--
	owner := shareOwnerKey(&s.owner)
	s.manager.ownerConnections[owner]--
	if s.manager.ownerConnections[owner] == 0 {
		delete(s.manager.ownerConnections, owner)
	}
}

type shareConn struct {
	net.Conn
	share   *sharedServiceSet
	counted bool
	once    sync.Once
}

func (conn *shareConn) Close() error {
	var err error
	conn.once.Do(func() {
		m := conn.share.manager
		m.mu.Lock()
		delete(conn.share.conns, conn)
		if conn.counted {
			conn.share.releaseSlotLocked()
		}
		m.mu.Unlock()
		conn.Conn.SetDeadline(time.Now())
		err = conn.Conn.Close()
	})
	return err
}

func (s *sharedServiceSet) trackLocked(conn net.Conn, counted bool) *shareConn {
	conn.SetDeadline(s.connectionDeadlineLocked())
	tracked := &shareConn{Conn: conn, share: s, counted: counted}
	s.conns[tracked] = struct{}{}
	return tracked
}

func (s *sharedServiceSet) dial(ctx context.Context, serviceID string) (net.Conn, error) {
	m := s.manager
	m.mu.Lock()
	if !s.liveLocked() || s.control == nil {
		m.mu.Unlock()
		return nil, shareAPIError(503, "upstream_unavailable", "publisher unavailable")
	}
	if !slices.ContainsFunc(s.info.Services, func(service api.ShareService) bool { return service.ID == serviceID }) {
		m.mu.Unlock()
		return nil, fmt.Errorf("unknown registered service")
	}
	if len(s.pending) >= m.c.config().sharingConfig().MaxPendingDialsPerShare {
		m.mu.Unlock()
		return nil, shareAPIError(503, "quota_exceeded", "pending dial limit reached")
	}
	if err := s.reserveSlotLocked(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	id := strings.ToLower(rand.Text())
	pending := &shareDial{service: serviceID, generation: s.info.Generation, result: make(chan shareDialResult, 1)}
	s.pending[id] = pending
	control := s.control
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if s.pending[id] == pending {
			delete(s.pending, id)
			s.releaseSlotLocked()
		}
		m.mu.Unlock()
		select {
		case result := <-pending.result:
			if result.conn != nil {
				result.conn.Close()
			}
		default:
		}
	}()
	if err := control.send(api.PublisherMessage{Type: "dial", Generation: pending.generation, ServiceID: serviceID, ConnectionID: id}); err != nil {
		s.end("control_lost")
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	select {
	case result := <-pending.result:
		return result.conn, result.err
	case <-dialCtx.Done():
		return nil, dialCtx.Err()
	case <-s.ctx.Done():
		return nil, net.ErrClosed
	}
}
