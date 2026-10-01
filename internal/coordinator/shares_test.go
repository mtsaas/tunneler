package coordinator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/testutil"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

func shareTestConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{Database: filepath.Join(t.TempDir(), "shares.db"), SessionTTL: Duration(time.Hour), OIDC: OIDCConfig{Issuer: "https://issuer.test"}, Admins: []string{"admins"}, Sharing: &SharingConfig{Domain: "preview.test", ControlHosts: []string{"127.0.0.1"}, Grants: []PublishGrant{{Group: "developers"}}, AuthorizationLease: Duration(time.Minute), HeartbeatInterval: Duration(time.Second), HeartbeatTimeout: Duration(5 * time.Second)}}
}

func shareTestIdentity(name string) *Identity {
	id := &Identity{Issuer: "https://issuer.test", Subject: name, Username: name + "@test", UserID: name, ExpiresAt: time.Now().Add(time.Hour)}
	if name == "alice" {
		id.Groups = []string{"developers"}
	}
	if name == "admin" {
		id.Groups = []string{"admins"}
	}
	return id
}

func shareTestCoordinator(t *testing.T, cfg *Config) *Coordinator {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := New(cfg, func(_ context.Context, token string) (*Identity, error) {
		if token == "" {
			return nil, errors.New("no token")
		}
		return shareTestIdentity(token), nil
	}, quiet, quiet.Handler())
	testutil.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func shareTestRequest(id string, names ...string) api.ShareRequest {
	req := api.ShareRequest{Access: "public", RequestID: id, ManifestDigest: "sha256:local-manifest", TTL: "1h", StartupDeadline: time.Now().Add(30 * time.Second)}
	for _, name := range names {
		req.Services = append(req.Services, api.ShareServiceRequest{Name: name})
	}
	return req
}

func shareTestClient(server, user string) *Client {
	return &Client{Server: server, Token: func(context.Context) (string, error) { return user, nil }}
}

func requireShareError(t *testing.T, err error, code string) {
	t.Helper()
	var ae *api.Error
	testutil.Require(t, errors.As(err, &ae) && ae.Code == code, "error = %v, want code %s", err, code)
}

func TestShareCreationOwnershipRetryAndRestart(t *testing.T) {
	cfg := shareTestConfig(t)
	c := shareTestCoordinator(t, cfg)
	owner := shareTestIdentity("alice")
	req := shareTestRequest("operation-123", "web", "api")
	first, err := c.shares.create(owner, req)
	testutil.NoError(t, err)
	second, err := c.shares.create(owner, req)
	testutil.Require(t, err == nil && second.ID == first.ID, "retry = %+v, %v", second, err)
	changed := req
	changed.ManifestDigest = "other"
	_, err = c.shares.create(owner, changed)
	requireShareError(t, err, "idempotency_conflict")
	_, err = c.shares.create(shareTestIdentity("bob"), req)
	requireShareError(t, err, "access_denied")
	_, err = c.shares.inspect(shareTestIdentity("bob"), first.ID, false)
	requireShareError(t, err, "unknown_share")
	otherIssuer := *owner
	otherIssuer.Issuer = "https://other.test"
	_, err = c.shares.inspect(&otherIssuer, first.ID, false)
	requireShareError(t, err, "unknown_share")
	zeroExpiry := *owner
	zeroExpiry.ExpiresAt = time.Time{}
	_, err = c.shares.create(&zeroExpiry, req)
	requireShareError(t, err, "not_logged_in")
	missingIssuer := *owner
	missingIssuer.Issuer = ""
	_, err = c.shares.create(&missingIssuer, req)
	requireShareError(t, err, "not_logged_in")
	if _, err := c.shares.inspect(shareTestIdentity("admin"), first.ID, true); err != nil {
		t.Fatal(err)
	}
	bad := shareTestRequest("bad-service", "okay", "bad_name")
	_, err = c.shares.create(owner, bad)
	requireShareError(t, err, "usage")
	bad = shareTestRequest("bad-protocol", "web")
	bad.Services[0].Protocol = "tcp"
	_, err = c.shares.create(owner, bad)
	requireShareError(t, err, "usage")
	testutil.Require(t, len(c.shares.operations) == 1, "partial invalid allocation: %d records", len(c.shares.operations))
	testutil.NoError(t, c.Close())
	restarted := shareTestCoordinator(t, cfg)
	replay, err := restarted.shares.create(owner, req)
	testutil.Require(t, err == nil && replay.ID == first.ID && replay.State == "ended" && replay.TerminalReason == "coordinator_restart", "restart replay = %+v, %v", replay, err)
	testutil.Require(t, replay.BootID != restarted.shares.boot, "original operation boot identity lost")
	testutil.Require(t, len(restarted.shares.hosts) == 0, "restart restored routes")
	op, err := restarted.shares.operation(owner, req.RequestID)
	testutil.Require(t, err == nil && op.ID == first.ID, "operation lookup: %+v %v", op, err)
}

func TestShareConcurrentCreateAndRetentionCap(t *testing.T) {
	cfg := shareTestConfig(t)
	cfg.Sharing.MaxOperationRecords = 1
	c := shareTestCoordinator(t, cfg)
	req := shareTestRequest("same-operation", "web")
	owner := shareTestIdentity("alice")
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := c.shares.create(owner, req)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- info.ID
		}()
	}
	wg.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		testutil.Require(t, id == first, "duplicate allocation")
	}
	_, err := c.shares.create(owner, shareTestRequest("another-operation", "web"))
	requireShareError(t, err, "quota_exceeded")
	c.shares.shares[first].end("stopped")
	_, err = c.shares.create(owner, shareTestRequest("another-operation", "web"))
	requireShareError(t, err, "quota_exceeded")
	c.shares.mu.Lock()
	c.shares.shares[first].retainUntil = time.Now().Add(-time.Second)
	c.shares.saveLedgerLocked(c.shares.shares[first], false)
	c.shares.mu.Unlock()
	if _, err = c.shares.create(owner, shareTestRequest("another-operation", "web")); err != nil {
		t.Fatal(err)
	}
	_, err = c.shares.operation(owner, req.RequestID)
	requireShareError(t, err, "unknown_share")
}

func TestShareOwnerOperationRetentionBudget(t *testing.T) {
	cfg := shareTestConfig(t)
	cfg.Sharing.AllowAuthenticated = true
	cfg.Sharing.MaxOperationRecordsPerUser = 2
	cfg.Sharing.MaxOperationRecords = 4
	c := shareTestCoordinator(t, cfg)
	owner := shareTestIdentity("alice")
	firstRequest := shareTestRequest("owner-retention-first", "web")
	first, err := c.shares.create(owner, firstRequest)
	testutil.NoError(t, err)
	c.shares.shares[first.ID].end("stopped")
	second, err := c.shares.create(owner, shareTestRequest("owner-retention-second", "web"))
	testutil.NoError(t, err)
	c.shares.shares[second.ID].end("stopped")
	if replay, err := c.shares.create(owner, firstRequest); err != nil || replay.ID != first.ID || replay.State != "ended" {
		t.Fatalf("replay at owner cap = %+v, %v", replay, err)
	}
	conflict := firstRequest
	conflict.ManifestDigest = "different-manifest"
	_, err = c.shares.create(owner, conflict)
	requireShareError(t, err, "idempotency_conflict")
	_, err = c.shares.create(owner, shareTestRequest("owner-retention-third", "web"))
	requireShareError(t, err, "quota_exceeded")
	other, err := c.shares.create(shareTestIdentity("bob"), shareTestRequest("other-owner-operation", "web"))
	testutil.Require(t, err == nil && other.Owner == "bob@test", "other owner's available budget = %+v, %v", other, err)
	c.shares.mu.Lock()
	old := c.shares.shares[first.ID]
	old.retainUntil = time.Now().Add(-time.Second)
	err = c.shares.saveLedgerLocked(old, false)
	c.shares.mu.Unlock()
	testutil.NoError(t, err)
	if _, err := c.shares.create(owner, shareTestRequest("owner-retention-third", "web")); err != nil {
		t.Fatalf("expired retention did not recover the owner's budget: %v", err)
	}
	_, err = c.shares.operation(owner, firstRequest.RequestID)
	requireShareError(t, err, "unknown_share")
	if retained, err := c.shares.operation(owner, second.RequestID); err != nil || retained.ID != second.ID || retained.State != "ended" {
		t.Fatalf("unexpired tombstone = %+v, %v", retained, err)
	}
}

func TestShareCreateUsesConfigAfterAllocationLock(t *testing.T) {
	for _, change := range []string{"domain", "policy"} {
		t.Run(change, func(t *testing.T) {
			cfg := shareTestConfig(t)
			cfg.Sharing.AllowAuthenticated = true
			c := shareTestCoordinator(t, cfg)
			old, err := c.shares.create(shareTestIdentity("alice"), shareTestRequest("old-config-operation", "web"))
			testutil.NoError(t, err)
			current := *cfg
			sharing := *cfg.Sharing
			current.Sharing = &sharing
			if change == "domain" {
				sharing.Domain = "new-preview.test"
			} else {
				sharing.AllowAuthenticated = false
			}
			type outcome struct {
				share *api.Share
				err   error
			}
			result := make(chan outcome, 1)
			c.shares.mu.Lock()
			locked := true
			defer func() {
				if locked {
					c.shares.mu.Unlock()
				}
			}()
			go func() {
				share, err := c.shares.create(shareTestIdentity("bob"), shareTestRequest("new-config-operation", "web"))
				result <- outcome{share, err}
			}()
			deadline := time.Now().Add(2 * time.Second)
			for {
				stack := make([]byte, 64<<10)
				n := runtime.Stack(stack, true)
				blocked := false
				for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
					if strings.Contains(goroutine, "[sync.Mutex.Lock]") && strings.Contains(goroutine, "coordinator.(*shareManager).create(") {
						blocked = true
						break
					}
				}
				if blocked {
					break
				}
				testutil.Require(t, !time.Now().After(deadline), "create did not block on the allocation lock")
				runtime.Gosched()
			}
			c.cfg.Store(&current)
			testutil.Require(t, change != "domain" || !c.shares.shares[old.ID].liveLocked(), "retired domain remained live before the reload sweep")
			c.shares.mu.Unlock()
			locked = false
			select {
			case got := <-result:
				if change == "policy" {
					requireShareError(t, got.err, "access_denied")
				} else {
					testutil.Require(t, got.err == nil && strings.HasSuffix(got.share.Services[0].URL, ".new-preview.test"), "allocation after domain change = %+v, %v", got.share, got.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("create did not finish after unlocking")
			}
		})
	}
}

func TestShareFrontendAdmissionAndCleanup(t *testing.T) {
	for _, scope := range []string{"share", "owner", "global"} {
		t.Run(scope, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "open\n")
				http.NewResponseController(w).Flush()
				<-r.Context().Done()
			}))
			defer upstream.Close()
			cfg := shareTestConfig(t)
			cfg.Sharing.AllowAuthenticated = true
			cfg.Sharing.MaxConnectionsPerShare = 2
			cfg.Sharing.MaxConnectionsPerUser = 8
			cfg.Sharing.MaxConnections = 8
			switch scope {
			case "share":
				cfg.Sharing.MaxConnectionsPerShare = 1
			case "owner":
				cfg.Sharing.MaxConnectionsPerUser = 1
			case "global":
				cfg.Sharing.MaxConnections = 1
			}
			c := shareTestCoordinator(t, cfg)
			server := httptest.NewServer(c.Handler())
			defer server.Close()
			local, _ := url.Parse(upstream.URL)
			start := func(user, requestID string) (*Client, *api.Share) {
				client := shareTestClient(server.URL, user)
				info, err := client.CreateShare(ctx, shareTestRequest(requestID, "web"))
				testutil.NoError(t, err)
				publisher := startTestSharePublisher(t, ctx, client, info, map[string]string{"web": local.Host})
				return client, waitTestShareReady(t, publisher)
			}
			firstClient, first := start("alice", "first-frontend-operation")
			otherClient, other := firstClient, first
			if scope == "owner" {
				otherClient, other = start("alice", "second-frontend-operation")
			} else if scope == "global" {
				otherClient, other = start("bob", "second-frontend-operation")
			}
			visit := func(visitCtx context.Context, share *api.Share) *http.Response {
				public, _ := url.Parse(share.Services[0].URL)
				req, _ := http.NewRequestWithContext(visitCtx, "GET", server.URL+"/stream", nil)
				req.Host = public.Host
				response, err := http.DefaultClient.Do(req)
				testutil.NoError(t, err)
				return response
			}
			waitEmpty := func() {
				t.Helper()
				deadline := time.Now().Add(2 * time.Second)
				for {
					c.shares.mu.Lock()
					frontends, owners, backends := c.shares.frontendRequests, len(c.shares.ownerFrontendRequests), c.shares.connections
					c.shares.mu.Unlock()
					if frontends == 0 && owners == 0 && backends == 0 {
						return
					}
					testutil.Require(t, !time.Now().After(deadline), "cleanup = %d frontend requests, %d owners, %d backend sockets", frontends, owners, backends)
					time.Sleep(5 * time.Millisecond)
				}
			}
			firstCtx, firstCancel := context.WithCancel(ctx)
			defer firstCancel()
			response := visit(firstCtx, first)
			defer response.Body.Close()
			testutil.Require(t, response.StatusCode == http.StatusOK, "first visitor = %d", response.StatusCode)
			c.shares.mu.Lock()
			frontends, backends := c.shares.frontendRequests, c.shares.connections
			c.shares.mu.Unlock()
			testutil.Require(t, frontends == 1 && backends == 1, "independent counters = %d frontends, %d backends", frontends, backends)
			excessCtx, excessCancel := context.WithTimeout(ctx, time.Second)
			defer excessCancel()
			excess := visit(excessCtx, other)
			excess.Body.Close()
			testutil.Require(t, excess.StatusCode == http.StatusServiceUnavailable, "excess visitor = %d; want prompt 503", excess.StatusCode)
			firstCancel()
			response.Body.Close()
			waitEmpty()
			recovered := visit(ctx, other)
			defer recovered.Body.Close()
			testutil.Require(t, recovered.StatusCode == http.StatusOK, "visitor after cancellation = %d", recovered.StatusCode)
			opening := make([]byte, len("open\n"))
			if _, err := io.ReadFull(recovered.Body, opening); err != nil {
				t.Fatal(err)
			}
			closed := make(chan error, 1)
			go func() { _, err := recovered.Body.Read(make([]byte, 1)); closed <- err }()
			if _, err := otherClient.StopShare(ctx, other.ID); err != nil {
				t.Fatal(err)
			}
			testutil.Require(t, testutil.Receive(t, closed, time.Second, "stop did not unblock the streaming visitor") != nil, "visitor survived stop")
			recovered.Body.Close()
			waitEmpty()
		})
	}
}

func TestShareKnownReplayAfterStartupDeadline(t *testing.T) {
	c := shareTestCoordinator(t, shareTestConfig(t))
	owner := shareTestIdentity("alice")
	req := shareTestRequest("ready-replay-operation", "web")
	info, err := c.shares.create(owner, req)
	testutil.NoError(t, err)
	s := c.shares.shares[info.ID]
	c.shares.mu.Lock()
	s.timer.Stop()
	s.info.State = "ready"
	s.info.Generation = "existing-generation"
	s.info.StartupDeadline = time.Now().Add(-time.Second)
	c.shares.mu.Unlock()
	replay, err := c.shares.create(owner, req)
	testutil.Require(t, err == nil && replay.ID == info.ID && replay.State == "ready" && replay.Generation == "existing-generation", "known ready replay = %+v %v", replay, err)
	req.RequestID = "unknown-expired-operation"
	req.StartupDeadline = time.Now().Add(-time.Second)
	_, err = c.shares.create(owner, req)
	requireShareError(t, err, "usage")
}

func TestShareDeadlinesAndReload(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*api.Share)
	}{
		{"expired", func(info *api.Share) { info.ExpiresAt = time.Now().Add(-time.Second) }},
		{"authorization_expired", func(info *api.Share) { info.AuthorizationDeadline = time.Now().Add(-time.Second) }},
		{"setup_expired", func(info *api.Share) { info.StartupDeadline = time.Now().Add(-time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := shareTestCoordinator(t, shareTestConfig(t))
			owner := shareTestIdentity("alice")
			req := shareTestRequest("expiry-operation", "web")
			info, err := c.shares.create(owner, req)
			testutil.NoError(t, err)
			s := c.shares.shares[info.ID]
			c.shares.mu.Lock()
			s.timer.Stop()
			test.change(&s.info)
			c.shares.mu.Unlock()
			if _, err := s.dial(context.Background(), info.Services[0].ID); err == nil {
				t.Fatal("dial accepted past deadline before timer ran")
			}
			inspected, err := c.shares.inspect(owner, info.ID, false)
			testutil.Require(t, err == nil && inspected.State == "ended" && inspected.TerminalReason == test.name, "inspect = %+v, %v", inspected, err)
		})
	}
	cfg := shareTestConfig(t)
	c := shareTestCoordinator(t, cfg)
	info, _ := c.shares.create(shareTestIdentity("alice"), shareTestRequest("reload-operation", "web"))
	reloaded := *cfg
	sharing := *cfg.Sharing
	sharing.Grants = nil
	reloaded.Sharing = &sharing
	c.Reload(&reloaded)
	inspected, _ := c.shares.inspect(shareTestIdentity("alice"), info.ID, false)
	testutil.Require(t, inspected.TerminalReason == "permission_revoked", "reload = %+v", inspected)
}

func TestShareDeadlineTimers(t *testing.T) {
	cfg := shareTestConfig(t)
	c := shareTestCoordinator(t, cfg)
	req := shareTestRequest("timer-operation", "web")
	req.TTL = "35ms"
	info, err := c.shares.create(shareTestIdentity("alice"), req)
	testutil.NoError(t, err)
	s := c.shares.shares[info.ID]
	testutil.Receive(t, s.ctx.Done(), time.Second, "expiry did not end share")
	c.shares.mu.Lock()
	reason := s.info.TerminalReason
	c.shares.mu.Unlock()
	testutil.Require(t, reason == "expired", "reason = %s", reason)
}

type testSharePublisher struct {
	control net.Conn
	ready   <-chan *api.Share
	done    <-chan struct{}
}

func startTestSharePublisher(t *testing.T, ctx context.Context, client *Client, info *api.Share, targets map[string]string) testSharePublisher {
	t.Helper()
	control, err := client.PublisherControl(ctx, info.ID)
	testutil.NoError(t, err)
	ready := make(chan *api.Share, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		decoder := json.NewDecoder(control)
		encoder := json.NewEncoder(control)
		for {
			var message api.PublisherMessage
			if err := decoder.Decode(&message); err != nil {
				return
			}
			switch message.Type {
			case "ready":
				ready <- message.Share
			case "ping":
				if encoder.Encode(api.PublisherReply{Type: "pong"}) != nil {
					return
				}
			case "dial":
				go func(message api.PublisherMessage) {
					name := ""
					for _, service := range info.Services {
						if service.ID == message.ServiceID {
							name = service.Name
						}
					}
					local, err := net.DialTimeout("tcp", targets[name], time.Second)
					if err != nil {
						client.PublisherResult(ctx, info.ID, api.PublisherResult{Generation: message.Generation, ServiceID: message.ServiceID, ConnectionID: message.ConnectionID, Error: "local service unreachable"})
						return
					}
					stream, err := client.PublisherData(ctx, info.ID, message.Generation, message.ServiceID, message.ConnectionID)
					if err != nil {
						local.Close()
						return
					}
					tunnel.Splice(local, stream)
				}(message)
			}
		}
	}()
	t.Cleanup(func() {
		control.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("publisher did not close")
		}
	})
	return testSharePublisher{control, ready, done}
}

func waitTestShareReady(t *testing.T, publisher testSharePublisher) *api.Share {
	t.Helper()
	select {
	case ready := <-publisher.ready:
		return ready
	case <-publisher.done:
		t.Fatal("publisher ended before readiness")
	case <-time.After(3 * time.Second):
		t.Fatal("publisher readiness timeout")
	}
	return nil
}

func TestShareHTTPAndUpgradeEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	seen := make(chan *http.Request, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/opaque":
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: custom\r\n\r\nSERVER_EARLY")
			brw.Flush()
			io.Copy(conn, brw.Reader)
		case "/websocket":
			ws, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer ws.CloseNow()
			for {
				kind, data, err := ws.Read(r.Context())
				if err != nil {
					return
				}
				if ws.Write(r.Context(), kind, data) != nil {
					return
				}
			}
		case "/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: first\n\n")
			http.NewResponseController(w).Flush()
			<-r.Context().Done()
		default:
			seen <- r.Clone(context.Background())
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Set-Cookie", "app=1")
			fmt.Fprintf(w, "%s %s %s", r.URL.Path, r.URL.RawQuery, body)
		}
	}))
	defer upstream.Close()
	c := shareTestCoordinator(t, shareTestConfig(t))
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	info, err := client.CreateShare(ctx, shareTestRequest("http-operation", "web"))
	testutil.NoError(t, err)
	u, _ := url.Parse(upstream.URL)
	publisher := startTestSharePublisher(t, ctx, client, info, map[string]string{"web": u.Host})
	ready := waitTestShareReady(t, publisher)
	public, _ := url.Parse(ready.Services[0].URL)
	req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1/application?secret=application", strings.NewReader("body"))
	req.Host = public.Host
	req.Header.Set("Authorization", "Bearer application-token")
	req.Header.Set("Cookie", "app=private")
	req.Header.Set("Origin", public.Scheme+"://"+public.Host)
	req.Header.Set("X-Forwarded-For", "spoof")
	resp, err := http.DefaultClient.Do(req)
	testutil.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	testutil.Require(t, string(body) == "/v1/application secret=application body" && resp.Header.Get("Set-Cookie") == "app=1", "HTTP body/headers: %s %v", body, resp.Header)
	got := <-seen
	testutil.Require(t, got.Host == public.Host && got.Header.Get("Authorization") == "Bearer application-token" && got.Header.Get("Cookie") == "app=private" && got.Header.Get("Origin") == req.Header.Get("Origin") && got.Header.Get("X-Forwarded-For") != "spoof", "forwarded request = %s %v", got.Host, got.Header)
	// Ordinary HTTP/1.1 requests reuse the backend keep-alive connection.
	for range 2 {
		request, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/pooled", nil)
		request.Host = public.Host
		response, err := http.DefaultClient.Do(request)
		testutil.NoError(t, err)
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		<-seen
	}

	// A real WebSocket client still sends RFC6455 frames inside the byte tunnel.
	ws, _, err := websocket.Dial(ctx, server.URL+"/websocket", &websocket.DialOptions{Host: public.Host, HTTPHeader: http.Header{"Origin": {"https://" + public.Host}}})
	testutil.NoError(t, err)
	defer ws.CloseNow()
	testutil.NoError(t, ws.Write(ctx, websocket.MessageBinary, []byte{0, 1, 2, 255}))
	kind, echoed, err := ws.Read(ctx)
	testutil.Require(t, err == nil && kind == websocket.MessageBinary && bytes.Equal(echoed, []byte{0, 1, 2, 255}), "websocket echo = %v %v %v", kind, echoed, err)

	// Client bytes coalesced with its request and server bytes coalesced with
	// the 101 must both survive, with opaque bytes rather than WebSocket frames.
	serverURL, _ := url.Parse(server.URL)
	raw, err := net.Dial("tcp", serverURL.Host)
	testutil.NoError(t, err)
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(raw, "GET /opaque HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: custom\r\n\r\nCLIENT_EARLY", public.Host)
	reader := bufio.NewReader(raw)
	switched, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	testutil.Require(t, err == nil && switched.StatusCode == 101, "upgrade = %+v %v", switched, err)
	early := make([]byte, len("SERVER_EARLYCLIENT_EARLY"))
	if _, err := io.ReadFull(reader, early); err != nil || string(early) != "SERVER_EARLYCLIENT_EARLY" {
		t.Fatalf("early bytes = %q %v", early, err)
	}

	streamReq, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/stream", nil)
	streamReq.Host = public.Host
	stream, err := http.DefaultClient.Do(streamReq)
	testutil.NoError(t, err)
	defer stream.Body.Close()
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(stream.Body, first); err != nil {
		t.Fatal(err)
	}
	stopped, err := client.StopShare(ctx, info.ID)
	testutil.Require(t, err == nil && stopped.State == "ended", "stop = %+v %v", stopped, err)
	readCtx, readCancel := context.WithTimeout(ctx, time.Second)
	defer readCancel()
	if _, _, err := ws.Read(readCtx); err == nil {
		t.Fatal("WebSocket survived stop")
	}
	raw.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("opaque stream survived stop")
	}
	done := make(chan error, 1)
	go func() { _, err := stream.Body.Read(make([]byte, 1)); done <- err }()
	testutil.Require(t, testutil.Receive(t, done, time.Second, "stream was not canceled") != nil, "SSE survived stop")
	c.shares.mu.Lock()
	connections := c.shares.connections
	pending := len(c.shares.shares[info.ID].pending)
	c.shares.mu.Unlock()
	testutil.Require(t, connections == 0 && pending == 0, "cleanup leaked %d connections, %d pending", connections, pending)
	if _, err := client.StopShare(ctx, info.ID); err != nil {
		t.Fatal("repeated stop:", err)
	}
}

func TestShareHostIsolationAndDisable(t *testing.T) {
	cfg := shareTestConfig(t)
	c := shareTestCoordinator(t, cfg)
	info, err := c.shares.create(shareTestIdentity("alice"), shareTestRequest("host-operation", "web"))
	testutil.NoError(t, err)
	public, _ := url.Parse(info.Services[0].URL)
	request := func(host, method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+host+path, nil)
		r.Host = host
		r.Header.Set("Authorization", "Bearer admin")
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, r)
		return w
	}
	for _, host := range []string{"unknown.preview.test", "evil.example", "deep.unknown.preview.test"} {
		if got := request(host, "GET", "/v1/shares").Code; got != 404 {
			t.Fatalf("%s reached API: %d", host, got)
		}
	}
	if got := request(public.Host, "CONNECT", "/").Code; got != 405 {
		t.Fatalf("CONNECT = %d", got)
	}
	if got := request("127.0.0.1", "GET", "/v1/shares").Code; got != 200 {
		t.Fatalf("control host = %d", got)
	}
	reloaded := *cfg
	reloaded.Sharing = nil
	c.Reload(&reloaded)
	for _, host := range []string{public.Host, "unknown.preview.test", "evil.example"} {
		if got := request(host, "GET", "/v1/shares").Code; got != 404 {
			t.Fatalf("disabled sharing allowed API for %s: %d", host, got)
		}
	}
	testutil.NoError(t, c.Close())
	c = shareTestCoordinator(t, &reloaded)
	for _, host := range []string{public.Host, "unknown.preview.test", "evil.example"} {
		if got := request(host, "GET", "/v1/shares").Code; got != 404 {
			t.Fatalf("disabled restart allowed API for %s: %d", host, got)
		}
	}
	if got := request("127.0.0.1", "GET", "/v1/shares").Code; got != 200 {
		t.Fatalf("disabled restart rejected control host: %d", got)
	}
}

func readTestPublisherMessage(t *testing.T, decoder *json.Decoder, want string) api.PublisherMessage {
	t.Helper()
	for {
		var message api.PublisherMessage
		testutil.NoError(t, decoder.Decode(&message))
		if message.Type == "ping" {
			continue
		}
		testutil.Require(t, message.Type == want, "publisher message = %+v, want %s", message, want)
		return message
	}
}

func openTestPublisherControl(t *testing.T, ctx context.Context, client *Client, info *api.Share) (net.Conn, *json.Decoder, api.PublisherMessage) {
	t.Helper()
	control, err := client.PublisherControl(ctx, info.ID)
	testutil.NoError(t, err)
	t.Cleanup(func() { control.Close() })
	decoder := json.NewDecoder(control)
	readTestPublisherMessage(t, decoder, "attached")
	return control, decoder, readTestPublisherMessage(t, decoder, "dial")
}

func TestSharePublisherPairingAndPendingStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c := shareTestCoordinator(t, shareTestConfig(t))
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	info, err := client.CreateShare(ctx, shareTestRequest("pairing-operation", "web"))
	testutil.NoError(t, err)
	control, decoder, dial := openTestPublisherControl(t, ctx, client, info)
	defer control.Close()
	for _, test := range []struct{ user, generation, service, connection string }{
		{"bob", dial.Generation, dial.ServiceID, dial.ConnectionID},
		{"admin", dial.Generation, dial.ServiceID, dial.ConnectionID},
		{"alice", "wrong-generation", dial.ServiceID, dial.ConnectionID},
		{"alice", dial.Generation, "wrong-service", dial.ConnectionID},
		{"alice", dial.Generation, dial.ServiceID, "wrong-connection"},
	} {
		if conn, err := shareTestClient(server.URL, test.user).PublisherData(ctx, info.ID, test.generation, test.service, test.connection); err == nil {
			conn.Close()
			t.Fatalf("accepted invalid attachment: %+v", test)
		}
	}
	if duplicateControl, err := client.PublisherControl(ctx, info.ID); err == nil {
		duplicateControl.Close()
		t.Fatal("second publisher attached")
	}
	valid, err := client.PublisherData(ctx, info.ID, dial.Generation, dial.ServiceID, dial.ConnectionID)
	testutil.NoError(t, err)
	defer valid.Close()
	readTestPublisherMessage(t, decoder, "ready")
	if duplicate, err := client.PublisherData(ctx, info.ID, dial.Generation, dial.ServiceID, dial.ConnectionID); err == nil {
		duplicate.Close()
		t.Fatal("duplicate data attachment accepted")
	}
	s := c.shares.shares[info.ID]
	result := make(chan error, 1)
	go func() {
		conn, err := s.dial(ctx, dial.ServiceID)
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	pending := readTestPublisherMessage(t, decoder, "dial")
	if _, err := client.StopShare(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	testutil.Require(t, testutil.Receive(t, result, time.Second, "stop did not wake pending dial") != nil, "pending dial succeeded after stop")
	if late, err := client.PublisherData(ctx, info.ID, pending.Generation, pending.ServiceID, pending.ConnectionID); err == nil {
		late.Close()
		t.Fatal("late attachment accepted")
	}
	c.shares.mu.Lock()
	count, pendingCount := s.connections, len(s.pending)
	c.shares.mu.Unlock()
	testutil.Require(t, count == 0 && pendingCount == 0, "pending cleanup = %d slots, %d calls", count, pendingCount)
}

func TestSharePublisherFailureAndConnectionQuota(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cfg := shareTestConfig(t)
	cfg.Sharing.MaxConnectionsPerShare = 1
	c := shareTestCoordinator(t, cfg)
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	info, err := client.CreateShare(ctx, shareTestRequest("quota-operation", "web"))
	testutil.NoError(t, err)
	control, _, dial := openTestPublisherControl(t, ctx, client, info)
	defer control.Close()
	s := c.shares.shares[info.ID]
	_, err = s.dial(ctx, dial.ServiceID)
	requireShareError(t, err, "quota_exceeded")
	err = client.PublisherResult(ctx, info.ID, api.PublisherResult{Generation: dial.Generation, ServiceID: dial.ServiceID, ConnectionID: dial.ConnectionID, Error: "local connection refused"})
	testutil.NoError(t, err)
	testutil.Receive(t, s.ctx.Done(), time.Second, "failed readiness did not end share")
	got, _ := client.Share(ctx, info.ID)
	testutil.Require(t, got.State == "ended" && got.TerminalReason == "upstream_unavailable", "failed setup = %+v", got)
	c.shares.mu.Lock()
	count := s.connections
	c.shares.mu.Unlock()
	testutil.Require(t, count == 0, "failure leaked %d slots", count)
}

func TestShareRenewAndAuthorizationExpiryWithHeartbeats(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	cfg := shareTestConfig(t)
	cfg.Sharing.AuthorizationLease = Duration(250 * time.Millisecond)
	cfg.Sharing.HeartbeatInterval = Duration(10 * time.Millisecond)
	cfg.Sharing.HeartbeatTimeout = Duration(time.Second)
	c := shareTestCoordinator(t, cfg)
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	info, err := client.CreateShare(ctx, shareTestRequest("renew-operation", "web"))
	testutil.NoError(t, err)
	u, _ := url.Parse(upstream.URL)
	publisher := startTestSharePublisher(t, ctx, client, info, map[string]string{"web": u.Host})
	ready := waitTestShareReady(t, publisher)
	if _, err := client.RenewShare(ctx, info.ID, "wrong-generation"); err == nil {
		t.Fatal("wrong generation renewed")
	}
	renewed, err := client.RenewShare(ctx, info.ID, ready.Generation)
	testutil.Require(t, err == nil && !renewed.AuthorizationDeadline.Before(ready.AuthorizationDeadline), "renew = %+v %v", renewed, err)
	s := c.shares.shares[info.ID]
	testutil.Receive(t, s.ctx.Done(), time.Second, "heartbeats extended authorization")
	ended, _ := client.Share(ctx, info.ID)
	testutil.Require(t, ended.TerminalReason == "authorization_expired", "expired = %+v", ended)
	if _, err := client.RenewShare(ctx, info.ID, ready.Generation); err == nil {
		t.Fatal("expired share renewed")
	}
}

func TestShareStopRacesDataRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := shareTestCoordinator(t, shareTestConfig(t))
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	for iteration := range 12 {
		info, err := client.CreateShare(ctx, shareTestRequest(fmt.Sprintf("race-operation-%02d", iteration), "web"))
		testutil.NoError(t, err)
		control, _, dial := openTestPublisherControl(t, ctx, client, info)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			conn, _ := client.PublisherData(ctx, info.ID, dial.Generation, dial.ServiceID, dial.ConnectionID)
			if conn != nil {
				conn.Close()
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := client.StopShare(ctx, info.ID); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		control.Close()
		c.shares.mu.Lock()
		count := c.shares.connections
		s := c.shares.shares[info.ID]
		tracked := len(s.conns)
		pending := len(s.pending)
		c.shares.mu.Unlock()
		testutil.Require(t, count == 0 && tracked == 0 && pending == 0, "race %d leaked: %d slots %d sockets %d pending", iteration, count, tracked, pending)
	}
}

func TestShareGenericByteStreamsEndOnTTLAndHeartbeat(t *testing.T) {
	for _, reason := range []string{"expired", "heartbeat_timeout"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cfg := shareTestConfig(t)
			cfg.Sharing.HeartbeatInterval = Duration(10 * time.Millisecond)
			if reason == "heartbeat_timeout" {
				cfg.Sharing.HeartbeatTimeout = Duration(250 * time.Millisecond)
			}
			c := shareTestCoordinator(t, cfg)
			server := httptest.NewServer(c.Handler())
			defer server.Close()
			client := shareTestClient(server.URL, "alice")
			req := shareTestRequest("generic-operation", "stream")
			if reason == "expired" {
				req.TTL = "250ms"
			}
			info, err := client.CreateShare(ctx, req)
			testutil.NoError(t, err)
			control, decoder, probe := openTestPublisherControl(t, ctx, client, info)
			defer control.Close()
			control.SetReadDeadline(time.Now().Add(time.Second))
			data, err := client.PublisherData(ctx, info.ID, probe.Generation, probe.ServiceID, probe.ConnectionID)
			testutil.NoError(t, err)
			defer data.Close()
			readTestPublisherMessage(t, decoder, "ready")
			s := c.shares.shares[info.ID]
			connected := make(chan net.Conn, 1)
			failed := make(chan error, 1)
			go func() {
				conn, err := s.dial(ctx, probe.ServiceID)
				if err != nil {
					failed <- err
					return
				}
				connected <- conn
			}()
			message := readTestPublisherMessage(t, decoder, "dial")
			publisher, err := client.PublisherData(ctx, info.ID, message.Generation, message.ServiceID, message.ConnectionID)
			testutil.NoError(t, err)
			defer publisher.Close()
			var upstream net.Conn
			select {
			case upstream = <-connected:
			case err := <-failed:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer upstream.Close()
			// This caller uses only the generic stream mechanism; no HTTP request
			// or hostname is required to establish and exchange binary bytes.
			payload := []byte{0, 1, 255, 42}
			if _, err := upstream.Write(payload); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(publisher, received); err != nil || !bytes.Equal(received, payload) {
				t.Fatalf("generic payload %v %v", received, err)
			}
			pending := make(chan error, 1)
			go func() {
				conn, err := s.dial(ctx, probe.ServiceID)
				if conn != nil {
					conn.Close()
				}
				pending <- err
			}()
			readTestPublisherMessage(t, decoder, "dial")
			testutil.Receive(t, s.ctx.Done(), 2*time.Second, "deadline did not close generic stream")
			publisher.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := publisher.Read(make([]byte, 1)); err == nil {
				t.Fatal("data stream survived terminal deadline")
			}
			testutil.Require(t, testutil.Receive(t, pending, time.Second, "pending dial not canceled") != nil, "pending dial succeeded")
			ended, err := client.Share(ctx, info.ID)
			testutil.Require(t, err == nil && ended.TerminalReason == reason, "ended = %+v %v", ended, err)
			c.shares.mu.Lock()
			slots, tracked, waiting := s.connections, len(s.conns), len(s.pending)
			c.shares.mu.Unlock()
			testutil.Require(t, slots == 0 && tracked == 0 && waiting == 0, "terminal cleanup leaked %d %d %d", slots, tracked, waiting)
		})
	}
}

func TestShareRevokeStopsTrafficBeforeBlockedLedgerWrite(t *testing.T) {
	c := shareTestCoordinator(t, shareTestConfig(t))
	info, err := c.shares.create(shareTestIdentity("alice"), shareTestRequest("storage-block-operation", "web"))
	testutil.NoError(t, err)
	s := c.shares.shares[info.ID]
	local, peer := net.Pipe()
	defer peer.Close()
	c.shares.mu.Lock()
	tracked := s.trackLocked(local, false)
	c.shares.mu.Unlock()
	defer tracked.Close()
	tx, err := c.store.db.Begin()
	testutil.NoError(t, err)
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE share_operations SET metadata = metadata WHERE share_id = ?`, info.ID); err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	go func() { s.end("stopped"); close(ended) }()
	testutil.Receive(t, s.ctx.Done(), 300*time.Millisecond, "database latency delayed cancellation")
	read := make(chan error, 1)
	go func() { _, err := local.Read(make([]byte, 1)); read <- err }()
	testutil.Require(t, testutil.Receive(t, read, 300*time.Millisecond, "database latency delayed connection deadline") != nil, "revoked connection still passed traffic")
	testutil.NoError(t, tx.Rollback())
	testutil.Receive(t, ended, 2*time.Second, "termination did not finish after database lock released")
}

func TestShareLifetimeCutsTrafficWhileRenewHoldsDatabaseLock(t *testing.T) {
	c := shareTestCoordinator(t, shareTestConfig(t))
	owner := shareTestIdentity("alice")
	req := shareTestRequest("blocked-renew-operation", "web")
	req.TTL = "250ms"
	info, err := c.shares.create(owner, req)
	testutil.NoError(t, err)
	s := c.shares.shares[info.ID]
	local, peer := net.Pipe()
	defer peer.Close()
	c.shares.mu.Lock()
	s.info.State, s.info.Generation = "ready", "test-generation"
	tracked := s.trackLocked(local, false)
	s.scheduleLocked()
	c.shares.mu.Unlock()
	defer tracked.Close()
	tx, err := c.store.db.Begin()
	testutil.NoError(t, err)
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE share_operations SET metadata = metadata WHERE share_id = ?`, info.ID); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"generation":"test-generation"}`))
	r.SetPathValue("id", info.ID)
	w := httptest.NewRecorder()
	renewed := make(chan struct{})
	go func() { c.handleRenewShare(w, r, owner); close(renewed) }()
	// Renewal holds the registry lock while waiting for SQLite. The expiry
	// callback cannot run yet, but the already installed socket deadline can.
	locked := false
	for deadline := time.Now().Add(100 * time.Millisecond); time.Now().Before(deadline); {
		if !c.shares.mu.TryLock() {
			locked = true
			break
		}
		c.shares.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	testutil.Require(t, locked, "renewal did not acquire registry lock")
	read := make(chan error, 1)
	go func() { _, err := local.Read(make([]byte, 1)); read <- err }()
	testutil.Require(t, testutil.Receive(t, read, 500*time.Millisecond, "blocked renewal postponed socket expiry") != nil, "expired connection passed traffic")
	testutil.NoError(t, tx.Rollback())
	testutil.Receive(t, renewed, 2*time.Second, "renewal remained blocked")
	testutil.Receive(t, s.ctx.Done(), time.Second, "expiry did not finish after registry unlock")
}

type shareWriteAttempt struct{ done chan struct{} }
type slowShareResponseWriter struct {
	http.ResponseWriter
	latest *atomic.Pointer[shareWriteAttempt]
}

func (w *slowShareResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *slowShareResponseWriter) Write(p []byte) (int, error) {
	attempt := &shareWriteAttempt{done: make(chan struct{})}
	w.latest.Store(attempt)
	defer close(attempt.done)
	return w.ResponseWriter.Write(p)
}

func TestShareStopUnblocksSlowOrdinaryHTTPReader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	upstreamDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(upstreamDone)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(64<<20))
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for range 1024 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	c := shareTestCoordinator(t, shareTestConfig(t))
	var publicHost atomic.Value
	publicHost.Store("")
	var latest atomic.Pointer[shareWriteAttempt]
	frontendDone := make(chan struct{})
	handler := c.Handler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == publicHost.Load().(string) {
			defer close(frontendDone)
			handler.ServeHTTP(&slowShareResponseWriter{ResponseWriter: w, latest: &latest}, r)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	info, err := client.CreateShare(ctx, shareTestRequest("slow-reader-operation", "web"))
	testutil.NoError(t, err)
	u, _ := url.Parse(upstream.URL)
	publisher := startTestSharePublisher(t, ctx, client, info, map[string]string{"web": u.Host})
	ready := waitTestShareReady(t, publisher)
	public, _ := url.Parse(ready.Services[0].URL)
	publicHost.Store(public.Host)
	serverURL, _ := url.Parse(server.URL)
	raw, err := net.Dial("tcp", serverURL.Host)
	testutil.NoError(t, err)
	defer raw.Close()
	if tcp, ok := raw.(*net.TCPConn); ok {
		testutil.NoError(t, tcp.SetReadBuffer(1024))
	}
	fmt.Fprintf(raw, "GET /large HTTP/1.1\r\nHost: %s\r\n\r\n", public.Host)
	reader := bufio.NewReader(raw)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	testutil.Require(t, err == nil && response.StatusCode == 200, "response = %+v %v", response, err)
	// Stop reading after headers. Wait for a real ResponseWriter.Write to
	// remain in flight, rather than assuming a particular TCP buffer size.
	blocked := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		attempt := latest.Load()
		if attempt == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		select {
		case <-attempt.done:
			time.Sleep(time.Millisecond)
		case <-time.After(50 * time.Millisecond):
			blocked = true
		}
		if blocked {
			break
		}
	}
	testutil.Require(t, blocked, "fixture did not block an ordinary frontend write")
	if _, err := client.StopShare(ctx, info.ID); err != nil {
		t.Fatal(err)
	}
	testutil.Receive(t, frontendDone, time.Second, "stop left frontend handler blocked on a non-reading client")
	testutil.Receive(t, upstreamDone, time.Second, "stop left upstream streaming")
	c.shares.mu.Lock()
	frontends := len(c.shares.shares[info.ID].frontends)
	c.shares.mu.Unlock()
	testutil.Require(t, frontends == 0, "%d response deadlines leaked", frontends)
}

func TestShareAuthenticatedPublishingKeepsVisitorsAnonymous(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "unexpected coordinator identity", 500)
			return
		}
		if r.URL.Path == "/opaque" {
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: custom\r\n\r\n")
			brw.Flush()
			io.Copy(conn, brw.Reader)
			return
		}
		io.WriteString(w, "anonymous application visitor")
	}))
	defer upstream.Close()
	cfg := shareTestConfig(t)
	cfg.Sharing.AllowAuthenticated, cfg.Sharing.Grants = true, nil
	c := shareTestCoordinator(t, cfg)
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := shareTestClient(server.URL, "bob")
	// Bob carries a verified user identity, with no groups or publication grant.
	info, err := client.CreateShare(ctx, shareTestRequest("authenticated-operation", "web"))
	testutil.NoError(t, err)
	testutil.Require(t, info.Owner == "bob@test", "owner = %q", info.Owner)
	body, _ := json.Marshal(shareTestRequest("anonymous-operation", "web"))
	req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1/shares", bytes.NewReader(body))
	response, err := http.DefaultClient.Do(req)
	testutil.NoError(t, err)
	response.Body.Close()
	testutil.Require(t, response.StatusCode == 401, "anonymous publisher create = %d", response.StatusCode)
	if _, err := shareTestClient(server.URL, "carol").StopShare(ctx, info.ID); err == nil {
		t.Fatal("authenticated publishing bypassed ownership")
	}
	u, _ := url.Parse(upstream.URL)
	publisher := startTestSharePublisher(t, ctx, client, info, map[string]string{"web": u.Host})
	ready := waitTestShareReady(t, publisher)
	renewed, err := client.RenewShare(ctx, info.ID, ready.Generation)
	testutil.Require(t, err == nil && renewed.State == "ready", "ungranted user renew = %+v %v", renewed, err)
	public, _ := url.Parse(ready.Services[0].URL)
	visitor, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/v1/application", nil)
	visitor.Host = public.Host
	response, err = http.DefaultClient.Do(visitor)
	testutil.NoError(t, err)
	content, _ := io.ReadAll(response.Body)
	response.Body.Close()
	testutil.Require(t, response.StatusCode == 200 && string(content) == "anonymous application visitor", "anonymous visit = %d %q", response.StatusCode, content)
	serverURL, _ := url.Parse(server.URL)
	raw, err := net.Dial("tcp", serverURL.Host)
	testutil.NoError(t, err)
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(raw, "GET /opaque HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: custom\r\n\r\nanonymous-bytes", public.Host)
	reader := bufio.NewReader(raw)
	switched, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	testutil.Require(t, err == nil && switched.StatusCode == 101, "anonymous upgrade = %+v %v", switched, err)
	echo := make([]byte, len("anonymous-bytes"))
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "anonymous-bytes" {
		t.Fatalf("anonymous bytes = %q %v", echo, err)
	}
	stopped, err := client.StopShare(ctx, info.ID)
	testutil.Require(t, err == nil && stopped.State == "ended", "ungranted user stop = %+v %v", stopped, err)
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("anonymous visitor stream survived stop")
	}
}

func TestShareReloadDisablesAuthenticatedPublishing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	cfg := shareTestConfig(t)
	cfg.Sharing.AllowAuthenticated = true
	c := shareTestCoordinator(t, cfg)
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	ungranted := shareTestClient(server.URL, "bob")
	granted := shareTestClient(server.URL, "alice")
	ungrantedInfo, err := ungranted.CreateShare(ctx, shareTestRequest("ungranted-reload-operation", "web"))
	testutil.NoError(t, err)
	grantedInfo, err := granted.CreateShare(ctx, shareTestRequest("granted-reload-operation", "web"))
	testutil.NoError(t, err)
	u, _ := url.Parse(upstream.URL)
	ungPublisher := startTestSharePublisher(t, ctx, ungranted, ungrantedInfo, map[string]string{"web": u.Host})
	waitTestShareReady(t, ungPublisher)
	grantedPublisher := startTestSharePublisher(t, ctx, granted, grantedInfo, map[string]string{"web": u.Host})
	grantedReady := waitTestShareReady(t, grantedPublisher)
	reloaded := *cfg
	sharing := *cfg.Sharing
	sharing.AllowAuthenticated = false
	reloaded.Sharing = &sharing
	c.Reload(&reloaded)
	ended, err := ungranted.Share(ctx, ungrantedInfo.ID)
	testutil.Require(t, err == nil && ended.State == "ended" && ended.TerminalReason == "permission_revoked", "ungranted reload = %+v %v", ended, err)
	if _, err := ungranted.CreateShare(ctx, shareTestRequest("ungranted-after-reload", "web")); err == nil {
		t.Fatal("ungranted create remained enabled")
	}
	if _, err := granted.RenewShare(ctx, grantedInfo.ID, grantedReady.Generation); err != nil {
		t.Fatal("explicit group grant lost on disable:", err)
	}
	retained, err := granted.Share(ctx, grantedInfo.ID)
	testutil.Require(t, err == nil && retained.State == "ready", "granted reload = %+v %v", retained, err)
}
