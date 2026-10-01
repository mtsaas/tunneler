package coordinator

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/publisher"
	"github.com/mtsaas/tunneler/internal/testutil"
)

type delayedSharePublisher struct {
	*Client
	dials atomic.Int32
}

func (c *delayedSharePublisher) PublisherData(ctx context.Context, id, generation, service, connection string) (net.Conn, error) {
	c.dials.Add(1)
	select {
	case <-time.After(40 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return c.Client.PublisherData(ctx, id, generation, service, connection)
}

func TestShareHTTPPageLoadBurst(t *testing.T) {
	for _, tc := range []struct {
		name    string
		warm    bool
		pending int
	}{
		{"cold pool", false, 32}, {"warm pool", true, 32}, {"request burst", false, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(20 * time.Millisecond):
					io.WriteString(w, r.URL.Path)
				case <-r.Context().Done():
				}
			}))
			defer app.Close()
			cfg := shareTestConfig(t)
			cfg.Sharing.MaxConnectionsPerShare = 128
			cfg.Sharing.MaxConnectionsPerUser = 128
			cfg.Sharing.MaxPendingDialsPerShare = tc.pending
			c := shareTestCoordinator(t, cfg)
			control := httptest.NewServer(c.Handler())
			defer control.Close()
			client := &delayedSharePublisher{Client: shareTestClient(control.URL, "alice")}
			share, err := client.CreateShare(ctx, shareTestRequest("page-load", "web"))
			testutil.NoError(t, err)
			ready := make(chan *api.Share, 1)
			done := make(chan error, 1)
			go func() {
				done <- publisher.Run(ctx, client, share, map[string]string{"web": strings.TrimPrefix(app.URL, "http://")}, func(_ context.Context, share *api.Share) error {
					ready <- share
					return nil
				})
			}()
			t.Cleanup(func() {
				cancel()
				testutil.Receive(t, done, 2*time.Second, "publisher did not exit")
			})
			share = testutil.Receive(t, ready, 2*time.Second, "publisher did not become ready")
			public, _ := url.Parse(share.Services[0].URL)
			edge := httptest.NewUnstartedServer(c.Handler())
			edge.EnableHTTP2 = true
			edge.StartTLS()
			defer edge.Close()
			visit := func() error {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, edge.URL+"/module.tsx", nil)
				req.Host = public.Host
				response, err := edge.Client().Do(req)
				if err != nil {
					return err
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil || response.StatusCode != http.StatusOK || response.ProtoMajor != 2 || string(body) != "/module.tsx" {
					return fmt.Errorf("response %s: %q, %v", response.Status, body, err)
				}
				return nil
			}
			if tc.warm {
				testutil.NoError(t, visit())
			}
			const requests = 256
			start, results := make(chan struct{}), make(chan error, requests)
			for range requests {
				go func() { <-start; results <- visit() }()
			}
			close(start)
			failures := 0
			var first error
			for range requests {
				if err := testutil.Receive(t, results, 10*time.Second, "page load stalled"); err != nil {
					failures++
					first = err
				}
			}
			testutil.Require(t, failures == 0, "%d/%d page requests failed; example: %v", failures, requests, first)
			before := client.dials.Load()
			for range 10 {
				testutil.NoError(t, visit())
			}
			testutil.Require(t, client.dials.Load() == before, "sequential requests opened new tunnels instead of reusing the pool")
		})
	}
}

func TestShareHTTPReclaimsIdleConnectionBudget(t *testing.T) {
	for _, scope := range []string{"share", "owner", "global"} {
		t.Run(scope, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "application") }))
			defer app.Close()
			cfg := shareTestConfig(t)
			cfg.Sharing.AllowAuthenticated = true
			cfg.Sharing.MaxConnectionsPerShare, cfg.Sharing.MaxConnectionsPerUser, cfg.Sharing.MaxConnections = 2, 2, 2
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
			start := func(user, id string) *api.Share {
				client := shareTestClient(server.URL, user)
				share, err := client.CreateShare(ctx, shareTestRequest(id, "web", "api"))
				testutil.NoError(t, err)
				return waitTestShareReady(t, startTestSharePublisher(t, ctx, client, share, map[string]string{
					"web": strings.TrimPrefix(app.URL, "http://"), "api": strings.TrimPrefix(app.URL, "http://"),
				}))
			}
			first := start("alice", "idle-first")
			other := first
			if scope == "owner" {
				other = start("alice", "idle-other")
			} else if scope == "global" {
				other = start("bob", "idle-other")
			}
			for _, service := range []api.ShareService{first.Services[0], other.Services[1], first.Services[0]} {
				public, _ := url.Parse(service.URL)
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
				req.Host = public.Host
				response, err := http.DefaultClient.Do(req)
				testutil.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				testutil.Require(t, err == nil && response.StatusCode == http.StatusOK && string(body) == "application", "idle pool prevented another service from using capacity: %s %v", body, err)
				c.shares.mu.Lock()
				connections := c.shares.connections
				c.shares.mu.Unlock()
				testutil.Require(t, connections == 1, "socket budget or idle pooling changed: %d", connections)
			}
		})
	}
}

func TestShareHTTPQueueTimeoutKeepsStreamingRequestAlive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout+5*time.Second)
	defer cancel()
	pulse := make(chan struct{})
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Known-length streams need immediate flushing too.
		w.Header().Set("Content-Length", "1048576")
		io.WriteString(w, "open\n")
		http.NewResponseController(w).Flush()
		select {
		case <-pulse:
			io.WriteString(w, "still open\n")
			http.NewResponseController(w).Flush()
		case <-r.Context().Done():
			return
		}
		<-r.Context().Done()
	}))
	defer app.Close()
	cfg := shareTestConfig(t)
	cfg.Sharing.MaxConnectionsPerShare = 1
	c := shareTestCoordinator(t, cfg)
	server := httptest.NewServer(c.Handler())
	defer server.Close()
	client := shareTestClient(server.URL, "alice")
	share, err := client.CreateShare(ctx, shareTestRequest("queue-timeout", "web"))
	testutil.NoError(t, err)
	share = waitTestShareReady(t, startTestSharePublisher(t, ctx, client, share, map[string]string{"web": strings.TrimPrefix(app.URL, "http://")}))
	public, _ := url.Parse(share.Services[0].URL)
	visit := func() *http.Response {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		req.Host = public.Host
		response, err := http.DefaultClient.Do(req)
		testutil.NoError(t, err)
		return response
	}
	stream := visit()
	defer stream.Body.Close()
	opening := make([]byte, len("open\n"))
	_, err = io.ReadFull(stream.Body, opening)
	testutil.NoError(t, err)
	queued := visit()
	body, err := io.ReadAll(queued.Body)
	queued.Body.Close()
	testutil.Require(t, err == nil && queued.StatusCode == http.StatusServiceUnavailable && strings.Contains(string(body), "queue timed out"), "queue timeout = %d %q %v", queued.StatusCode, body, err)
	close(pulse)
	stillOpen := make([]byte, len("still open\n"))
	_, err = io.ReadFull(stream.Body, stillOpen)
	testutil.Require(t, err == nil && string(stillOpen) == "still open\n", "queue deadline ended the active stream: %q %v", stillOpen, err)
}
