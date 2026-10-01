package coordinator

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/publisher"
	"github.com/mtsaas/tunneler/internal/testutil"
)

const shareBenchmarkModuleSize = 16 << 10

type benchmarkSharePublisher struct {
	*Client
	dials atomic.Int64
}

func (c *benchmarkSharePublisher) PublisherData(ctx context.Context, id, generation, service, connection string) (net.Conn, error) {
	c.dials.Add(1)
	return c.Client.PublisherData(ctx, id, generation, service, connection)
}

type shareHTTPBenchmark struct {
	client    *http.Client
	url, host string
	dials     *atomic.Int64
	closeIdle func()
}

func newShareHTTPBenchmark(b *testing.B, shared bool) *shareHTTPBenchmark {
	b.Helper()
	module := []byte(strings.Repeat("x", shareBenchmarkModuleSize))
	arrived, release := make(chan struct{}, 128), make(chan struct{})
	var priming atomic.Bool
	priming.Store(true)
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if priming.Load() {
			arrived <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(module)))
		w.Write(module)
	})
	fixture := &shareHTTPBenchmark{}
	var handler http.Handler = appHandler
	var closeBackend func()
	if shared {
		app := httptest.NewServer(appHandler)
		b.Cleanup(app.Close)
		cfg := shareTestConfig(b)
		cfg.Sharing.MaxConnectionsPerShare, cfg.Sharing.MaxConnectionsPerUser = 128, 128
		c := shareTestCoordinator(b, cfg)
		control := httptest.NewUnstartedServer(c.Handler())
		control.Config.ErrorLog = log.New(io.Discard, "", 0)
		control.StartTLS()
		b.Cleanup(control.Close)
		client := &benchmarkSharePublisher{Client: shareTestClient(control.URL, "alice")}
		client.HTTP = control.Client()
		share, err := client.CreateShare(b.Context(), shareTestRequest("benchmark", "web"))
		testutil.NoError(b, err)
		ctx, cancel := context.WithCancel(b.Context())
		ready, done := make(chan *api.Share, 1), make(chan error, 1)
		go func() {
			done <- publisher.Run(ctx, client, share, map[string]string{"web": strings.TrimPrefix(app.URL, "http://")}, func(_ context.Context, share *api.Share) error {
				ready <- share
				return nil
			})
		}()
		b.Cleanup(func() {
			cancel()
			testutil.Receive(b, done, 5*time.Second, "benchmark publisher did not exit")
		})
		share = testutil.Receive(b, ready, 5*time.Second, "benchmark publisher did not become ready")
		public, _ := url.Parse(share.Services[0].URL)
		fixture.host, fixture.dials = public.Host, &client.dials
		handler = c.Handler()
		closeBackend = func() {
			c.shares.mu.Lock()
			proxy := c.shares.shares[share.ID].proxies[share.Services[0].ID]
			c.shares.mu.Unlock()
			if proxy != nil {
				proxy.transport.CloseIdleConnections()
			}
		}
	}
	edge := httptest.NewUnstartedServer(handler)
	edge.Config.ErrorLog = log.New(io.Discard, "", 0)
	edge.EnableHTTP2 = true
	edge.StartTLS()
	b.Cleanup(edge.Close)
	fixture.client, fixture.url = edge.Client(), edge.URL+"/module.js"
	fixture.client.Timeout = 30 * time.Second
	fixture.closeIdle = func() {
		fixture.client.CloseIdleConnections()
		if closeBackend != nil {
			closeBackend()
		}
	}
	// Hold the initial responses until all 128 backend connections exist.
	// Otherwise a "warm" sample can still include growing the connection pool.
	warmed := make(chan error, 1)
	go func() { warmed <- fixture.page(b.Context(), 128) }()
	for range 128 {
		testutil.Receive(b, arrived, 5*time.Second, "benchmark pool did not become warm")
	}
	priming.Store(false)
	close(release)
	testutil.NoError(b, testutil.Receive(b, warmed, 5*time.Second, "benchmark warmup did not finish"))
	return fixture
}

func (f *shareHTTPBenchmark) request(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return err
	}
	if f.host != "" {
		req.Host = f.host
	}
	req.Header.Set("Accept-Encoding", "identity")
	response, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	n, err := io.Copy(io.Discard, response.Body)
	if err != nil || response.StatusCode != http.StatusOK || response.ProtoMajor != 2 || n != shareBenchmarkModuleSize {
		return fmt.Errorf("module response: status=%d protocol=%s bytes=%d error=%v", response.StatusCode, response.Proto, n, err)
	}
	return nil
}

func (f *shareHTTPBenchmark) page(ctx context.Context, requests int) error {
	results := make(chan error, requests)
	for range requests {
		go func() { results <- f.request(ctx) }()
	}
	var first error
	for range requests {
		if err := <-results; err != nil && first == nil {
			first = err
		}
	}
	return first
}

// A page operation fetches 256 modules in parallel. Both paths use HTTP/2
// and TLS at the visitor edge; sharing also uses the real TLS publisher path.
func BenchmarkShareHTTP(b *testing.B) {
	for _, workload := range []struct {
		name     string
		requests int
		cold     bool
	}{
		{"warm-request", 1, false}, {"warm-page", 256, false}, {"cold-page", 256, true},
	} {
		b.Run(workload.name, func(b *testing.B) {
			for _, shared := range []bool{false, true} {
				name := "direct"
				if shared {
					name = "tunnel"
				}
				b.Run(name, func(b *testing.B) {
					fixture := newShareHTTPBenchmark(b, shared)
					var dials int64
					if fixture.dials != nil {
						dials = fixture.dials.Load()
					}
					b.ReportAllocs()
					b.SetBytes(int64(workload.requests * shareBenchmarkModuleSize))
					for b.Loop() {
						if workload.cold {
							b.StopTimer()
							fixture.closeIdle()
							b.StartTimer()
						}
						var err error
						if workload.requests == 1 {
							err = fixture.request(b.Context())
						} else {
							err = fixture.page(b.Context(), workload.requests)
						}
						testutil.NoError(b, err)
					}
					if fixture.dials != nil {
						b.ReportMetric(float64(fixture.dials.Load()-dials)/float64(b.N), "dials/op")
					}
				})
			}
		})
	}
}
