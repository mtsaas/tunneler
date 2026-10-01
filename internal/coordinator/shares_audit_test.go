package coordinator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/mtsaas/tunneler/internal/testutil"
)

type shareAuditSink struct {
	slog.Handler
	failing *atomic.Bool
}

func (h shareAuditSink) Handle(ctx context.Context, record slog.Record) error {
	if h.failing.Load() {
		return errors.New("audit sink unavailable")
	}
	return h.Handler.Handle(ctx, record)
}

func (h shareAuditSink) WithAttrs(attrs []slog.Attr) slog.Handler {
	return shareAuditSink{h.Handler.WithAttrs(attrs), h.failing}
}

func TestShareAuditFailureRefusesPublishingAndForwarding(t *testing.T) {
	c := shareTestCoordinator(t, shareTestConfig(t))
	var failing atomic.Bool
	c.audit = slog.New(auditHandler{Handler: shareAuditSink{slog.NewTextHandler(io.Discard, nil), &failing}, log: c.log})
	failing.Store(true)
	req := shareTestRequest("audited-operation", "web")
	if _, err := c.shares.create(shareTestIdentity("alice"), req); err == nil {
		t.Fatal("share creation succeeded without its audit record")
	} else {
		requireShareError(t, err, "audit_unavailable")
	}
	testutil.Require(t, len(c.shares.shares) == 0 && len(c.shares.operations) == 0 && len(c.shares.hosts) == 0, "refused share left a live route or operation")
	failing.Store(false)
	info, err := c.shares.create(shareTestIdentity("alice"), req)
	testutil.NoError(t, err)
	var forwarded atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		io.WriteString(w, "application response")
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	public, _ := url.Parse(info.Services[0].URL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	c.shares.mu.Lock()
	s := c.shares.shares[info.ID]
	s.info.State = "ready"
	s.proxies[info.Services[0].ID] = &shareHTTPProxy{proxy: proxy, transport: transport}
	c.shares.mu.Unlock()
	for _, fail := range []bool{true, false} {
		failing.Store(fail)
		response := httptest.NewRecorder()
		c.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, public.String(), nil))
		want := http.StatusOK
		if fail {
			want = http.StatusServiceUnavailable
		}
		testutil.Require(t, response.Code == want, "audit failing %t: status %d, want %d", fail, response.Code, want)
	}
	testutil.Require(t, forwarded.Load() == 1, "an unrecorded request reached the application")
}
