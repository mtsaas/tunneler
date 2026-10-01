package publisher

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

type fakeClient struct {
	control  net.Conn
	data     chan net.Conn
	results  chan api.PublisherResult
	renew    func(context.Context) (*api.Share, error)
	controls atomic.Int32
}

func (c *fakeClient) PublisherControl(context.Context, string) (net.Conn, error) {
	c.controls.Add(1)
	return c.control, nil
}
func (c *fakeClient) PublisherData(ctx context.Context, _, _, _, _ string) (net.Conn, error) {
	a, b := net.Pipe()
	select {
	case c.data <- b:
		return a, nil
	case <-ctx.Done():
		a.Close()
		b.Close()
		return nil, ctx.Err()
	}
}
func (c *fakeClient) PublisherResult(_ context.Context, _ string, result api.PublisherResult) error {
	c.results <- result
	return nil
}
func (c *fakeClient) RenewShare(ctx context.Context, _, _ string) (*api.Share, error) {
	return c.renew(ctx)
}

func fixture(t *testing.T) (*fakeClient, net.Conn, *api.Share, map[string]string) {
	t.Helper()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { local.Close() })
	go func() {
		for {
			conn, err := local.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	s := &api.Share{ID: "share", State: "pending", ExpiresAt: time.Now().Add(time.Hour), AuthorizationDeadline: time.Now().Add(time.Hour), Services: []api.ShareService{{ID: "svc", Name: "web"}}}
	c := &fakeClient{control: a, data: make(chan net.Conn, 1), results: make(chan api.PublisherResult, 1)}
	c.renew = func(context.Context) (*api.Share, error) {
		copy := *s
		copy.AuthorizationDeadline = time.Now().Add(time.Hour)
		return &copy, nil
	}
	return c, b, s, map[string]string{"web": local.Addr().String()}
}

func send(t *testing.T, control net.Conn, msg api.PublisherMessage) {
	t.Helper()
	control.SetWriteDeadline(time.Now().Add(time.Second))
	if err := json.NewEncoder(control).Encode(msg); err != nil {
		t.Fatal(err)
	}
}

func TestRunOpaqueBytesAndPromptCancellation(t *testing.T) {
	c, control, s, targets := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, c, s, targets, func(context.Context, *api.Share) error { close(ready); return nil })
	}()
	send(t, control, api.PublisherMessage{Type: "attached", Generation: "gen", Share: s})
	send(t, control, api.PublisherMessage{Type: "dial", Generation: "gen", ServiceID: "svc", ConnectionID: "connection"})
	var data net.Conn
	select {
	case data = <-c.data:
	case <-time.After(time.Second):
		t.Fatal("data did not attach")
	}
	defer data.Close()
	copy := *s
	copy.State = "ready"
	send(t, control, api.PublisherMessage{Type: "ready", Share: &copy})
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("readiness did not arrive")
	}
	payload := []byte{0, 255, 128, 'H', 'T', 'T', 'P', '\r', '\n', 0}
	data.SetDeadline(time.Now().Add(time.Second))
	if _, err := data.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(data, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatalf("opaque payload changed: %x", got)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close streams")
	}
	if _, err := data.Read(make([]byte, 1)); err == nil {
		t.Fatal("data remained open")
	}
	if c.controls.Load() != 1 {
		t.Fatal("publisher reconnected")
	}
}

func TestBlockedRenewalStillAnswersHeartbeat(t *testing.T) {
	c, control, s, targets := fixture(t)
	s.AuthorizationDeadline = time.Now().Add(50 * time.Millisecond)
	started, release := make(chan struct{}), make(chan struct{})
	c.renew = func(ctx context.Context) (*api.Share, error) {
		close(started)
		select {
		case <-release:
			copy := *s
			copy.AuthorizationDeadline = time.Now().Add(time.Hour)
			return &copy, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, s, targets, nil) }()
	send(t, control, api.PublisherMessage{Type: "attached", Generation: "gen", Share: s})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("renewal did not begin")
	}
	send(t, control, api.PublisherMessage{Type: "ping"})
	control.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var reply api.PublisherReply
	if err := json.NewDecoder(control).Decode(&reply); err != nil || reply.Type != "pong" {
		t.Fatalf("heartbeat blocked by renewal: %+v, %v", reply, err)
	}
	close(release)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publisher did not stop")
	}
}

func TestUnknownServiceNeverDialsAndControlLossIsTerminal(t *testing.T) {
	c, control, s, targets := fixture(t)
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), c, s, targets, nil) }()
	send(t, control, api.PublisherMessage{Type: "attached", Generation: "gen", Share: s})
	send(t, control, api.PublisherMessage{Type: "dial", Generation: "gen", ServiceID: "arbitrary", ConnectionID: "connection"})
	select {
	case result := <-c.results:
		if result.ServiceID != "arbitrary" || result.Error == "" {
			t.Fatalf("bad result: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("dial failure was not returned")
	}
	select {
	case conn := <-c.data:
		conn.Close()
		t.Fatal("unknown service dialed")
	default:
	}
	control.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("control loss was silently successful")
		}
	case <-time.After(time.Second):
		t.Fatal("control loss did not stop publisher")
	}
	if c.controls.Load() != 1 {
		t.Fatal("publisher recreated control")
	}
}

func TestExpiryStopsWithoutRecreation(t *testing.T) {
	c, control, s, targets := fixture(t)
	s.ExpiresAt = time.Now().Add(50 * time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), c, s, targets, nil) }()
	send(t, control, api.PublisherMessage{Type: "attached", Generation: "gen", Share: s})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("expiry did not stop publisher")
	}
	if c.controls.Load() != 1 {
		t.Fatal("expired publisher reconnected")
	}
}

func TestRejectNonLoopbackBeforeAttachment(t *testing.T) {
	c := &fakeClient{}
	err := Run(context.Background(), c, &api.Share{Services: []api.ShareService{{Name: "web"}}}, map[string]string{"web": "192.0.2.1:80"}, nil)
	if err == nil || c.controls.Load() != 0 {
		t.Fatal("remote target reached control attachment")
	}
}

func TestReadinessContextEndsBeforeTerminalCleanupWait(t *testing.T) {
	c, control, s, targets := fixture(t)
	s.AuthorizationDeadline = time.Now().Add(50 * time.Millisecond)
	renewing, release := make(chan struct{}), make(chan struct{})
	c.renew = func(ctx context.Context) (*api.Share, error) { close(renewing); <-release; return nil, ctx.Err() }
	readyContext := make(chan context.Context, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), c, s, targets, func(ctx context.Context, _ *api.Share) error { readyContext <- ctx; <-ctx.Done(); return ctx.Err() })
	}()
	send(t, control, api.PublisherMessage{Type: "attached", Generation: "gen", Share: s})
	select {
	case <-renewing:
	case <-time.After(time.Second):
		t.Fatal("renewal never started")
	}
	copy := *s
	copy.State = "ready"
	send(t, control, api.PublisherMessage{Type: "ready", Share: &copy})
	var callbackContext context.Context
	select {
	case callbackContext = <-readyContext:
	case <-time.After(time.Second):
		t.Fatal("readiness callback never began")
	}
	control.Close()
	select {
	case <-callbackContext.Done():
	case <-time.After(time.Second):
		close(release)
		t.Fatal("handoff context survived terminal control")
	}
	select {
	case <-done:
		close(release)
		t.Fatal("fixture did not keep cleanup pending")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("terminal cleanup never completed")
	}
}
