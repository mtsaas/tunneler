package exit

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

type blockingBackend struct {
	reap func(context.Context) ([]string, error)
	drop func(context.Context, string) error
}

func (*blockingBackend) Addr() string                               { return "in-memory" }
func (*blockingBackend) Ping(context.Context) error                 { return nil }
func (*blockingBackend) Connect(context.Context) (net.Conn, error)  { return nil, nil }
func (*blockingBackend) CreateRole(context.Context, api.Role) error { return nil }
func (b *blockingBackend) DropRole(ctx context.Context, name string) error {
	return b.drop(ctx, name)
}
func (b *blockingBackend) Reap(ctx context.Context) ([]string, error) {
	return b.reap(ctx)
}

func TestReapLoopBoundsStalledServiceWithoutDelayingOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stalled := make(chan bool, 1)
		healthy := make(chan struct{}, 1)
		services := map[string]*service{
			"stalled": {advert: api.Service{Name: "stalled"}, backend: &blockingBackend{reap: func(ctx context.Context) ([]string, error) {
				_, bounded := ctx.Deadline()
				stalled <- bounded
				<-ctx.Done()
				return nil, ctx.Err()
			}}},
			"healthy": {advert: api.Service{Name: "healthy"}, backend: &blockingBackend{reap: func(context.Context) ([]string, error) {
				healthy <- struct{}{}
				return nil, nil
			}}},
		}
		a := &Agent{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		a.advertised.Store(&services)
		done := make(chan struct{})
		go func() { a.reapLoop(ctx); close(done) }()
		select {
		case bounded := <-stalled:
			if !bounded {
				t.Error("stalled backend received the unbounded agent context")
			}
		case <-time.After(25 * time.Second):
			t.Error("stalled backend was never reaped")
		}
		select {
		case <-healthy:
		case <-time.After(time.Second):
			t.Error("a stalled service delayed reaping another service")
		}
		cancel()
		<-done
	})
}

func TestHandleCancelsBackendWhenCoordinatorClosesStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		started := make(chan struct{})
		finished := make(chan error, 1)
		b := &blockingBackend{drop: func(ctx context.Context, _ string) error {
			close(started)
			<-ctx.Done()
			finished <- ctx.Err()
			return ctx.Err()
		}}
		services := map[string]*service{"db": {advert: api.Service{Name: "db"}, backend: b}}
		a := &Agent{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		a.advertised.Store(&services)
		server, client := net.Pipe()
		defer client.Close()
		done := make(chan struct{})
		go func() { a.handle(ctx, server); close(done) }()
		if err := tunnel.WriteMessage(client, api.ExitRequest{Op: api.OpDropRole, Service: "db", Role: &api.Role{Name: "tnl_test"}}); err != nil {
			t.Fatal(err)
		}
		<-started
		client.Close()
		select {
		case err := <-finished:
			if err != context.Canceled {
				t.Errorf("backend cancellation = %v, want context canceled", err)
			}
		case <-time.After(time.Second):
			t.Error("closing the request stream did not cancel the backend operation")
		}
		cancel()
		<-done
	})
}

func TestHandleBoundsBackendOperation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := make(chan error, 1)
		b := &blockingBackend{drop: func(ctx context.Context, _ string) error {
			<-ctx.Done()
			finished <- ctx.Err()
			return ctx.Err()
		}}
		services := map[string]*service{"db": {advert: api.Service{Name: "db"}, backend: b}}
		a := &Agent{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		a.advertised.Store(&services)
		server, client := net.Pipe()
		defer client.Close()
		done := make(chan struct{})
		go func() { a.handle(ctx, server); close(done) }()
		if err := tunnel.WriteMessage(client, api.ExitRequest{Op: api.OpDropRole, Service: "db", Role: &api.Role{Name: "tnl_test"}}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-finished:
			if err != context.DeadlineExceeded {
				t.Errorf("backend error = %v, want deadline exceeded", err)
			}
		case <-time.After(25 * time.Second):
			t.Error("backend operation had no deadline before the coordinator timeout")
		}
		client.Close()
		cancel()
		<-done
	})
}
