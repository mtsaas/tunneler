// Package publisher supplies fixed loopback byte streams to a coordinator.
// Public frontend protocols and process supervision belong to its callers.
package publisher

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

type Client interface {
	PublisherControl(context.Context, string) (net.Conn, error)
	PublisherData(context.Context, string, string, string, string) (net.Conn, error)
	PublisherResult(context.Context, string, api.PublisherResult) error
	RenewShare(context.Context, string, string) (*api.Share, error)
}

// Observer receives attachment metadata before startup probes. Process adapters
// can persist ownership for cleanup without changing byte-stream behavior.
type Observer interface{ PublisherAttached(*api.Share) error }

// ValidateTarget rejects names and remote addresses before any local dial.
func ValidateTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid loopback target %q", target)
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("target must be a literal loopback address and port: %q", target)
	}
	return nil
}

// Run attaches once and stays until cancellation or a terminal control failure.
// ready is invoked only after the coordinator has probed every data path. It
// may wait for ownership handoff while the loop continues answering control.
func Run(ctx context.Context, c Client, share *api.Share, targets map[string]string, ready func(context.Context, *api.Share) error) error {
	byID := make(map[string]string, len(share.Services))
	for _, service := range share.Services {
		target, ok := targets[service.Name]
		if !ok {
			return fmt.Errorf("missing local target for service %q", service.Name)
		}
		if err := ValidateTarget(target); err != nil {
			return err
		}
		byID[service.ID] = target
	}
	ctx, cancel := context.WithDeadline(ctx, share.ExpiresAt)
	defer cancel()
	control, err := c.PublisherControl(ctx, share.ID)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	requests := make(map[string]struct{})
	closed := false
	var workers sync.WaitGroup
	track := func(conn net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			conn.Close()
			return false
		}
		connections[conn] = struct{}{}
		return true
	}
	untrack := func(conn net.Conn) {
		mu.Lock()
		delete(connections, conn)
		mu.Unlock()
	}
	defer func() {
		cancel()
		control.SetDeadline(time.Now())
		control.Close()
		mu.Lock()
		closed = true
		for conn := range connections {
			conn.SetDeadline(time.Now())
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	}()

	type received struct {
		message api.PublisherMessage
		err     error
	}
	messages := make(chan received)
	go func() {
		reader := bufio.NewReaderSize(control, 64<<10)
		for {
			line, err := reader.ReadSlice('\n')
			var msg api.PublisherMessage
			if err == nil {
				err = json.Unmarshal(line, &msg)
			}
			select {
			case messages <- received{msg, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	callback := make(chan error, 1)
	var generation string
	var isReady bool
	type renewal struct {
		share *api.Share
		err   error
	}
	renewed := make(chan renewal, 1)
	renew := time.NewTimer(time.Hour)
	defer renew.Stop()
	resetRenew := func(s *api.Share) error {
		left := time.Until(s.AuthorizationDeadline)
		if left <= 0 {
			return errors.New("publisher authorization has expired")
		}
		interval := min(30*time.Second, left/2)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
		renew.Reset(interval)
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-callback:
			if err != nil {
				return err
			}
		case <-renew.C:
			workers.Add(1)
			go func() {
				defer workers.Done()
				rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
				defer rcancel()
				s, err := c.RenewShare(rctx, share.ID, generation)
				renewed <- renewal{s, err}
			}()
		case outcome := <-renewed:
			if outcome.err != nil {
				return fmt.Errorf("renewing publisher authorization: %w", outcome.err)
			}
			if err := resetRenew(outcome.share); err != nil {
				return err
			}
		case received := <-messages:
			if received.err != nil {
				return fmt.Errorf("publisher control ended: %w", received.err)
			}
			msg := received.message
			switch msg.Type {
			case "attached":
				if generation != "" || msg.Generation == "" || msg.Share == nil || msg.Share.ID != share.ID {
					return errors.New("invalid publisher attachment")
				}
				generation = msg.Generation
				msg.Share.Generation = generation
				if observer, ok := c.(Observer); ok {
					if err := observer.PublisherAttached(msg.Share); err != nil {
						return err
					}
				}
				if err := resetRenew(msg.Share); err != nil {
					return err
				}
			case "dial":
				if generation == "" || msg.Generation != generation || msg.ConnectionID == "" {
					return errors.New("invalid publisher dial generation")
				}
				mu.Lock()
				_, duplicate := requests[msg.ConnectionID]
				if !duplicate {
					requests[msg.ConnectionID] = struct{}{}
				}
				mu.Unlock()
				if duplicate {
					return errors.New("duplicate publisher dial")
				}
				workers.Add(1)
				go func(msg api.PublisherMessage) {
					defer workers.Done()
					defer func() { mu.Lock(); delete(requests, msg.ConnectionID); mu.Unlock() }()
					dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
					defer dialCancel()
					var dialErr error
					target, ok := byID[msg.ServiceID]
					if !ok {
						dialErr = errors.New("unknown registered service")
					}
					var local net.Conn
					if dialErr == nil {
						local, dialErr = (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
					}
					if local != nil {
						if !track(local) {
							return
						}
						defer local.Close()
						defer untrack(local)
					}
					var data net.Conn
					if dialErr == nil {
						data, dialErr = c.PublisherData(dialCtx, share.ID, generation, msg.ServiceID, msg.ConnectionID)
					}
					if dialErr != nil {
						_ = c.PublisherResult(dialCtx, share.ID, api.PublisherResult{Generation: generation, ConnectionID: msg.ConnectionID, ServiceID: msg.ServiceID, Error: dialErr.Error()})
						return
					}
					if !track(data) {
						return
					}
					defer data.Close()
					defer untrack(data)
					tunnel.Splice(local, data)
				}(msg)
			case "ready":
				if isReady || generation == "" || msg.Share == nil || msg.Share.ID != share.ID || msg.Share.State != "ready" {
					return errors.New("invalid publisher readiness")
				}
				isReady = true
				msg.Share.Generation = generation
				if ready != nil {
					go func() { callback <- ready(ctx, msg.Share) }()
				}
			case "ping":
				control.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := json.NewEncoder(control).Encode(api.PublisherReply{Type: "pong"}); err != nil {
					return err
				}
			case "ended":
				if msg.Share != nil && (msg.Share.TerminalReason == "expired" || msg.Share.TerminalReason == "stopped") {
					return nil
				}
				return fmt.Errorf("share ended: %s", msg.Error)
			default:
				return fmt.Errorf("unknown publisher control message %q", msg.Type)
			}
		}
	}
}
