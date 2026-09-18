package main

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

// connectSession reaches a service of a kind with sessions, such as a
// database: the coordinator provisions a temporary account, and a local port
// carries connections to it until the person disconnects or the command
// exits, which revokes the account.
func connectSession(ctx context.Context, c *client, cluster string, svc api.Service, opts connectOptions) error {
	port, command := opts.port, opts.command
	if opts.context != "" || opts.noUse {
		return usageError{fmt.Errorf("--context and --use apply to kubernetes services, and %s is %s", svc.Name, svc.Kind)}
	}
	if len(command) > 0 {
		// Ctrl-C belongs to the command, which shares our terminal and gets
		// the signal too: psql uses it to cancel a query. The session ends
		// when the command does.
		ctx = context.WithoutCancel(ctx)
		if !log.Enabled(ctx, slog.LevelDebug) {
			log = slog.New(statusHandler{w: os.Stderr, mu: new(sync.Mutex), min: slog.LevelWarn})
		}
	}
	parent := ctx // done when the person interrupts us, which is not a failure
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var err error
	// An explicit port is claimed before provisioning, so that finding it
	// busy costs nothing upstream.
	var ln net.Listener
	if port != 0 {
		if ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
			return err
		}
		defer ln.Close()
	}

	log.Info(fmt.Sprintf("Requesting access to %s/%s...", cluster, svc.Name))
	s, err := c.CreateSession(ctx, map[string]string{"cluster": cluster, "name": svc.Name})
	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("Access granted to %s/%s: temporary account %s is provisioned.", s.Cluster, s.Service, s.Username), "session", s.ID)
	var ended atomic.Bool
	defer func() {
		// ctx is probably cancelled, by Ctrl-C.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if ended.Load() {
			return // the coordinator already ended it
		}
		log.Info("Disconnecting and revoking the session...")
		if err := c.RevokeSession(ctx, s.ID); err != nil {
			log.Warn("Could not revoke the session; it will end on its own at "+s.ExpiresAt.Local().Format(time.TimeOnly), "err", err)
			return
		}
		log.Info("Session revoked.")
	}()
	go func() {
		reason := c.watchSession(ctx, s.ID)
		if reason != "" {
			ended.Store(true)
			cancel(fmt.Errorf("the coordinator ended the session: %s", reason))
		}
	}()

	if ln == nil {
		if ln, err = listenStable(s); err != nil {
			return err
		}
		defer ln.Close()
	}
	addr := ln.Addr().(*net.TCPAddr)
	go func() {
		var n atomic.Int64
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if err := c.forward(ctx, conn, s.ID, n.Add(1)); err != nil {
					cancel(err)
				}
			}()
		}
	}()

	if len(command) > 0 {
		if !outputJSON {
			fmt.Fprintf(os.Stderr, "%s\n\n", auditNotice(s))
		}
		return runSessionCommand(ctx, command, s, addr)
	}
	if outputJSON {
		// One object, once connections are accepted: the signal to proceed.
		result(map[string]any{
			"event": "listening", "session": s, "host": addr.IP.String(), "port": addr.Port, "url": sessionURL(s, addr),
			"notice": auditNotice(s),
		}, "")
	} else {
		printSession(s, addr)
	}
	log.Info(fmt.Sprintf("Listening on %s. Press Ctrl-C to disconnect and revoke the session.", addr))
	select {
	case <-ctx.Done():
		if parent.Err() == nil {
			return context.Cause(ctx) // the session ended under us, and this says why
		}
	case <-time.After(time.Until(s.ExpiresAt)):
		log.Info("The session has reached its expiry.")
	}
	return nil
}

// listenStable listens on the loopback port derived from the service's
// name, so that the endpoint is the same from one session to the next, or on
// any free port if that one is taken.
func listenStable(s *api.Session) (net.Listener, error) {
	h := fnv.New32a()
	h.Write([]byte(s.Cluster + "/" + s.Service))
	port := 49152 + h.Sum32()%16384 // the dynamic range, where nothing is registered
	if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		return ln, nil
	}
	log.Warn(fmt.Sprintf("The usual port for this service, %d, is in use; using another.", port))
	return net.Listen("tcp", "127.0.0.1:0")
}

// runSessionCommand runs a command with the session in its environment,
// until it exits or the session ends.
func runSessionCommand(ctx context.Context, command []string, s *api.Session, addr *net.TCPAddr) error {
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = append(os.Environ(),
		"PGHOST="+addr.IP.String(),
		fmt.Sprintf("PGPORT=%d", addr.Port),
		"PGUSER="+s.Username,
		"PGPASSWORD="+s.Password,
		"PGDATABASE="+s.Database,
		"PGSSLMODE=disable", // the hop to the coordinator is TLS; the loopback hop has no need
		"DATABASE_URL="+sessionURL(s, addr),
	)
	err := child.Run()
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause // the session ended under the command
	}
	return err
}

// watchSession follows the session's events until the coordinator reports
// that the session ended, and returns the reason. An interrupted stream is
// reopened; a session that no longer exists counts as ended. It returns ""
// only when ctx is done first.
func (c *client) watchSession(ctx context.Context, sessionID string) string {
	backoff := time.Second
	for ctx.Err() == nil {
		reason, err := c.WatchSession(ctx, sessionID)
		if reason != "" {
			return reason
		}
		if gone := (*api.Error)(nil); errors.As(err, &gone) {
			return "it was revoked, or your access was withdrawn"
		}
		if ctx.Err() != nil {
			return ""
		}
		log.Debug("session event stream interrupted; reconnecting", "err", err, "in", backoff.String())
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
		}
		backoff = min(2*backoff, 30*time.Second)
	}
	return ""
}

// forward carries one local connection, the n'th, to the coordinator. It
// returns an error only if the session as a whole is over.
func (c *client) forward(ctx context.Context, local net.Conn, sessionID string, n int64) error {
	defer local.Close()
	log.Info(fmt.Sprintf("Connection %d: opened by a local client; tunneling to the coordinator.", n), "local", local.RemoteAddr())

	start := time.Now()
	stream, err := c.DialSession(ctx, sessionID)
	if refused := (*api.Error)(nil); errors.As(err, &refused) &&
		(refused.Status == http.StatusNotFound || refused.Status == http.StatusForbidden) {
		return errors.New("the coordinator no longer honors this session: it was revoked, or your access was withdrawn")
	}
	if err != nil {
		log.Error(fmt.Sprintf("Connection %d: could not reach the coordinator", n), "err", err)
		return nil
	}
	log.Debug("tunnel established", "connection", n, "took", time.Since(start).Round(time.Millisecond).String())
	tunnel.Splice(local, stream)
	log.Info(fmt.Sprintf("Connection %d: closed after %s.", n, time.Since(start).Round(time.Second)))
	return nil
}

// auditNotice tells the person, every time a session starts, that what they
// do in it is recorded under their name.
func auditNotice(s *api.Session) string {
	return fmt.Sprintf("NOTICE: This session is audited. Every query you run is logged with your identity (%s).", s.Owner)
}

// printSession writes what a client program needs in order to connect.
func printSession(s *api.Session, addr *net.TCPAddr) {
	fmt.Printf("\n%s\n", auditNotice(s))
	fmt.Printf("\n  Host:      %s\n  Port:      %d\n", addr.IP, addr.Port)
	if s.Database != "" {
		fmt.Printf("  Database:  %s\n", s.Database)
	}
	fmt.Printf("  User:      %s\n  Password:  %s\n  Expires:   %s\n",
		s.Username, s.Password, s.ExpiresAt.Local().Format(time.DateTime))

	if s.Kind == "postgres" {
		dsn := sessionURL(s, addr)
		fmt.Printf("\n  URL:       %s\n  psql:      psql '%s'\n", dsn, dsn)
	}
	fmt.Println()
}

// sessionURL returns the connection URL for the session's local endpoint.
func sessionURL(s *api.Session, addr *net.TCPAddr) string {
	u := url.URL{
		Scheme: s.Kind,
		User:   url.UserPassword(s.Username, s.Password),
		Host:   addr.String(),
		Path:   "/" + s.Database,
		// The hop to the coordinator is TLS; the loopback hop has no need.
		RawQuery: "sslmode=disable",
	}
	return u.String()
}
