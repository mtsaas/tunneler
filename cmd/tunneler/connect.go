package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

func connectCmd() *cobra.Command {
	var cluster, name string
	var port int
	cmd := &cobra.Command{
		Use:   "connect [LABEL=VALUE...] [-- COMMAND [ARG...]]",
		Short: "Open a local endpoint for a service, or run a command against it",
		Long: `Open a local endpoint for a service, or run a command against it.

Name the service by its labels, as many as it takes to match exactly one.
Every service has the labels cluster, kind and name, besides those its
cluster gave it; "tunneler services list" shows them all. If the selector
matches several services, you are asked to pick one.

The coordinator provisions a temporary account for you on the service. With
no command, this prints what your client needs to connect, then carries
connections until you press Ctrl-C, which revokes the account. The local
port is the same every time for a given service, so a connection saved in a
database tool keeps working; only the user and password change.

With a command after "--", the command runs with the connection in its
environment (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE and
DATABASE_URL), nothing is printed, and the account is revoked when the
command exits.`,
		Example: `  tunneler connect cluster=prod team=shop
  tunneler connect env=preview-123 -- psql
  tunneler connect name=orders-db -- pg_dump --schema-only -f schema.sql
  tunneler connect`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var command []string
			if n := cmd.ArgsLenAtDash(); n >= 0 {
				args, command = args[:n], args[n:]
			}
			selector, err := parseSelector(args)
			if err != nil {
				return err
			}
			// Shorthands for the two labels every service has.
			if cluster != "" {
				selector["cluster"] = cluster
			}
			if name != "" {
				selector["name"] = name
			}
			return connect(cmd.Context(), selector, port, command)
		},
	}
	cmd.Flags().StringVar(&cluster, "cluster", "", "shorthand for the label cluster=NAME")
	cmd.Flags().StringVar(&name, "service", "", "shorthand for the label name=NAME")
	cmd.Flags().IntVar(&port, "port", 0, "local port to listen on (default: one derived from the service's name)")
	return cmd
}

// parseSelector reads label=value pairs, separated by commas or given as
// separate arguments.
func parseSelector(args []string) (map[string]string, error) {
	selector := make(map[string]string)
	for _, pair := range strings.FieldsFunc(strings.Join(args, ","), func(r rune) bool { return r == ',' }) {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("malformed selector %q: want LABEL=VALUE", pair)
		}
		selector[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return selector, nil
}

func connect(ctx context.Context, selector map[string]string, port int, command []string) error {
	if len(command) > 0 {
		// Ctrl-C belongs to the command, which shares our terminal and gets
		// the signal too: psql uses it to cancel a query. The session ends
		// when the command does.
		ctx = context.WithoutCancel(ctx)
		if !log.Enabled(ctx, slog.LevelDebug) {
			log = slog.New(statusHandler{w: os.Stderr, mu: new(sync.Mutex), min: slog.LevelWarn})
		}
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	c, token, err := authed(ctx)
	if err != nil {
		return err
	}
	// An explicit port is claimed before provisioning, so that finding it
	// busy costs nothing upstream.
	var ln net.Listener
	if port != 0 {
		if ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
			return err
		}
		defer ln.Close()
	}

	s, err := c.createSession(ctx, token, selector)
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
		token, err := c.token(ctx)
		if err == nil {
			err = c.do(ctx, http.MethodDelete, "/v1/sessions/"+s.ID, token, nil, nil)
		}
		if err != nil {
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
		return runCommand(ctx, command, s, addr)
	}
	printSession(s, addr)
	log.Info(fmt.Sprintf("Listening on %s. Press Ctrl-C to disconnect and revoke the session.", addr))
	select {
	case <-ctx.Done():
		if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
			return err
		}
	case <-time.After(time.Until(s.ExpiresAt)):
		log.Info("The session has reached its expiry.")
	}
	return nil
}

// createSession asks for a session on the service the selector matches. If
// it matches several and there is a person to ask, they pick one.
func (c *client) createSession(ctx context.Context, token string, selector map[string]string) (*api.Session, error) {
	for {
		what := "the service labelled " + formatLabels(selector)
		if len(selector) == 0 {
			what = "the only service you can reach"
		}
		log.Info(fmt.Sprintf("Requesting access to %s...", what))
		var s api.Session
		err := c.do(ctx, http.MethodPost, "/v1/sessions", token, api.SessionRequest{Selector: selector}, &s)
		ambiguous := (*api.Error)(nil)
		if !errors.As(err, &ambiguous) || len(ambiguous.Matches) == 0 {
			return &s, err
		}

		var choices []map[string]string
		for _, cl := range ambiguous.Matches {
			for _, svc := range cl.Services {
				choices = append(choices, map[string]string{"cluster": cl.Name, "name": svc.Name})
			}
		}
		fmt.Fprintf(os.Stderr, "\nMore than one service matches:\n\n")
		printServices(os.Stderr, ambiguous.Matches, true)
		if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			fmt.Fprintln(os.Stderr, "\nAdd labels until the selector matches one; name=... always will.")
			return nil, errors.New("ambiguous selector")
		}
		fmt.Fprintf(os.Stderr, "\nWhich one? [1-%d]: ", len(choices))
		var n int
		if _, err := fmt.Fscanln(os.Stdin, &n); err != nil || n < 1 || n > len(choices) {
			return nil, errors.New("no service chosen")
		}
		selector = choices[n-1]
	}
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

// runCommand runs a command with the session in its environment, until it
// exits or the session ends.
func runCommand(ctx context.Context, command []string, s *api.Session, addr *net.TCPAddr) error {
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

// watchSession follows the session's event stream until the coordinator
// reports that the session ended, and returns the reason. An interrupted
// stream is reopened; a session that no longer exists counts as ended.
// It returns "" only when ctx is done first.
func (c *client) watchSession(ctx context.Context, sessionID string) string {
	backoff := time.Second
	for ctx.Err() == nil {
		reason, err := c.followEvents(ctx, sessionID)
		if reason != "" {
			return reason
		}
		if status := (*api.Error)(nil); errors.As(err, &status) {
			return "it was revoked, or your access was withdrawn" // a 4xx: the session is gone
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

func (c *client) followEvents(ctx context.Context, sessionID string) (reason string, err error) {
	token, err := c.token(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.state.Server+"/v1/sessions/"+sessionID+"/events", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e := &api.Error{Message: resp.Status}
		json.NewDecoder(resp.Body).Decode(e)
		return "", e
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev api.SessionEvent
		if err := dec.Decode(&ev); err != nil {
			return "", err
		}
		if ev.Ended {
			return ev.Reason, nil
		}
	}
}

// forward carries one local connection, the n'th, to the coordinator. It
// returns an error only if the session as a whole is over.
func (c *client) forward(ctx context.Context, local net.Conn, sessionID string, n int64) error {
	defer local.Close()
	log.Info(fmt.Sprintf("Connection %d: opened by a local client; tunneling to the coordinator.", n), "local", local.RemoteAddr())

	token, err := c.token(ctx)
	if err != nil {
		log.Error(fmt.Sprintf("Connection %d: failed", n), "err", err)
		return nil
	}
	start := time.Now()
	stream, err := tunnel.Dial(ctx, c.state.Server+"/v1/sessions/"+sessionID+"/connect",
		http.Header{"Authorization": {"Bearer " + token}})
	if status := (*tunnel.StatusError)(nil); errors.As(err, &status) &&
		(status.Code == http.StatusNotFound || status.Code == http.StatusForbidden) {
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

// printSession writes what a client program needs in order to connect.
func printSession(s *api.Session, addr *net.TCPAddr) {
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
	fmt.Printf("\n  Everything you run is audited as %s.\n\n", s.Owner)
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
