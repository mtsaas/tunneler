package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
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
		Use:   "connect [LABEL=VALUE...]",
		Short: "Open a local endpoint for the service matching a label selector",
		Long: `Open a local endpoint for the service matching a label selector.

Name the service by its labels, as many as it takes to match exactly one.
Every service has the labels cluster, kind and name, besides those its
cluster gave it; "tunneler services list" shows them all. If the selector
matches several services, they are listed so you can narrow it.

The coordinator provisions a temporary account for you on the service and
this command prints what your client needs to connect. It then carries
connections until you press Ctrl-C, which revokes the account.`,
		Example: `  tunneler connect cluster=prod team=shop
  tunneler connect cluster=prod,kind=postgres,tier=primary
  tunneler connect --cluster prod --service orders-db`,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			if len(selector) == 0 {
				return errors.New("say which service: tunneler connect LABEL=VALUE... (see: tunneler services list)")
			}
			return connect(cmd.Context(), api.SessionRequest{Selector: selector}, port)
		},
	}
	cmd.Flags().StringVar(&cluster, "cluster", "", "shorthand for the label cluster=NAME")
	cmd.Flags().StringVar(&name, "service", "", "shorthand for the label name=NAME")
	cmd.Flags().IntVar(&port, "port", 0, "local port to listen on (default: any free port)")
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

func connect(ctx context.Context, req api.SessionRequest, port int) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	c, token, err := authed(ctx)
	if err != nil {
		return err
	}
	// Listen before provisioning, so a busy port costs nothing upstream.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Info(fmt.Sprintf("Requesting access to the service labelled %s...", formatLabels(req.Selector)))
	var s api.Session
	err = c.do(ctx, http.MethodPost, "/v1/sessions", token, req, &s)
	if ambiguous := (*api.Error)(nil); errors.As(err, &ambiguous) && len(ambiguous.Matches) > 0 {
		fmt.Printf("\nThe selector %s matches more than one service:\n\n", formatLabels(req.Selector))
		printServices(ambiguous.Matches)
		fmt.Println("\nAdd labels until it matches one; name=... always will.")
		return errors.New("ambiguous selector")
	}
	if err != nil {
		return err
	}
	log.Info(fmt.Sprintf("Access granted to %s/%s: temporary account %s is provisioned.", s.Cluster, s.Service, s.Username), "session", s.ID)
	defer func() {
		// ctx is probably cancelled, by Ctrl-C.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
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
	printSession(&s, ln.Addr().(*net.TCPAddr))
	log.Info(fmt.Sprintf("Listening on %s. Press Ctrl-C to disconnect and revoke the session.", ln.Addr()))

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
		dsn := url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(s.Username, s.Password),
			Host:   addr.String(),
			Path:   "/" + s.Database,
			// The hop to the coordinator is TLS; the loopback hop has no need.
			RawQuery: "sslmode=disable",
		}
		fmt.Printf("\n  URL:       %s\n  psql:      psql '%s'\n", &dsn, &dsn)
	}
	fmt.Printf("\n  Everything you run is audited as %s.\n\n", s.Owner)
}
