package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
)

// connectOptions are connect's flags. Which apply depends on the kind of
// the service the selector turns out to match.
type connectOptions struct {
	command []string // after "--"
	port    int      // session kinds
	context string   // kubernetes
	noUse   bool     // kubernetes
}

// connectors says how connect reaches a service of each kind. It is the
// CLI's part of a kind, beside the coordinator's and the exit node's.
var connectors = map[string]func(ctx context.Context, c *client, cluster string, svc api.Service, opts connectOptions) error{
	"postgres":   connectSession,
	"kubernetes": connectKubernetes,
}

func connectCmd() *cobra.Command {
	var cluster, name string
	var opts connectOptions
	use := true
	cmd := &cobra.Command{
		Use:   "connect [LABEL=VALUE...] [-- COMMAND [ARG...]]",
		Short: "Connect to a service",
		Long: `Connect to a service.

What connecting means depends on the kind of service.

postgres: creates a temporary account for you, and opens a local port for
your database tool. Ctrl-C disconnects and removes the account. The port for
a service is the same every time.

kubernetes: adds a context to your kubeconfig, and exits. kubectl and other
tools then reach the cluster through the coordinator, as you. The context
holds no credential; kubectl gets your login from tunneler when it needs it.

With "-- COMMAND", runs the command with the connection in its environment
instead, and leaves nothing behind when it exits.

Everything you do is logged with your identity.`,
		Annotations: map[string]string{
			helpArguments: selectorArguments + `

After "--": a command to run. See "tunneler help environment".`,
			helpJSON: `postgres:   {"event": "listening", "host", "port", "url", "session", "notice"}
kubernetes: {"event": "configured", "context", "kubeconfig", "server", "notice"}`,
		},
		Example: `$ tunneler connect cluster=prod team=shop
$ tunneler connect env=preview-123 -- psql
$ tunneler connect cluster=prod kind=kubernetes
$ tunneler connect cluster=prod kind=kubernetes -- kubectl get pods
$ tunneler connect`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if n := cmd.ArgsLenAtDash(); n >= 0 {
				args, opts.command = args[:n], args[n:]
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
			opts.noUse = !use
			return connect(cmd.Context(), selector, opts)
		},
	}
	cmd.Flags().StringVar(&cluster, "cluster", "", "Same as the label cluster=NAME")
	cmd.Flags().StringVar(&name, "service", "", "Same as the label name=NAME")
	cmd.Flags().IntVar(&opts.port, "port", 0, "postgres: local port to listen on (default: fixed per service)")
	cmd.Flags().StringVar(&opts.context, "context", "", "kubernetes: name of the context (default: tunneler-CLUSTER)")
	cmd.Flags().BoolVar(&use, "use", true, "kubernetes: make the context current")
	return cmd
}

// parseSelector reads label=value pairs, separated by commas or given as
// separate arguments.
func parseSelector(args []string) (map[string]string, error) {
	selector := make(map[string]string)
	for _, pair := range strings.FieldsFunc(strings.Join(args, ","), func(r rune) bool { return r == ',' }) {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || k == "" || v == "" {
			return nil, usageError{fmt.Errorf("malformed selector %q: want LABEL=VALUE", pair)}
		}
		selector[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return selector, nil
}

// connect finds the one service the selector names and reaches it in the
// way of its kind.
func connect(ctx context.Context, selector map[string]string, opts connectOptions) error {
	c, err := authed(ctx)
	if err != nil {
		return err
	}
	clusters, err := c.Services(ctx)
	if err != nil {
		return err
	}
	cluster, svc, err := selectService(clusters, selector)
	if err != nil {
		return err
	}
	if !svc.Ready {
		return &api.Error{Status: 503, Message: fmt.Sprintf("%s/%s is registered but its exit node cannot reach it: %s", cluster, svc.Name, svc.Status)}
	}
	connector := connectors[svc.Kind]
	if connector == nil {
		return fmt.Errorf("this version of tunneler cannot connect to services of kind %q; upgrade it", svc.Kind)
	}
	return connector(ctx, c, cluster, svc, opts)
}

// selectService returns the one service the selector matches. If it matches
// several, a person at a terminal is asked to pick; otherwise the error
// lists the matches, as the coordinator's own does.
func selectService(clusters []api.Cluster, selector map[string]string) (cluster string, svc api.Service, err error) {
	var matches []api.Cluster
	var choices []api.Service
	var owners []string
	for _, cl := range clusters {
		var services []api.Service
		for _, s := range cl.Services {
			if (coordinator.Grant{Labels: selector}).Matches(s.Labels) {
				services = append(services, s)
				choices, owners = append(choices, s), append(owners, cl.Name)
			}
		}
		if len(services) > 0 {
			matches = append(matches, api.Cluster{Name: cl.Name, Services: services})
		}
	}
	switch len(choices) {
	case 0:
		what := "matches " + formatLabels(selector)
		if len(selector) == 0 {
			what = "is connected"
		}
		return "", api.Service{}, &api.Error{Status: 403, Message: "no service you have access to " + what + "; see: tunneler services list"}
	case 1:
		return owners[0], choices[0], nil
	}

	ambiguous := &api.Error{
		Status:  409,
		Message: fmt.Sprintf("the selector matches %d services; add labels until it matches one (name=... always will)", len(choices)),
		Matches: matches,
	}
	if !outputJSON {
		fmt.Fprintf(os.Stderr, "More than one service matches:\n\n")
		printServices(os.Stderr, matches, true)
		fmt.Fprintln(os.Stderr)
	}
	if !interactive() {
		return "", api.Service{}, ambiguous
	}
	fmt.Fprintf(os.Stderr, "Which one? [1-%d]: ", len(choices))
	var n int
	if _, err := fmt.Fscanln(os.Stdin, &n); err != nil || n < 1 || n > len(choices) {
		return "", api.Service{}, ambiguous // no usable answer leaves the selector ambiguous
	}
	return owners[n-1], choices[n-1], nil
}
