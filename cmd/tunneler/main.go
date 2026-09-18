// Tunneler is an identity-aware proxy for reaching services inside Kubernetes
// clusters. One binary is the user-facing CLI, the central coordinator, and
// the per-cluster exit node.
//
// Each subcommand lives in the file named after it.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Known before flags are parsed, so that even a flag error is reported
	// in the format that was asked for.
	for i, arg := range os.Args {
		if arg == "--output=json" || arg == "-o=json" || arg == "-ojson" ||
			(arg == "--output" || arg == "-o") && i+1 < len(os.Args) && os.Args[i+1] == "json" {
			outputJSON = true
		}
	}
	if err := rootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(fail(os.Stderr, err))
	}
}

func rootCmd() *cobra.Command {
	var verbose bool
	var output string
	root := &cobra.Command{
		Use:   "tunneler",
		Short: "Identity-aware access to services inside Kubernetes clusters",
		Long: `Identity-aware access to services inside Kubernetes clusters.

Typical use:

  tunneler config --server https://tunneler.example.com
  tunneler auth login
  tunneler services list
  tunneler connect env=prod team=shop -- psql

For scripts and agents:

  --output json   Every command writes its result to stdout as JSON, reports
                  errors on stderr as {"error", "code", "matches"}, and never
                  prompts. "connect" writes one JSON object once it is
                  listening, then events on stderr as JSON lines.
  connect -- CMD  Runs CMD with PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE
                  and DATABASE_URL set, prints no credentials, and revokes the
                  account when CMD exits. Prefer it to parsing credentials:
                    tunneler connect name=orders-db -- psql -Atc 'select 1'
  auth login      Needs a person: it prints a URL and a code for them to use.
                  Check first with "tunneler auth status"; exit status 3 means
                  a login is needed.
  TUNNELER_SERVER Overrides the configured coordinator.

Exit status: 0 success; 1 failure; 2 usage; 3 not logged in; 4 access denied
or no such service; 5 ambiguous selector (the error lists the matches; add
name=... to pick one); 6 service or coordinator unavailable. With
"connect -- CMD", the exit status of CMD.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			switch output {
			case "text":
			case "json":
				outputJSON = true
			default:
				return usageError{fmt.Errorf("--output must be text or json, not %q", output)}
			}
			server := cmd.Parent() != nil && cmd.Parent().Name() == "start"
			log = newLogger(server, verbose)
			return nil
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "log everything that happens, as structured records")
	root.PersistentFlags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })

	auth := &cobra.Command{Use: "auth", Short: "Manage your login"}
	auth.AddCommand(authLoginCmd(), authStatusCmd())
	services := &cobra.Command{Use: "services", Short: "Inspect services"}
	services.AddCommand(servicesListCmd())
	clusters := &cobra.Command{Use: "clusters", Short: "Manage clusters"}
	clusters.AddCommand(clustersForgetCmd())
	sessions := &cobra.Command{Use: "sessions", Short: "Manage sessions"}
	sessions.AddCommand(sessionsListCmd(), sessionsRevokeCmd())
	start := &cobra.Command{Use: "start", Short: "Run a server component"}
	start.AddCommand(startCoordinatorCmd(), startExitCmd())

	root.AddCommand(configCmd(), auth, services, clusters, connectCmd(), sessions, start, versionCmd())
	return root
}
