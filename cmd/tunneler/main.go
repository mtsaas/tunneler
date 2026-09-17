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
	if err := rootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "tunneler:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var verbose bool
	root := &cobra.Command{
		Use:           "tunneler",
		Short:         "Identity-aware access to services inside Kubernetes clusters",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			server := cmd.Parent() != nil && cmd.Parent().Name() == "start"
			log = newLogger(server, verbose)
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "log everything that happens, as structured records")

	auth := &cobra.Command{Use: "auth", Short: "Manage your login"}
	auth.AddCommand(authLoginCmd(), authStatusCmd())
	clusters := &cobra.Command{Use: "clusters", Short: "Inspect clusters"}
	clusters.AddCommand(clustersListCmd())
	sessions := &cobra.Command{Use: "sessions", Short: "Manage sessions"}
	sessions.AddCommand(sessionsListCmd(), sessionsRevokeCmd())
	start := &cobra.Command{Use: "start", Short: "Run a server component"}
	start.AddCommand(startCoordinatorCmd(), startExitCmd())

	root.AddCommand(configCmd(), auth, clusters, connectCmd(), sessions, start)
	return root
}
