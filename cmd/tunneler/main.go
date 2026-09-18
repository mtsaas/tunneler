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
		Use:           "tunneler",
		Short:         "Reach services inside Kubernetes clusters with your own login.",
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
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Log everything that happens")
	root.PersistentFlags().StringVarP(&output, "output", "o", "text", "Output `format`: text or json")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })

	root.SetHelpFunc(help)
	root.AddGroup(
		&cobra.Group{ID: groupCore, Title: "CORE COMMANDS"},
		&cobra.Group{ID: groupServer, Title: "SERVER COMMANDS"},
	)
	root.Example = `$ tunneler config --server https://tunneler.example.com
$ tunneler auth login
$ tunneler services list
$ tunneler connect cluster=prod team=shop -- psql`

	group := func(id, name, short string, subs ...*cobra.Command) *cobra.Command {
		cmd := &cobra.Command{Use: name, Short: short, GroupID: id}
		cmd.AddCommand(subs...)
		return cmd
	}
	config, connect := configCmd(), connectCmd()
	config.GroupID, connect.GroupID = groupCore, groupCore
	root.AddCommand(
		group(groupCore, "auth", "Log in and check your access", authLoginCmd(), authStatusCmd()),
		config,
		connect,
		group(groupCore, "services", "List services you can reach", servicesListCmd()),
		group(groupCore, "sessions", "List and revoke sessions", sessionsListCmd(), sessionsRevokeCmd()),
		group(groupServer, "start", "Run the coordinator or an exit node", startCoordinatorCmd(), startExitCmd()),
		group("", "clusters", "Manage cluster names", clustersForgetCmd()),
		versionCmd(),
	)
	root.AddCommand(helpTopics()...)
	root.InitDefaultCompletionCmd()
	if completion, _, err := root.Find([]string{"completion"}); err == nil {
		completion.Short = "Generate shell completion scripts"
	}
	return root
}
