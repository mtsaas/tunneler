package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func clustersListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List cluster names and the clusters that own them",
		Long: `List cluster names and the clusters that own them.

A cluster name belongs to the first cluster that uses it, identified by its
OIDC issuer. Exit nodes from any other issuer are refused the name. If a
rebuilt cluster is refused, compare its issuer with the one listed here, then
release the name with "tunneler clusters forget".`,
		Args: usage(cobra.NoArgs),
		Example: `$ tunneler clusters list
$ tunneler clusters list --output json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			bindings, err := c.ClusterBindings(cmd.Context())
			if err != nil {
				return err
			}
			if outputJSON {
				result(bindings, "")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "CLUSTER\tEXIT NODES\tOWNED BY ISSUER")
			for _, b := range bindings {
				issuer := b.Issuer
				if issuer == "" {
					issuer = "(not bound: its exit nodes do not use a cluster token)"
				}
				fmt.Fprintf(w, "%s\t%d\t%s\n", b.Name, b.ExitNodes, issuer)
			}
			return w.Flush()
		},
	}
}
