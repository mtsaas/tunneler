package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/api"
)

func servicesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List services you can reach",
		Long: `List services you can reach, with the labels that select them.

STATUS is "ready" if the service's exit node can connect to it.`,
		Example: `$ tunneler services list
$ tunneler services list --output json`,
		Args: usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			clusters, err := c.Services(cmd.Context())
			if err != nil {
				return err
			}
			if outputJSON {
				result(clusters, "")
				return nil
			}
			if len(clusters) == 0 {
				fmt.Print("No services. Either no exit node is connected, or no grant gives you access to one.\n" +
					"To see which, run:\n\n    tunneler auth status\n\n")
				return nil
			}
			printServices(os.Stdout, clusters, false)
			return nil
		},
	}
}

// printServices writes a table of services and the labels to select them
// by, numbering the rows if asked.
func printServices(out io.Writer, clusters []api.Cluster, numbered bool) {
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	header := "CLUSTER\tSERVICE\tKIND\tSTATUS\tLABELS"
	if numbered {
		header = "\t" + header
	}
	fmt.Fprintln(w, header)
	n := 0
	for _, cl := range clusters {
		for _, svc := range cl.Services {
			status := "ready"
			if !svc.Ready {
				status = "unreachable: " + svc.Status
			}
			if n++; numbered {
				fmt.Fprintf(w, "%d\t", n)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", cl.Name, svc.Name, svc.Kind, status, formatLabels(svc.Labels))
		}
	}
	w.Flush()
}

// formatLabels renders labels as sorted, comma-separated k=v pairs.
func formatLabels(labels map[string]string) string {
	var pairs []string
	for k, v := range labels {
		pairs = append(pairs, k+"="+v)
	}
	slices.Sort(pairs)
	return strings.Join(pairs, ",")
}
