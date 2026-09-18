package main

import (
	"fmt"
	"net/http"
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
		Short: "List the services you can reach",
		Long: `List the services you can reach, with the labels to select them by.

A service is listed while an exit node of its cluster is connected to the
coordinator and your grants reach it. STATUS says whether that exit node can
currently connect to it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, token, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			var clusters []api.Cluster
			if err := c.do(cmd.Context(), http.MethodGet, "/v1/clusters", token, nil, &clusters); err != nil {
				return err
			}
			if len(clusters) == 0 {
				log.Info("Nothing to list. Either no exit node is connected, or none of your groups is granted access to " +
					"any service. To see which, run: tunneler auth status")
				return nil
			}
			printServices(clusters)
			return nil
		},
	}
}

// printServices writes a table of services and the labels to select them by.
func printServices(clusters []api.Cluster) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "CLUSTER\tSERVICE\tKIND\tSTATUS\tLABELS")
	for _, cl := range clusters {
		for _, svc := range cl.Services {
			status := "ready"
			if !svc.Ready {
				status = "unreachable: " + svc.Status
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
