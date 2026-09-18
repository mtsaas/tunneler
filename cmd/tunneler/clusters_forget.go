package main

import (
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
)

func clustersForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget NAME",
		Short: "Release a cluster name bound to a rebuilt cluster's old issuer (admins)",
		Long: `Release a cluster name bound to a rebuilt cluster's old issuer.

When exit nodes authenticate with their cluster's service account tokens,
the coordinator binds each cluster name to the first issuer that presents
it and refuses the name to any other. A rebuilt cluster has a new issuer,
so its exit nodes are refused until an admin releases the name.`,
		Args: usage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, token, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			err = c.do(cmd.Context(), http.MethodDelete, "/v1/clusters/"+url.PathEscape(args[0])+"/binding", token, nil, nil)
			if err != nil {
				return err
			}
			result(map[string]string{"released": args[0]},
				"Released. The next cluster to present the name "+args[0]+" will own it.")
			return nil
		},
	}
}
