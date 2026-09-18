package main

import (
	"github.com/spf13/cobra"
)

func clustersForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget NAME",
		Short: "Release the name of a rebuilt cluster",
		Long: `Release the name of a rebuilt cluster.

A cluster name belongs to the first cluster that uses it. A rebuilt cluster
counts as a new one, and is refused the name until it is released.`,
		Example: `$ tunneler clusters forget prod`,
		Args:    usage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			if err := c.ForgetCluster(cmd.Context(), args[0]); err != nil {
				return err
			}
			result(map[string]string{"released": args[0]},
				"Released. The next cluster to present the name "+args[0]+" will own it.")
			return nil
		},
	}
}
