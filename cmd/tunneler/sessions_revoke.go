package main

import (
	"github.com/spf13/cobra"
)

func sessionsRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke ID",
		Short: "End a session and remove its account",
		Args:  usage(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			if err := c.RevokeSession(cmd.Context(), args[0]); err != nil {
				return err
			}
			result(map[string]string{"revoked": args[0]},
				"Session revoked. Its connections are closed and its account is removed.")
			return nil
		},
	}
}
