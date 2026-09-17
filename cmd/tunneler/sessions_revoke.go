package main

import (
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
)

func sessionsRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke ID",
		Short: "End a session: disconnect it and drop its account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, token, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			err = c.do(cmd.Context(), http.MethodDelete, "/v1/sessions/"+url.PathEscape(args[0]), token, nil, nil)
			if err != nil {
				return err
			}
			log.Info("Session revoked: its connections are closed and its account dropped.", "session", args[0])
			return nil
		},
	}
}
