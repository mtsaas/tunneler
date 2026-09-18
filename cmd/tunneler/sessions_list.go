package main

import (
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/api"
)

func sessionsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your sessions (admins: all sessions)",
		Args:  usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, token, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			var sessions []api.Session
			if err := c.do(cmd.Context(), http.MethodGet, "/v1/sessions", token, nil, &sessions); err != nil {
				return err
			}
			if outputJSON {
				result(sessions, "")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tOWNER\tCLUSTER\tSERVICE\tACCOUNT\tEXPIRES")
			for _, s := range sessions {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.ID, s.Owner, s.Cluster, s.Service, s.Username,
					s.ExpiresAt.Local().Format(time.DateTime))
			}
			return w.Flush()
		},
	}
}
