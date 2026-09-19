package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func sessionsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your sessions (admins: all sessions)",
		Args:  usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			sessions, err := c.Sessions(cmd.Context())
			if err != nil {
				return err
			}
			if outputJSON {
				result(sessions, "")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tOWNER\tCLUSTER\tSERVICE\tACCOUNT\tEXPIRES")
			for _, s := range sessions {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", printable(s.ID), printable(s.Owner), printable(s.Cluster),
					printable(s.Service), printable(s.Username), s.ExpiresAt.Local().Format(time.DateTime))
			}
			return w.Flush()
		},
	}
}
