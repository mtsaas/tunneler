package main

import (
	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/version"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show client and coordinator versions",
		Args:  usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := map[string]string{"client": version.String()}
			defer func() {
				text := "client:      " + out["client"]
				if out["server"] != "" {
					text += "\ncoordinator: " + printable(out["coordinator"]) + " (" + out["server"] + ")"
				}
				result(out, text)
			}()
			c, err := loadClient()
			if err != nil || c.state.Server == "" {
				return err
			}
			out["server"] = c.state.Server
			coordinatorVersion, err := c.Version(cmd.Context())
			if err != nil {
				coordinatorVersion = "unreachable: " + err.Error()
			}
			out["coordinator"] = coordinatorVersion
			return nil
		},
	}
}
