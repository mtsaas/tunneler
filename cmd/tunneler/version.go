package main

import (
	"errors"
	"io"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/version"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the version of this client and of the coordinator",
		Args:  usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := map[string]string{"client": version.String()}
			defer func() {
				text := "client:      " + out["client"]
				if out["server"] != "" {
					text += "\ncoordinator: " + out["coordinator"] + " (" + out["server"] + ")"
				}
				result(out, text)
			}()
			c, err := loadClient()
			if err != nil || c.state.Server == "" {
				return err
			}
			out["server"] = c.state.Server
			var health struct {
				Version string `json:"version"`
			}
			err = c.do(cmd.Context(), http.MethodGet, "/healthz", "", nil, &health)
			switch {
			case errors.Is(err, io.EOF): // older coordinators answer /healthz with an empty body
				health.Version = "an old build, from before version reporting"
			case err != nil:
				health.Version = "unreachable: " + err.Error()
			}
			out["coordinator"] = health.Version
			return nil
		},
	}
}
