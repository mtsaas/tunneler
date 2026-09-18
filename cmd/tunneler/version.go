package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/version"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the version of this client and of the coordinator",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Println("client:     ", version.String())
			c, err := loadClient()
			if err != nil || c.state.Server == "" {
				return err
			}
			var health struct {
				Version string `json:"version"`
			}
			err = c.do(cmd.Context(), http.MethodGet, "/healthz", "", nil, &health)
			switch {
			case errors.Is(err, io.EOF): // older coordinators answer /healthz with an empty body
				health.Version = "an old build, from before version reporting"
			case err != nil:
				fmt.Println("coordinator: unreachable:", err)
				return nil
			}
			fmt.Printf("coordinator: %s (%s)\n", health.Version, c.state.Server)
			return nil
		},
	}
}
