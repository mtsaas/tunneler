package main

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

func configCmd() *cobra.Command {
	var server string
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Set the coordinator to use",
		Example: `$ tunneler config --server https://tunneler.example.com
$ tunneler config`,
		Args: usage(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			c, err := loadClient()
			if err != nil {
				return err
			}
			if server == "" {
				result(map[string]string{"server": c.state.Server, "file": c.path}, "server: "+c.state.Server)
				return nil
			}
			u, err := url.Parse(server)
			if err != nil {
				return err
			}
			// Bearer tokens and database passwords cross this connection.
			loopback := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()
			if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
				return errors.New("--server must be an https:// URL")
			}
			c.state.Server = strings.TrimRight(server, "/")
			c.state.IDToken, c.state.RefreshToken = "", "" // they belonged to the old server
			if err := c.save(); err != nil {
				return err
			}
			result(map[string]string{"server": c.state.Server, "file": c.path},
				"Saved. Run the following to authenticate:\n\n    tunneler auth login")
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "URL of the coordinator")
	return cmd
}
