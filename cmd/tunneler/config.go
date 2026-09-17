package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

func configCmd() *cobra.Command {
	var server string
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or set the coordinator to talk to",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			c, err := loadClient()
			if err != nil {
				return err
			}
			if server == "" {
				fmt.Println("server:", c.state.Server)
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
			log.Info("Saved. Next: tunneler auth login", "file", c.path)
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "coordinator URL")
	return cmd
}
