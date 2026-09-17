package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func authLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Sign in through the coordinator's identity provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, err := loadClient()
			if err != nil {
				return err
			}
			conf, err := c.oauth(ctx)
			if err != nil {
				return err
			}
			// The device flow needs no local browser or listener, so it also
			// works over SSH. Entra, Okta, Auth0 and Keycloak all support it.
			da, err := conf.DeviceAuth(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("To sign in, open\n\n    %s\n\nand enter the code %s\n\n", da.VerificationURI, da.UserCode)
			log.Info("Waiting for you to finish signing in...")
			tok, err := conf.DeviceAccessToken(ctx, da)
			if err != nil {
				// Entra's way of saying the app registration is a confidential
				// client. It is the first thing everyone hits.
				if strings.Contains(err.Error(), "AADSTS7000218") {
					return fmt.Errorf("the app registration does not allow public clients, which a CLI must be; "+
						"in Entra set Authentication > Allow public client flows to Yes\n\n%w", err)
				}
				return err
			}
			if err := c.storeToken(tok); err != nil {
				return err
			}
			log.Info("Logged in.", "token_expires", jwtExpiry(c.state.IDToken), "refreshable", c.state.RefreshToken != "")
			return nil
		},
	}
}
