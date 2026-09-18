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
		Args:  usage(cobra.NoArgs),
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
			// A person must do this part. With JSON output an agent gets what it
			// needs to ask them, and the command then waits as usual.
			result(map[string]any{"event": "device_code", "verification_uri": da.VerificationURI, "user_code": da.UserCode, "expires_at": da.Expiry},
				fmt.Sprintf("To sign in, open\n\n    %s\n\nand enter the code %s\n\nWaiting for you to finish signing in...", da.VerificationURI, da.UserCode))
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
			result(map[string]any{"event": "logged_in", "token_expires_at": jwtExpiry(c.state.IDToken), "renewable": c.state.RefreshToken != ""},
				"\nLogged in. To see what you can reach:\n\n    tunneler services list")
			return nil
		},
	}
}
