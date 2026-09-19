package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

func authLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Log in with your organization's identity provider",
		Long: `Log in with your organization's identity provider.

Prints a URL and a code. Open the URL in any browser and enter the code.`,
		Args: usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, err := loadClient()
			if err != nil {
				return err
			}
			// A person must do the signing in. With JSON output an agent gets
			// what it needs to ask them, and the command then waits as usual.
			err = c.login(ctx, func(da *oauth2.DeviceAuthResponse) {
				result(map[string]any{"event": "device_code", "verification_uri": da.VerificationURI, "user_code": da.UserCode, "expires_at": da.Expiry},
					signInText(da))
			})
			if err != nil {
				return err
			}
			result(map[string]any{"event": "logged_in", "token_expires_at": jwtExpiry(c.state.IDToken), "renewable": c.state.RefreshToken != ""},
				"\nLogged in. To see what you can reach:\n\n    tunneler services list")
			return nil
		},
	}
}

// login signs a person in with the device flow, at the identity provider
// that the coordinator names, and saves the login. It calls prompt with
// where they must go to do so, and returns once they have.
func (c *client) login(ctx context.Context, prompt func(*oauth2.DeviceAuthResponse)) error {
	if c.Server == "" {
		return errors.New("no coordinator configured; run: tunneler config --server URL")
	}
	ac, err := c.AuthConfig(ctx)
	if err != nil {
		return err
	}
	conf, err := oauth(ctx, ac.Issuer, ac.ClientID)
	if err != nil {
		return err
	}
	// The device flow needs no local browser or listener, so it also works
	// over SSH. Entra, Okta, Auth0 and Keycloak all support it.
	da, err := conf.DeviceAuth(ctx)
	if err != nil {
		return err
	}
	prompt(da)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	// The new login replaces the old one whole. Were the old refresh token
	// kept, for want of a new one, it would be sent to the new issuer.
	c.state.Issuer, c.state.ClientID, c.state.RefreshToken = ac.Issuer, ac.ClientID, ""
	return c.storeToken(tok)
}

// signInText tells a person where to sign in.
func signInText(da *oauth2.DeviceAuthResponse) string {
	return fmt.Sprintf("To sign in, open\n\n    %s\n\nand enter the code %s\n\nWaiting for you to finish signing in...", da.VerificationURI, da.UserCode)
}
