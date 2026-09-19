package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func authStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show your login and what it lets you reach",
		Long: `Show your login and what it lets you reach.

Shows, in order: the token from the identity provider, how the coordinator
reads it, the grants that apply to you, and the services those grants reach.
If you cannot reach a service, the first section that looks wrong says why.

Exits with 3 if you are not logged in.`,
		Args: usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := authed(cmd.Context())
			if err != nil {
				return err
			}
			token, _ := c.token(cmd.Context())

			if outputJSON {
				st, err := c.AuthStatus(cmd.Context())
				if err != nil {
					return err
				}
				result(map[string]any{
					"server":           c.state.Server,
					"token_expires_at": jwtExpiry(token),
					"renewable":        c.state.RefreshToken != "",
					"identity":         st,
				}, "")
				return nil
			}
			fmt.Printf("Coordinator: %s\n\n", c.state.Server)
			fmt.Println("1. Your ID token, as the identity provider issued it")
			fmt.Printf("   expires %s; %s\n\n", jwtExpiry(token).Local().Format(time.DateTime),
				map[bool]string{true: "renews itself with a refresh token", false: "no refresh token, so you will need to log in again"}[c.state.RefreshToken != ""])
			printClaims(token)

			st, err := c.AuthStatus(cmd.Context())
			if err != nil {
				return fmt.Errorf("the coordinator did not accept the token: %w", err)
			}
			fmt.Println("\n2. You, as the coordinator sees you")
			groups := make([]string, len(st.Groups))
			for i, g := range st.Groups {
				groups[i] = printable(g)
			}
			fmt.Printf("   subject:   %s\n   user id:   %s\n   username:  %s\n   admin:     %t\n   groups:    %s\n",
				printable(st.Subject), printable(st.UserID), printable(st.Username), st.Admin, orNone(strings.Join(groups, "\n              ")))
			if len(st.Groups) == 0 {
				fmt.Println("\n   Without groups only a grant naming your user id or username can apply. The token\n" +
					"   above has no groups claim: in Entra, add one to ID tokens under Token configuration.")
			}

			fmt.Println("\n3. Grants that apply to you")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "   VIA\tREACHES SERVICES LABELLED\tWITH ROLES")
			for _, g := range st.Grants {
				via := "group " + g.Group
				if g.User != "" {
					via = "user " + g.User
				}
				fmt.Fprintf(w, "   %s\t%s\t%s\n", printable(via), printable(formatLabels(g.Labels)), printable(orNone(strings.Join(g.Roles, ","))))
			}
			w.Flush()
			if len(st.Grants) == 0 {
				fmt.Println("   (none: no grant in the coordinator's configuration names you or one of your groups)")
			}

			fmt.Println("\n4. Services those grants reach right now")
			fmt.Fprintln(w, "   CLUSTER\tSERVICE\tKIND\tSTATUS\tLABELS")
			for _, cl := range st.Clusters {
				for _, svc := range cl.Services {
					fmt.Fprintf(w, "   %s\n", serviceRow(cl.Name, svc))
				}
			}
			w.Flush()
			if len(st.Clusters) == 0 {
				fmt.Println("   (none: either no exit node is connected, or no connected service carries the labels above)")
			}
			return nil
		},
	}
}

// printClaims prints a JWT's claims. They are not verified here; section 2
// of the output is the coordinator's verified reading of the same token.
// encoding/json escapes C0 controls in them but not C1 or bidi ones, so
// each line is made printable too.
func printClaims(token string) {
	var claims map[string]any
	if parts := strings.Split(token, "."); len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		json.Unmarshal(payload, &claims)
	}
	out, _ := json.MarshalIndent(claims, "", "  ")
	for line := range strings.Lines(string(out)) {
		fmt.Printf("   %s\n", printable(strings.TrimSuffix(line, "\n")))
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
