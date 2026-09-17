package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mtsaas/tunneler/internal/api"
)

func authStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show who you are logged in as and what that lets you reach",
		Long: `Show who you are logged in as and what that lets you reach.

The output follows a login through the system: the claims the identity
provider put in your token, what the coordinator makes of them, which grants
your groups satisfy, and which services those grants reach right now. When
you cannot reach something, the first section that looks wrong says why.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, token, err := authed(cmd.Context())
			if err != nil {
				return err
			}

			fmt.Printf("Coordinator: %s\n\n", c.state.Server)
			fmt.Println("1. Your ID token, as the identity provider issued it")
			fmt.Printf("   expires %s; %s\n\n", jwtExpiry(token).Local().Format(time.DateTime),
				map[bool]string{true: "renews itself with a refresh token", false: "no refresh token, so you will need to log in again"}[c.state.RefreshToken != ""])
			printClaims(token)

			var st api.AuthStatus
			if err := c.do(cmd.Context(), http.MethodGet, "/v1/auth/status", token, nil, &st); err != nil {
				return fmt.Errorf("the coordinator did not accept the token: %w", err)
			}
			fmt.Println("\n2. You, as the coordinator sees you")
			fmt.Printf("   subject:   %s\n   user id:   %s\n   username:  %s\n   admin:     %t\n   groups:    %s\n",
				st.Subject, st.UserID, st.Username, st.Admin, orNone(strings.Join(st.Groups, "\n              ")))
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
				fmt.Fprintf(w, "   %s\t%s\t%s\n", via, formatLabels(g.Labels), orNone(strings.Join(g.Roles, ",")))
			}
			w.Flush()
			if len(st.Grants) == 0 {
				fmt.Println("   (none: no grant in the coordinator's configuration names you or one of your groups)")
			}

			fmt.Println("\n4. Services those grants reach right now")
			fmt.Fprintln(w, "   CLUSTER\tSERVICE\tKIND\tLABELS")
			for _, cl := range st.Clusters {
				for _, svc := range cl.Services {
					fmt.Fprintf(w, "   %s\t%s\t%s\t%s\n", cl.Name, svc.Name, svc.Kind, formatLabels(svc.Labels))
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
func printClaims(token string) {
	var claims map[string]any
	if parts := strings.Split(token, "."); len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		json.Unmarshal(payload, &claims)
	}
	out, _ := json.MarshalIndent(claims, "   ", "  ")
	fmt.Printf("   %s\n", out)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
