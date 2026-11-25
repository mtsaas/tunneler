package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

func authLoginCmd() *cobra.Command {
	var deviceCode bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in with your organization's identity provider",
		Long: `Log in with your organization's identity provider.

Opens your browser to sign in. Over SSH, on Linux without a display, or with
--device-code, it instead prints a URL and a code: open the URL in any browser
and enter the code.

Sign in in the browser if your organization requires a managed device; the
device code flow cannot show the identity provider which device signs in.`,
		Args: usage(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, err := loadClient()
			if err != nil {
				return err
			}
			// A person must do the signing in. With JSON output an agent gets
			// what it needs to ask them, and the command then waits as usual.
			if err := c.login(ctx, deviceCode, result); err != nil {
				return err
			}
			result(map[string]any{"event": "logged_in", "token_expires_at": jwtExpiry(c.state.IDToken), "renewable": c.state.RefreshToken != ""},
				"\nLogged in. To see what you can reach:\n\n    tunneler services list")
			return nil
		},
	}
	cmd.Flags().BoolVar(&deviceCode, "device-code", false, "sign in with a code in any browser, instead of opening one here")
	return cmd
}

// login signs a person in at the identity provider that the coordinator
// names, and saves the login. It calls prompt with where they must go to do
// so, as an event for JSON output and as text, and returns once they have.
func (c *client) login(ctx context.Context, deviceCode bool, prompt func(event any, text string)) error {
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
	var tok *oauth2.Token
	browser := conf.Endpoint.AuthURL != "" && (conf.Endpoint.DeviceAuthURL == "" || !deviceCode && !remoteSession())
	if browser {
		tok, err = browserLogin(ctx, conf, prompt)
	}
	if tok == nil && (err == nil || errors.Is(err, errNoBrowser)) {
		if err != nil {
			log.Debug("signing in with a device code instead", "err", err)
		}
		browser = false
		tok, err = deviceLogin(ctx, conf, prompt)
	}
	if err != nil {
		// Entra's way of saying it takes the app registration for a
		// confidential client. It is the first thing everyone hits. With a
		// redirect URI, the URI's platform decides that, not the
		// "Allow public client flows" setting.
		if strings.Contains(err.Error(), "AADSTS7000218") {
			if browser {
				return fmt.Errorf("the app registration treats http://localhost as a web app's redirect URI; in Entra, under Authentication, "+
					"move it from the Web platform to Mobile and desktop applications, or sign in with --device-code (%w)", err)
			}
			return fmt.Errorf("the app registration does not allow public clients, which a CLI must be; "+
				"in Entra set Authentication > Allow public client flows to Yes (%w)", err)
		}
		return err
	}
	return c.storeLogin(ctx, tok, ac.Issuer, ac.ClientID)
}

// remoteSession reports whether a browser opened here is likely out of the
// person's reach, so that a device code serves them better.
func remoteSession() bool {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return true
	}
	return runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
}

// deviceLogin needs no local browser or listener, so it also works over
// SSH. Entra, Okta, Auth0 and Keycloak all support it. But the browser that
// signs in can be anywhere, so Entra cannot tell whether this device is
// managed, and Conditional Access that requires one refuses it (530033).
func deviceLogin(ctx context.Context, conf *oauth2.Config, prompt func(any, string)) (*oauth2.Token, error) {
	da, err := conf.DeviceAuth(ctx)
	if err != nil {
		return nil, err
	}
	prompt(map[string]any{"event": "device_code", "verification_uri": da.VerificationURI, "user_code": da.UserCode, "expires_at": da.Expiry},
		fmt.Sprintf("To sign in, open\n\n    %s\n\nand enter the code %s\n\nWaiting for you to finish signing in...",
			printable(da.VerificationURI), printable(da.UserCode)))
	return conf.DeviceAccessToken(ctx, da)
}

var errNoBrowser = errors.New("no browser could be opened")

// openBrowser opens url in the person's browser. Tests replace it.
var openBrowser = func(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

// browserLogin uses the authorization code flow with PKCE, in a browser on
// this computer that the identity provider sends back to a listener on
// loopback. Because the browser is local, Entra's SSO extension (Company
// Portal, Platform SSO, or Edge) can show it that the device is managed.
//
// Entra accepts any port on http://localhost once the app registration has
// that redirect URI on its "Mobile and desktop applications" platform.
func browserLogin(ctx context.Context, conf *oauth2.Config, prompt func(any, string)) (*oauth2.Token, error) {
	// Browsers fall back from ::1 to 127.0.0.1 for localhost; the redirect
	// URI must say localhost because that is what Entra matches on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoBrowser, err)
	}
	defer ln.Close()
	local := *conf
	local.RedirectURL = fmt.Sprintf("http://localhost:%d/", ln.Addr().(*net.TCPAddr).Port)

	state, verifier := rand.Text(), oauth2.GenerateVerifier()
	type reply struct {
		code string
		err  error
	}
	replies := make(chan reply, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// Anything else, such as a favicon or a forged redirect, is ignored.
		if q.Get("state") != state {
			http.NotFound(w, r)
			return
		}
		rep := reply{code: q.Get("code")}
		if e := q.Get("error"); e != "" || rep.code == "" {
			rep.err = fmt.Errorf("the identity provider refused the sign-in: %s: %s", printable(e), printable(q.Get("error_description")))
			fmt.Fprintln(w, "Signing in failed. Return to your terminal to see why.")
		} else {
			fmt.Fprintln(w, "Signed in. You can close this window and return to your terminal.")
		}
		select {
		case replies <- rep:
		default:
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	url := local.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	if err := openBrowser(url); err != nil {
		return nil, fmt.Errorf("%w: %w", errNoBrowser, err)
	}
	prompt(map[string]any{"event": "browser", "url": url},
		fmt.Sprintf("Opened your browser to sign in. If it did not open, visit\n\n    %s\n\nWaiting for you to finish signing in...", printable(url)))
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case rep := <-replies:
		if rep.err != nil {
			return nil, rep.err
		}
		return local.Exchange(ctx, rep.code, oauth2.VerifierOption(verifier))
	}
}
