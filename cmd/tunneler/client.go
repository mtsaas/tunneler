package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mtsaas/tunneler/internal/coordinator"
)

// client talks to the coordinator using the state saved by earlier commands:
// which coordinator, and the login to present to it.
type client struct {
	*coordinator.Client
	path string

	mu    sync.Mutex // guards state, which connect refreshes from many goroutines
	state struct {
		Server       string `json:"server"`
		IDToken      string `json:"id_token,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}
}

// loadClient reads the saved state. A missing file is not an error.
func loadClient() (*client, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	c := &client{path: filepath.Join(dir, "tunneler", "config.json")}
	c.Client = &coordinator.Client{Token: c.token, HTTP: &http.Client{Transport: logTransport{}}}
	defer func() { c.Server = c.state.Server }()
	data, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &c.state); err != nil {
		return nil, fmt.Errorf("%s: %w", c.path, err)
	}
	// For automation, which would rather not write a file first. A login
	// belongs to the server it was made with, so it is not carried over.
	if server := strings.TrimRight(os.Getenv("TUNNELER_SERVER"), "/"); server != "" && server != c.state.Server {
		c.state.Server, c.state.IDToken, c.state.RefreshToken = server, "", ""
	}
	return c, nil
}

func (c *client) save() error {
	data, err := json.MarshalIndent(&c.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0o600) // holds a refresh token
}

// logTransport records each request to the coordinator, for --verbose.
type logTransport struct{}

func (logTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		log.Debug("coordinator request", "method", req.Method, "path", req.URL.Path, "status", resp.StatusCode,
			"took", time.Since(start).Round(time.Millisecond).String())
	}
	return resp, err
}

// oauth returns the OAuth 2.0 configuration for the coordinator's identity
// provider.
func (c *client) oauth(ctx context.Context) (*oauth2.Config, error) {
	if c.Server == "" {
		return nil, errors.New("no coordinator configured; run: tunneler config --server URL")
	}
	ac, err := c.AuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	log.Debug("discovering identity provider", "issuer", ac.Issuer, "client_id", ac.ClientID)
	provider, err := oidc.NewProvider(ctx, ac.Issuer)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{ClientID: ac.ClientID, Endpoint: provider.Endpoint(), Scopes: ac.Scopes}, nil
}

// token returns a current ID token, refreshing and saving it if necessary.
func (c *client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Until(jwtExpiry(c.state.IDToken)) > time.Minute {
		return c.state.IDToken, nil
	}
	if c.state.RefreshToken == "" {
		return "", fmt.Errorf("%w; run: tunneler auth login", errNotLoggedIn)
	}
	log.Debug("ID token expired or about to; refreshing", "expired_at", jwtExpiry(c.state.IDToken))
	conf, err := c.oauth(ctx)
	if err != nil {
		return "", err
	}
	tok, err := conf.TokenSource(ctx, &oauth2.Token{RefreshToken: c.state.RefreshToken}).Token()
	if err != nil {
		return "", fmt.Errorf("%w: the login expired and could not be renewed (%v); run: tunneler auth login", errNotLoggedIn, err)
	}
	return c.state.IDToken, c.storeToken(tok)
}

func (c *client) storeToken(tok *oauth2.Token) error {
	idToken, _ := tok.Extra("id_token").(string)
	if idToken == "" {
		return errors.New("identity provider returned no ID token")
	}
	c.state.IDToken = idToken
	if tok.RefreshToken != "" {
		c.state.RefreshToken = tok.RefreshToken
	}
	return c.save()
}

// jwtExpiry returns the exp claim of a JWT, or the zero time if there is
// none. The token is not verified; that is the coordinator's job.
func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

// authed loads the client and makes sure that it has a current login, so
// that a command fails for want of one before it does anything else. A
// person at a terminal whose login has expired, or who has none, is signed
// in there and then; a script is told to run "tunneler auth login".
func authed(ctx context.Context) (*client, error) {
	c, err := loadClient()
	if err != nil {
		return nil, err
	}
	if c.Server == "" {
		return nil, errors.New("no coordinator configured; run: tunneler config --server URL")
	}
	_, err = c.token(ctx)
	if !errors.Is(err, errNotLoggedIn) || !interactive() {
		return c, err
	}
	// The identity provider's reason, such as a sign-in frequency policy,
	// is detail for --verbose; the person needs only to sign in.
	log.Debug("the login cannot be used", "err", err)
	if c.state.IDToken != "" {
		fmt.Fprint(os.Stderr, "Your login has expired, so you need to sign in again.\n\n")
	} else {
		fmt.Fprint(os.Stderr, "You are not logged in yet.\n\n")
	}
	err = c.login(ctx, func(da *oauth2.DeviceAuthResponse) { fmt.Fprintln(os.Stderr, signInText(da)) })
	if err != nil {
		return c, fmt.Errorf("%w: signing in failed: %w", errNotLoggedIn, err)
	}
	fmt.Fprint(os.Stderr, "Signed in.\n\n")
	return c, nil
}
