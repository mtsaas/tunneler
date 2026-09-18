package main

import (
	"bytes"
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

	"github.com/mtsaas/tunneler/internal/api"
)

// client talks to the coordinator using the state saved by earlier commands.
type client struct {
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

// do makes an API request. A non-nil in is sent as JSON, and a non-nil out
// receives the decoded response. A non-empty token authenticates the request.
func (c *client) do(ctx context.Context, method, path, token string, in, out any) error {
	if c.state.Server == "" {
		return errors.New("no coordinator configured; run: tunneler config --server URL")
	}
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.state.Server+path, &body)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	log.Debug("coordinator request", "method", method, "path", path, "status", resp.StatusCode,
		"took", time.Since(start).Round(time.Millisecond).String())
	if resp.StatusCode >= 300 {
		e := new(api.Error)
		if json.NewDecoder(resp.Body).Decode(e) != nil || e.Message == "" {
			e.Message = resp.Status
		}
		e.Status = resp.StatusCode
		return e
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// oauth returns the OAuth 2.0 configuration for the coordinator's identity
// provider.
func (c *client) oauth(ctx context.Context) (*oauth2.Config, error) {
	var ac api.AuthConfig
	if err := c.do(ctx, http.MethodGet, "/v1/auth/config", "", nil, &ac); err != nil {
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

// authed loads the client and a current token.
func authed(ctx context.Context) (*client, string, error) {
	c, err := loadClient()
	if err != nil {
		return nil, "", err
	}
	token, err := c.token(ctx)
	return c, token, err
}
