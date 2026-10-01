package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/oauth2"
)

type authState struct {
	Server string `json:"server"`
	// Refresh credentials stay bound to the provider and app registration
	// that issued them, even if the coordinator changes its auth config.
	Issuer       string `json:"issuer,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Revision     string `json:"revision,omitempty"`
	Generation   string `json:"auth_generation,omitempty"`
}

func readAuthState(path string) (authState, error) {
	var state authState
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() {
		return state, fmt.Errorf("%s: login state must be a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return state, fmt.Errorf("%s: login state permissions must be 0600", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("%s: %w", path, err)
	}
	// Legacy state cannot identify the provider allowed to receive its
	// refresh token. Keep its ID token usable until it expires.
	if state.Issuer == "" {
		state.RefreshToken = ""
	}
	return state, nil
}

// The lock has a stable inode; locking config.json would stop coordinating
// readers after its atomic replacement. OS locks are released on process exit.
func lockAuthState(ctx context.Context, path string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	lockPath := path + ".lock"
	if info, err := os.Lstat(lockPath); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: login lock must be a regular file", lockPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	for {
		ok, err := tryAuthLock(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if ok {
			return func() { releaseAuthLock(f); f.Close() }, nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// Call only while holding the state lock. Each replacement contains the
// complete state, so concurrent readers see either complete version.
func writeAuthState(path string, state *authState) error {
	state.Revision = rand.Text()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".auth-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func refreshedAuthState(state authState, tok *oauth2.Token) (authState, error) {
	idToken, _ := tok.Extra("id_token").(string)
	if idToken == "" {
		return state, errors.New("identity provider returned no ID token")
	}
	state.IDToken = idToken
	if tok.RefreshToken != "" {
		state.RefreshToken = tok.RefreshToken
	}
	return state, nil
}

// OAuth retrieval errors include the response body. Worker diagnostics must
// never persist provider responses that could echo credentials.
func authRenewalError(err error) error {
	var rejected *oauth2.RetrieveError
	if errors.As(err, &rejected) && rejected.Response != nil {
		return fmt.Errorf("%w: the login could not be renewed (identity provider returned HTTP %d); run: tunneler auth login", errNotLoggedIn, rejected.Response.StatusCode)
	}
	return fmt.Errorf("%w: the login could not be renewed; run: tunneler auth login", errNotLoggedIn)
}

// Device authorization can take minutes. Compare the original revision so a
// completed old flow cannot undo a newer login, cleared state or server choice.
func (c *client) storeLogin(ctx context.Context, tok *oauth2.Token, issuer, clientID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	unlock, err := lockAuthState(ctx, c.path)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := readAuthState(c.path)
	if err != nil {
		return err
	}
	if current != c.saved {
		return fmt.Errorf("%w: saved login changed during sign-in; run: tunneler auth login", errNotLoggedIn)
	}
	state := authState{Server: c.Server, Issuer: issuer, ClientID: clientID, RefreshToken: tok.RefreshToken, Generation: rand.Text()}
	state, err = refreshedAuthState(state, tok)
	if err != nil {
		return err
	}
	if err := writeAuthState(c.path, &state); err != nil {
		return err
	}
	c.state, c.saved, c.generation = state, state, state.Generation
	return nil
}

func (c *client) setServer(ctx context.Context, server string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	unlock, err := lockAuthState(ctx, c.path)
	if err != nil {
		return err
	}
	defer unlock()
	state := authState{Server: server, Generation: rand.Text()}
	if err := writeAuthState(c.path, &state); err != nil {
		return err
	}
	c.state, c.saved, c.generation = state, state, state.Generation
	c.Server = server
	return nil
}
