package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"golang.org/x/oauth2"
)

// No test may open a real browser. Without one, sign-in falls back to the
// device code flow, which the other tests drive.
func TestMain(m *testing.M) {
	openBrowser = func(string) error { return errors.New("no browser in tests") }
	os.Exit(m.Run())
}

// TestBrowserLogin drives the authorization code flow as a browser would:
// a stray request with the wrong state is ignored, and the code from the
// real redirect is exchanged with the PKCE verifier.
func TestBrowserLogin(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "c" || r.FormValue("code_verifier") == "" || r.FormValue("redirect_uri") == "" {
			t.Errorf("token request lacks the code, verifier or redirect URI: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"a","token_type":"Bearer","id_token":"i"}`))
	}))
	defer idp.Close()

	open := openBrowser
	t.Cleanup(func() { openBrowser = open })
	openBrowser = func(auth string) error {
		u, _ := url.Parse(auth)
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" {
			t.Errorf("no PKCE challenge in %s", auth)
		}
		go func() {
			if resp, err := http.Get(q.Get("redirect_uri") + "?code=forged&state=wrong"); err == nil && resp.StatusCode != http.StatusNotFound {
				t.Errorf("a redirect with the wrong state got %d", resp.StatusCode)
			}
			http.Get(q.Get("redirect_uri") + "?code=c&state=" + url.QueryEscape(q.Get("state")))
		}()
		return nil
	}
	conf := &oauth2.Config{ClientID: "tunneler", Endpoint: oauth2.Endpoint{AuthURL: idp.URL + "/authorize", TokenURL: idp.URL + "/token"}}
	tok, err := browserLogin(t.Context(), conf, func(any, string) {})
	if err != nil || tok.Extra("id_token") != "i" {
		t.Fatalf("browserLogin = %v, %v", tok, err)
	}
}
