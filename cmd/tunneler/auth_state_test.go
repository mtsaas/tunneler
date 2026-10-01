package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
	"github.com/mtsaas/tunneler/internal/testutil"
	"golang.org/x/oauth2"
)

func authTestJWT(expiry time.Time) string {
	data, _ := json.Marshal(map[string]int64{"exp": expiry.Unix()})
	return "h." + base64.RawURLEncoding.EncodeToString(data) + ".s"
}

func authTestClient(t *testing.T, path string) *client {
	t.Helper()
	state, err := readAuthState(path)
	testutil.NoError(t, err)
	c := &client{path: path, state: state, saved: state, generation: state.Generation}
	c.Client = &coordinator.Client{Server: state.Server, Token: c.token, HTTP: &http.Client{Transport: logTransport{}}}
	return c
}

func authTestWrite(t *testing.T, path string, state authState) {
	t.Helper()
	unlock, err := lockAuthState(t.Context(), path)
	testutil.NoError(t, err)
	defer unlock()
	testutil.NoError(t, writeAuthState(path, &state))
}

// The helper runs in a fresh process, so the test cannot pass using only the
// client's mutex or a process-local lock registry.
func TestAuthProcessHelper(t *testing.T) {
	mode := os.Getenv("TUNNELER_AUTH_TEST_MODE")
	if mode == "" {
		return
	}
	path := os.Getenv("TUNNELER_AUTH_TEST_PATH")
	if mode == "hold" {
		unlock, err := lockAuthState(t.Context(), path)
		testutil.NoError(t, err)
		defer unlock()
		fmt.Println("locked")
		io.Copy(io.Discard, os.Stdin)
		return
	}
	if certPath := os.Getenv("TUNNELER_AUTH_TEST_CA"); certPath != "" {
		cert, err := os.ReadFile(certPath)
		testutil.NoError(t, err)
		roots := x509.NewCertPool()
		testutil.Require(t, roots.AppendCertsFromPEM(cert), "invalid test CA")
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: roots}
		http.DefaultTransport = transport
	}
	if _, err := authTestClient(t, path).token(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func authHelperCommand(t *testing.T, path, mode string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	testutil.NoError(t, err)
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestAuthProcessHelper$")
	cmd.Env = append(os.Environ(), "TUNNELER_AUTH_TEST_MODE="+mode, "TUNNELER_AUTH_TEST_PATH="+path)
	return cmd
}

func TestAuthRefreshAcrossProcesses(t *testing.T) {
	var refreshes atomic.Int32
	var server *httptest.Server
	fresh := authTestJWT(time.Now().Add(time.Hour))
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/config":
			json.NewEncoder(w).Encode(api.AuthConfig{Issuer: server.URL + "/oidc", ClientID: "test", Scopes: []string{"openid"}})
		case "/oidc/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL + "/oidc", "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/keys"})
		case "/token":
			if r.FormValue("refresh_token") != "refresh-0" {
				t.Errorf("refresh used a stale or unexpected credential")
			}
			refreshes.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": fresh, "refresh_token": "refresh-1"})
		default:
			t.Errorf("unexpected auth request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	testutil.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
	t.Setenv("TUNNELER_AUTH_TEST_CA", certPath)
	path := filepath.Join(t.TempDir(), "tunneler", "config.json")
	authTestWrite(t, path, authState{Server: server.URL, Issuer: server.URL + "/oidc", ClientID: "test", IDToken: authTestJWT(time.Now().Add(-time.Hour)), RefreshToken: "refresh-0", Generation: "same-login"})
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			if out, err := authHelperCommand(t, path, "token").CombinedOutput(); err != nil {
				t.Errorf("token child: %v: %s", err, out)
			}
		})
	}
	wg.Wait()
	if got := refreshes.Load(); got != 1 {
		t.Fatalf("refresh requests = %d, want one serialized rotation", got)
	}
	state, err := readAuthState(path)
	testutil.NoError(t, err)
	testutil.Require(t, state.IDToken == fresh && state.RefreshToken == "refresh-1" && state.Generation == "same-login", "refresh did not preserve the login generation and rotated credentials")
}

func TestAuthLockCancellationAndProcessExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunneler", "config.json")
	cmd := authHelperCommand(t, path, "hold")
	stdout, err := cmd.StdoutPipe()
	testutil.NoError(t, err)
	stdin, err := cmd.StdinPipe()
	testutil.NoError(t, err)
	defer stdin.Close()
	testutil.NoError(t, cmd.Start())
	defer cmd.Process.Kill()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("child lock readiness: %q, %v", line, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if unlock, err := lockAuthState(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("lock cancellation = %v", err)
	}
	testutil.NoError(t, cmd.Process.Kill())
	cmd.Wait()
	ctx, cancel = context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	unlock, err := lockAuthState(ctx, path)
	testutil.Require(t, err == nil, "crashed process kept the lock: %v", err)
	unlock()
}

func TestAuthStaleLoginCannotRestoreClearedCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunneler", "config.json")
	authTestWrite(t, path, authState{Server: "https://coordinator.example", IDToken: authTestJWT(time.Now().Add(time.Hour)), RefreshToken: "old-refresh", Generation: "old-login"})
	stale, current := authTestClient(t, path), authTestClient(t, path)
	testutil.NoError(t, current.setServer(t.Context(), current.Server))
	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": authTestJWT(time.Now().Add(2 * time.Hour))})
	if err := stale.storeLogin(t.Context(), tok, "https://issuer.test", "test"); !errors.Is(err, errNotLoggedIn) {
		t.Fatalf("stale login write = %v", err)
	}
	if _, err := stale.token(t.Context()); !errors.Is(err, errNotLoggedIn) {
		t.Fatalf("old worker token = %v", err)
	}
	state, err := readAuthState(path)
	testutil.NoError(t, err)
	testutil.Require(t, state.IDToken == "" && state.RefreshToken == "", "stale login resurrected credentials")
	testutil.NoError(t, current.storeLogin(t.Context(), tok, "https://issuer.test", "test"))
	testutil.Require(t, current.state.RefreshToken == "", "new login inherited another login's refresh token")
	testutil.Require(t, current.state.Issuer == "https://issuer.test" && current.state.ClientID == "test", "new login lost its provider binding")
	if _, err := stale.token(t.Context()); !errors.Is(err, errNotLoggedIn) {
		t.Fatalf("old worker adopted a new login: %v", err)
	}
}

func TestAuthReloadRejectsDeletedClearedOrChangedState(t *testing.T) {
	for _, change := range []string{"delete", "clear", "server", "login"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tunneler", "config.json")
			state := authState{Server: "https://coordinator.example", IDToken: authTestJWT(time.Now().Add(time.Hour)), Generation: "initial"}
			authTestWrite(t, path, state)
			c := authTestClient(t, path)
			switch change {
			case "delete":
				testutil.NoError(t, os.Remove(path))
			case "clear":
				state.IDToken, state.RefreshToken = "", ""
				authTestWrite(t, path, state)
			case "server":
				state.Server = "https://different.example"
				authTestWrite(t, path, state)
			case "login":
				state.Generation = "new-login"
				authTestWrite(t, path, state)
			}
			if token, err := c.token(t.Context()); !errors.Is(err, errNotLoggedIn) || token != "" {
				t.Fatalf("cached token escaped invalidation: token present %t, error %v", token != "", err)
			}
		})
	}
}

func TestAuthStatePrivateAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunneler", "config.json")
	authTestWrite(t, path, authState{Server: "https://coordinator.example", Generation: "initial"})
	unlock, err := lockAuthState(t.Context(), path)
	testutil.NoError(t, err)
	defer unlock()
	if runtime.GOOS != "windows" {
		for name, want := range map[string]os.FileMode{path: 0o600, path + ".lock": 0o600, filepath.Dir(path): 0o700} {
			info, err := os.Stat(name)
			testutil.NoError(t, err)
			if got := info.Mode().Perm(); got != want {
				t.Errorf("%s mode = %o, want %o", filepath.Base(name), got, want)
			}
		}
	}
	done := make(chan struct{})
	var readers sync.WaitGroup
	readers.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			state, err := readAuthState(path)
			if err != nil || state.Server != "https://coordinator.example" {
				t.Errorf("atomic read failed: %v", err)
				return
			}
		}
	})
	for range 30 {
		state := authState{Server: "https://coordinator.example", IDToken: strings.Repeat("x", 16384), Generation: "initial"}
		testutil.NoError(t, writeAuthState(path, &state))
	}
	close(done)
	readers.Wait()
}

func TestAuthStateRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires separate Windows privileges")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	testutil.NoError(t, os.WriteFile(target, []byte("{}"), 0o600))
	for _, suffix := range []string{"", ".lock"} {
		path := filepath.Join(dir, "state"+strings.ReplaceAll(suffix, ".", ""))
		testutil.NoError(t, os.Symlink(target, path+suffix))
		if suffix == "" {
			if _, err := readAuthState(path); err == nil {
				t.Fatal("read followed login symlink")
			}
		} else {
			if unlock, err := lockAuthState(t.Context(), path); err == nil {
				unlock()
				t.Fatal("lock followed symlink")
			}
		}
	}
}

func TestAuthServerOverrideWithoutSavedFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(os.Getenv("HOME"), ".config"))
	t.Setenv("TUNNELER_SERVER", "https://override.example/")
	c, err := loadClient()
	testutil.NoError(t, err)
	testutil.Require(t, c.Server == "https://override.example" && c.state.IDToken == "", "server override did not apply without a saved file")
}

func TestAuthRenewalErrorDoesNotPersistProviderSecrets(t *testing.T) {
	secret := "provider-echoed-sensitive-token"
	err := authRenewalError(&oauth2.RetrieveError{
		Response: &http.Response{StatusCode: http.StatusBadRequest},
		Body:     []byte(secret), ErrorCode: secret, ErrorDescription: secret,
	})
	testutil.Require(t, errors.Is(err, errNotLoggedIn) && !strings.Contains(err.Error(), secret) && strings.Contains(err.Error(), "HTTP 400"), "refresh failure exposed provider response details or lost its actionable status")
}

func TestAuthProviderChangeClearsAndFencesSavedLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/config" {
			t.Errorf("credential sent to unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(api.AuthConfig{Issuer: "https://new-issuer.test", ClientID: "new-app"})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "tunneler", "config.json")
	authTestWrite(t, path, authState{Server: server.URL, Issuer: "https://old-issuer.test", ClientID: "old-app", IDToken: authTestJWT(time.Now().Add(-time.Hour)), RefreshToken: "private-refresh-token", Generation: "old-login"})
	current, stale := authTestClient(t, path), authTestClient(t, path)
	if _, err := current.token(t.Context()); !errors.Is(err, errProviderChanged) {
		t.Fatalf("changed provider: %v", err)
	}
	state, err := readAuthState(path)
	testutil.NoError(t, err)
	testutil.Require(t, state.IDToken == "" && state.RefreshToken == "" && state.Generation != "old-login", "provider change retained credentials or the old worker's authority")
	if _, err := stale.token(t.Context()); !errors.Is(err, errNotLoggedIn) {
		t.Fatalf("old worker remained authorized: %v", err)
	}
}

func TestAuthLegacyLoginDoesNotRenewWithoutProviderBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunneler", "config.json")
	authTestWrite(t, path, authState{Server: "https://coordinator.example", IDToken: authTestJWT(time.Now().Add(-time.Hour)), RefreshToken: "unbound-refresh-token"})
	c := authTestClient(t, path)
	testutil.Require(t, c.state.RefreshToken == "", "legacy refresh token was retained without its issuer")
	if _, err := c.token(t.Context()); !errors.Is(err, errNotLoggedIn) {
		t.Fatalf("legacy login attempted renewal: %v", err)
	}
}
