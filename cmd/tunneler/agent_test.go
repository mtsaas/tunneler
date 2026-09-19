package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/mtsaas/tunneler/internal/api"
)

// cli runs the command line against a logged-in state and returns what it
// wrote to stdout, what fail reports for its error, and the exit status.
func cli(t *testing.T, server string, args ...string) (stdout, stderr string, status int) {
	t.Helper()
	return cliAs(t, map[string]string{"server": server, "id_token": idToken(time.Now().Add(time.Hour))}, args...)
}

// cliAs is cli from the saved state given.
func cliAs(t *testing.T, saved map[string]string, args ...string) (stdout, stderr string, status int) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(os.Getenv("HOME"), ".config"))
	t.Setenv("TUNNELER_SERVER", "")
	dir, _ := os.UserConfigDir()
	os.MkdirAll(filepath.Join(dir, "tunneler"), 0o700)
	state, _ := json.Marshal(saved)
	os.WriteFile(filepath.Join(dir, "tunneler", "config.json"), state, 0o600)

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	outputJSON = false
	root := rootCmd()
	root.SetArgs(args)
	err := root.Execute()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)

	var errOut bytes.Buffer
	if err != nil {
		status = fail(&errOut, err)
	}
	return string(out), errOut.String(), status
}

func TestAgentContract(t *testing.T) {
	two := []api.Cluster{{Name: "dev", Services: []api.Service{
		{Name: "orders", Kind: "postgres", Ready: true, Labels: map[string]string{"cluster": "dev", "name": "orders"}},
		{Name: "billing", Kind: "postgres", Ready: true, Labels: map[string]string{"cluster": "dev", "name": "billing"}},
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/clusters":
			json.NewEncoder(w).Encode(two)
		case "POST /v1/sessions":
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(api.Error{Message: "the selector matches 2 services", Matches: two})
		case "DELETE /v1/sessions/gone":
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(api.Error{Message: "no such session"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	// A listing is data on stdout and nothing else.
	out, _, status := cli(t, srv.URL, "services", "list", "-o", "json")
	var got []api.Cluster
	if err := json.Unmarshal([]byte(out), &got); err != nil || status != 0 || len(got) != 1 || len(got[0].Services) != 2 {
		t.Errorf("services list: status %d, err %v, stdout %q", status, err, out)
	}

	// An ambiguous selector never prompts: it fails with its own status and
	// the matches, so that the caller can choose and retry.
	out, errOut, status := cli(t, srv.URL, "connect", "cluster=dev", "-o", "json")
	var failure struct {
		Code    string
		Error   string
		Matches []api.Cluster
	}
	if err := json.Unmarshal([]byte(errOut), &failure); err != nil {
		t.Fatalf("stderr is not JSON: %q", errOut)
	}
	if status != exitAmbiguous || failure.Code != "ambiguous_selector" || len(failure.Matches) != 1 || out != "" {
		t.Errorf("ambiguous connect: status %d, failure %+v, stdout %q", status, failure, out)
	}
	if !strings.Contains(failure.Error, "name=") {
		t.Errorf("error does not say how to disambiguate: %q", failure.Error)
	}

	// The same without --output json, as a script with stdin from /dev/null
	// runs it. /dev/null is a character device, which once passed for a
	// terminal: the command prompted, read EOF, and exited 1.
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	stdin := os.Stdin
	os.Stdin = devnull
	_, errOut, status = cli(t, srv.URL, "connect", "cluster=dev")
	os.Stdin = stdin
	if status != exitAmbiguous || !strings.Contains(errOut, "name=") {
		t.Errorf("ambiguous connect from a script: status %d, want %d; stderr %q", status, exitAmbiguous, errOut)
	}

	// Statuses tell failures apart without reading messages.
	if _, _, status := cli(t, srv.URL, "sessions", "revoke", "gone", "-o", "json"); status != exitDenied {
		t.Errorf("revoking a missing session: status %d, want %d", status, exitDenied)
	}
	if _, _, status := cli(t, srv.URL, "sessions", "revoke"); status != exitUsage {
		t.Errorf("missing argument: status %d, want %d", status, exitUsage)
	}

	// For a person, a result carries no timestamp.
	out, _, _ = cli(t, srv.URL, "config", "--server", "https://tunneler.example.com")
	if want := "Saved. Run the following to authenticate:\n\n    tunneler auth login\n"; out != want {
		t.Errorf("config output = %q, want %q", out, want)
	}
}

// idToken returns an unsigned ID token that expires at exp, which is all
// the CLI reads of one.
func idToken(exp time.Time) string {
	claims, _ := json.Marshal(map[string]any{"exp": exp.Unix()})
	return "h." + base64.RawURLEncoding.EncodeToString(claims) + ".s"
}

// TestExpiredLogin runs a command with a login that has expired and cannot
// be renewed, as when a sign-in frequency policy refuses the refresh token.
// A person at a terminal is told so, signed in, and the command goes on. A
// script is told to run "tunneler auth login", at once and as before.
func TestExpiredLogin(t *testing.T) {
	var srv *httptest.Server
	var mu sync.Mutex
	var signIns int
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/config":
			json.NewEncoder(w).Encode(api.AuthConfig{Issuer: srv.URL, ClientID: "tunneler"})
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
				"device_authorization_endpoint": srv.URL + "/device", "token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/keys"})
		case "/device":
			mu.Lock()
			signIns++
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"device_code": "d", "user_code": "WXYZ-1234",
				"verification_uri": "https://login.example.com/device", "expires_in": 60, "interval": 1})
		case "/token":
			if r.FormValue("grant_type") == "refresh_token" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant",
					"error_description": "AADSTS70043: The refresh token has expired due to sign-in frequency checks by conditional access."})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": 3600,
				"id_token": idToken(time.Now().Add(time.Hour)), "refresh_token": "renewed"})
		case "/v1/clusters":
			json.NewEncoder(w).Encode([]api.Cluster{})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	trust(t, srv)
	expired := map[string]string{"server": srv.URL, "issuer": srv.URL, "client_id": "tunneler",
		"id_token": idToken(time.Now().Add(-time.Hour)), "refresh_token": "stale"}
	t.Cleanup(func() { interactive = func() bool { return false } })

	interactive = func() bool { return false }
	if _, errOut, status := cliAs(t, expired, "services", "list"); status != exitNotLoggedIn || !strings.Contains(errOut, "tunneler auth login") {
		t.Errorf("from a script: status %d, stderr %q; want %d telling it to log in", status, errOut, exitNotLoggedIn)
	}
	mu.Lock()
	if signIns != 0 {
		t.Errorf("a script was asked to sign in")
	}
	mu.Unlock()

	interactive = func() bool { return true }
	r, w, _ := os.Pipe()
	stderr := os.Stderr
	os.Stderr = w
	_, _, status := cliAs(t, expired, "services", "list")
	w.Close()
	os.Stderr = stderr
	told, _ := io.ReadAll(r)
	if status != 0 {
		t.Errorf("at a terminal: status %d, want the command to go on after signing in", status)
	}
	for _, want := range []string{"Your login has expired", "https://login.example.com/device", "WXYZ-1234", "Signed in."} {
		if !strings.Contains(string(told), want) {
			t.Errorf("at a terminal, stderr lacks %q:\n%s", want, told)
		}
	}
	dir, _ := os.UserConfigDir()
	if saved, _ := os.ReadFile(filepath.Join(dir, "tunneler", "config.json")); !strings.Contains(string(saved), `"renewed"`) {
		t.Errorf("the new login was not saved: %s", saved)
	}
}

// fakeProvider is an identity provider for tests. It signs anyone in with
// the device flow, renews any refresh token, and remembers every request
// made of it, with its form.
type fakeProvider struct {
	*httptest.Server
	tokenURL string // the token endpoint that discovery names; its own if empty

	mu       sync.Mutex
	requests []string
}

// newFakeProvider starts a fakeProvider with serve, which is
// httptest.NewServer or httptest.NewTLSServer.
func newFakeProvider(t *testing.T, serve func(http.Handler) *httptest.Server, tokenURL string) *fakeProvider {
	p := &fakeProvider{tokenURL: tokenURL}
	p.Server = serve(p)
	t.Cleanup(p.Close)
	return p
}

func (p *fakeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p.mu.Lock()
	p.requests = append(p.requests, r.URL.Path+"?"+r.Form.Encode())
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		tokenURL := p.tokenURL
		if tokenURL == "" {
			tokenURL = p.URL + "/token"
		}
		json.NewEncoder(w).Encode(map[string]string{"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize",
			"device_authorization_endpoint": p.URL + "/device", "token_endpoint": tokenURL, "jwks_uri": p.URL + "/keys"})
	case "/device":
		json.NewEncoder(w).Encode(map[string]any{"device_code": "d", "user_code": "WXYZ-1234",
			"verification_uri": "https://login.example.com/device", "expires_in": 60, "interval": 1})
	case "/token":
		json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": 3600,
			"id_token": idToken(time.Now().Add(time.Hour)), "refresh_token": "renewed"})
	}
}

// requested returns every request made of p, as its path and form.
func (p *fakeProvider) requested() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.requests)
}

// sent reports whether any request made of p carried s.
func (p *fakeProvider) sent(s string) bool {
	return slices.ContainsFunc(p.requested(), func(req string) bool { return strings.Contains(req, s) })
}

// trust makes the CLI, which uses the default transport, trust srv. Every
// httptest TLS server has the same certificate, so it trusts them all.
func trust(t *testing.T, srv *httptest.Server) {
	defaultTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = defaultTransport })
}

// fakeCoordinator serves the coordinator's auth config, naming the identity
// provider that issuer returns and asking for more scopes than the CLI
// needs, and an empty list of clusters.
func fakeCoordinator(t *testing.T, issuer func() string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/config":
			json.NewEncoder(w).Encode(api.AuthConfig{Issuer: issuer(), ClientID: "tunneler", Scopes: []string{"openid", "Mail.Read"}})
		case "/v1/clusters":
			json.NewEncoder(w).Encode([]api.Cluster{})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestLoginKeepsItsIssuer holds a login's refresh token to the identity
// provider that issued it. The coordinator says which identity provider to
// sign in with, unauthenticated; one that was compromised could otherwise
// name its own and be sent everyone's refresh token as their ID tokens
// expired.
func TestLoginKeepsItsIssuer(t *testing.T) {
	idp := newFakeProvider(t, httptest.NewTLSServer, "")
	trust(t, idp.Server)
	var mu sync.Mutex
	issuer := idp.URL
	coord := fakeCoordinator(t, func() string { mu.Lock(); defer mu.Unlock(); return issuer })
	t.Cleanup(func() { interactive = func() bool { return false } })
	interactive = func() bool { return false }
	expired := idToken(time.Now().Add(-time.Hour))
	login := map[string]string{"server": coord.URL, "issuer": idp.URL, "client_id": "tunneler", "id_token": expired, "refresh_token": "secret"}

	// An expired ID token is renewed where the login was made.
	if _, errOut, status := cliAs(t, login, "services", "list"); status != 0 || !idp.sent("refresh_token=secret") {
		t.Fatalf("renewing with the same identity provider: status %d, %s", status, errOut)
	}

	// Once the coordinator names another, the refresh token is not sent
	// there. The login is dropped, and a script is told to log in.
	evil := newFakeProvider(t, httptest.NewTLSServer, "")
	mu.Lock()
	issuer = evil.URL
	mu.Unlock()
	_, errOut, status := cliAs(t, login, "services", "list")
	if status != exitNotLoggedIn || !strings.Contains(errOut, "identity provider has changed") || !strings.Contains(errOut, "tunneler auth login") {
		t.Errorf("from a script: status %d, stderr %q; want %d saying why", status, errOut, exitNotLoggedIn)
	}
	dir, _ := os.UserConfigDir()
	if saved := readFile(t, filepath.Join(dir, "tunneler", "config.json")); strings.Contains(saved, "secret") {
		t.Errorf("the login was kept: %s", saved)
	}

	// A person at a terminal is told why and signed in with the new one,
	// asking for no more than the CLI needs, whatever the coordinator asks.
	interactive = func() bool { return true }
	r, w, _ := os.Pipe()
	stderr := os.Stderr
	os.Stderr = w
	_, _, status = cliAs(t, login, "services", "list")
	w.Close()
	os.Stderr = stderr
	told, _ := io.ReadAll(r)
	if status != 0 || !strings.Contains(string(told), "identity provider has changed") || !strings.Contains(string(told), "Signed in.") {
		t.Errorf("at a terminal: status %d, stderr:\n%s", status, told)
	}
	if !evil.sent("scope=openid+profile+offline_access") || evil.sent("Mail.Read") {
		t.Errorf("signing in asked for other scopes: %q", evil.requested())
	}
	dir, _ = os.UserConfigDir()
	var saved map[string]string
	json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "tunneler", "config.json"))), &saved)
	if saved["issuer"] != evil.URL || saved["refresh_token"] != "renewed" {
		t.Errorf("the new login was not saved with its issuer: %v", saved)
	}
	if evil.sent("secret") {
		t.Error("the refresh token was sent to the identity provider that the coordinator now names")
	}

	// A login saved by an earlier version, without its issuer, is not
	// renewed at all: nothing says where its refresh token may safely go.
	interactive = func() bool { return false }
	legacy := map[string]string{"server": coord.URL, "id_token": expired, "refresh_token": "legacy"}
	if _, errOut, status := cliAs(t, legacy, "services", "list"); status != exitNotLoggedIn {
		t.Errorf("a login without an issuer: status %d, stderr %q; want %d", status, errOut, exitNotLoggedIn)
	}
	if idp.sent("legacy") || evil.sent("legacy") {
		t.Error("the refresh token of a login without an issuer was sent")
	}
}

// TestInsecureIssuer refuses an identity provider that is not https, where
// the device code and the refresh token would cross the network in plain
// text. Nothing is sent to it.
func TestInsecureIssuer(t *testing.T) {
	plain := newFakeProvider(t, httptest.NewServer, "")
	downgraded := newFakeProvider(t, httptest.NewTLSServer, plain.URL+"/token")
	trust(t, downgraded.Server)
	var mu sync.Mutex
	issuer := plain.URL
	coord := fakeCoordinator(t, func() string { mu.Lock(); defer mu.Unlock(); return issuer })
	expired := idToken(time.Now().Add(-time.Hour))

	if _, errOut, status := cliAs(t, map[string]string{"server": coord.URL}, "auth", "login"); status == 0 || !strings.Contains(errOut, "https") {
		t.Errorf("logging in with an http issuer: status %d, stderr %q", status, errOut)
	}
	login := map[string]string{"server": coord.URL, "issuer": plain.URL, "client_id": "tunneler", "id_token": expired, "refresh_token": "secret"}
	if _, errOut, status := cliAs(t, login, "services", "list"); status == 0 || !strings.Contains(errOut, "https") {
		t.Errorf("renewing with an http issuer: status %d, stderr %q", status, errOut)
	}
	if got := plain.requested(); len(got) > 0 {
		t.Errorf("the http issuer was asked %q", got)
	}

	// An https issuer is refused too if it names an http token endpoint.
	mu.Lock()
	issuer = downgraded.URL
	mu.Unlock()
	login["issuer"] = downgraded.URL
	if _, errOut, status := cliAs(t, login, "services", "list"); status == 0 || !strings.Contains(errOut, "https") {
		t.Errorf("renewing with an http token endpoint: status %d, stderr %q", status, errOut)
	}
	if got := plain.requested(); len(got) > 0 {
		t.Errorf("the http token endpoint was sent %q", got)
	}
}

// TestHelpStyle holds every command's help to the conventions of help.go:
// a terse description with no full stop in listings, and examples written
// as "$ command" lines.
func TestHelpStyle(t *testing.T) {
	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		if cmd.Name() == "help" || strings.HasPrefix(cmd.CommandPath(), "tunneler completion") {
			return
		}
		if cmd.HasParent() {
			if cmd.Short == "" || strings.HasSuffix(cmd.Short, ".") || len(strings.Fields(cmd.Short)) > 9 {
				t.Errorf("%s: Short %q should be a few words with no full stop", cmd.CommandPath(), cmd.Short)
			}
		}
		for _, line := range strings.Split(strings.TrimSpace(cmd.Example), "\n") {
			if line != "" && !strings.HasPrefix(line, "$ ") {
				t.Errorf("%s: example %q should be a command, starting with \"$ \"", cmd.CommandPath(), line)
			}
		}
		var out bytes.Buffer
		cmd.SetOut(&out)
		help(cmd, nil)
		if strings.Contains(out.String(), "`") && !strings.Contains(out.String(), "LEARN MORE") {
			t.Errorf("%s: help contains a stray backtick:\n%s", cmd.CommandPath(), out.String())
		}
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd())
}

func TestKubeCommands(t *testing.T) {
	services := []api.Cluster{{Name: "prod", Services: []api.Service{
		{Name: "kubernetes", Kind: "kubernetes", Ready: true, Labels: map[string]string{"cluster": "prod", "kind": "kubernetes", "name": "kubernetes"}},
		{Name: "orders", Kind: "postgres", Ready: true, Labels: map[string]string{"cluster": "prod", "kind": "postgres", "name": "orders"}},
	}}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(services)
	}))
	defer srv.Close()
	// The CLI uses the default transport; let it trust the test server.
	defaultTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = defaultTransport }()
	kubeconfig := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", kubeconfig)

	// connect reaches whatever the selector names, in the way of its kind.
	// For a cluster that is a kubeconfig context, and nothing left running.
	out, errOut, status := cli(t, srv.URL, "connect", "cluster=prod", "kind=kubernetes", "-o", "json")
	if status != 0 {
		t.Fatalf("connect to a cluster: status %d, %s", status, errOut)
	}
	var res map[string]string
	json.Unmarshal([]byte(out), &res)
	if res["event"] != "configured" || res["context"] != "tunneler-prod" ||
		res["server"] != srv.URL+"/v1/gateway/prod/kubernetes" || !strings.Contains(res["notice"], "audited") {
		t.Errorf("connect result = %v", res)
	}
	cfg, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	exec := cfg.AuthInfos["tunneler-prod"].Exec
	if cfg.CurrentContext != "tunneler-prod" || cfg.Clusters["tunneler-prod"].Server != res["server"] ||
		exec == nil || strings.Join(exec.Args, " ") != "kube token" || exec.Env[0].Value != srv.URL {
		t.Errorf("kubeconfig = %+v, exec = %+v", cfg, exec)
	}
	// It holds no credential: the token comes from the plugin, when asked.
	if raw, _ := os.ReadFile(kubeconfig); strings.Contains(string(raw), "token:") {
		t.Errorf("the kubeconfig holds a token:\n%s", raw)
	}

	// The cluster's database and its API both answer to cluster=prod.
	if _, _, status := cli(t, srv.URL, "connect", "cluster=prod"); status != exitAmbiguous {
		t.Errorf("connect cluster=prod: status %d, want %d", status, exitAmbiguous)
	}

	// With a command, the context lives only as long as the command, in a
	// file of its own, and the person's kubeconfig is left alone.
	before, _ := os.ReadFile(kubeconfig)
	seen := filepath.Join(t.TempDir(), "seen")
	_, errOut, status = cli(t, srv.URL, "connect", "kind=kubernetes", "--",
		"sh", "-c", `echo "$KUBECONFIG" > `+seen+`; grep -c "kube" "$KUBECONFIG" >> `+seen)
	if status != 0 {
		t.Fatalf("connect -- command: status %d, %s", status, errOut)
	}
	lines := strings.Fields(readFile(t, seen))
	if len(lines) != 2 || lines[0] == kubeconfig || lines[1] == "0" {
		t.Errorf("the command saw KUBECONFIG %q", lines)
	} else if _, err := os.Stat(lines[0]); !os.IsNotExist(err) {
		t.Errorf("the temporary kubeconfig %s outlived the command", lines[0])
	}
	if after, _ := os.ReadFile(kubeconfig); string(after) != string(before) {
		t.Error("connect -- command changed the person's kubeconfig")
	}

	// Flags of one kind are refused for the other, rather than ignored.
	if _, _, status := cli(t, srv.URL, "connect", "kind=kubernetes", "--port", "5432"); status != exitUsage {
		t.Errorf("--port with a cluster: status %d, want %d", status, exitUsage)
	}
	if _, _, status := cli(t, srv.URL, "connect", "kind=postgres", "--context", "x"); status != exitUsage {
		t.Errorf("--context with a database: status %d, want %d", status, exitUsage)
	}

	// kubectl sends no credentials over plain HTTP; say so now, not later.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(services) }))
	defer plain.Close()
	if _, errOut, status := cli(t, plain.URL, "connect", "kind=kubernetes"); status == 0 || !strings.Contains(errOut, "https") {
		t.Errorf("connect to a cluster through an http coordinator: status %d, %q", status, errOut)
	}

	// The plugin hands kubectl the login, and when to ask again.
	out, _, status = cli(t, srv.URL, "kube", "token")
	var cred execCredential
	if err := json.Unmarshal([]byte(out), &cred); err != nil || status != 0 {
		t.Fatalf("kube token: status %d, %v, %q", status, err, out)
	}
	if cred.Kind != "ExecCredential" || cred.APIVersion != "client.authentication.k8s.io/v1" ||
		!strings.HasPrefix(cred.Status.Token, "h.") || time.Until(cred.Status.ExpirationTimestamp) < 50*time.Minute {
		t.Errorf("credential = %+v", cred)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
