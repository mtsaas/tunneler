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
	"strings"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

// cli runs the command line against a logged-in state and returns what it
// wrote to stdout, what fail reports for its error, and the exit status.
func cli(t *testing.T, server string, args ...string) (stdout, stderr string, status int) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(os.Getenv("HOME"), ".config"))
	t.Setenv("TUNNELER_SERVER", "")
	dir, _ := os.UserConfigDir()
	os.MkdirAll(filepath.Join(dir, "tunneler"), 0o700)
	claims, _ := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	token := "h." + base64.RawURLEncoding.EncodeToString(claims) + ".s"
	state, _ := json.Marshal(map[string]string{"server": server, "id_token": token})
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
