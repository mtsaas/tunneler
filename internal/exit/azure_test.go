package exit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

const coordinatorApp = "4f1b2c3d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"

func TestAzureWorkloadIdentity(t *testing.T) {
	if _, err := NewAzureCredential(); err == nil {
		t.Fatal("no error outside a workload identity environment")
	}
	server, cred, requests := fakeAzure(t, coordinatorApp)
	token := AzureWorkloadIdentity(cred, server, "")
	for range 3 {
		got, err := token(context.Background())
		if err != nil || got != "entra-access-token" {
			t.Fatalf("token = %q, %v", got, err)
		}
	}
	if got, want := requests(), []string{"config", coordinatorApp + "/.default"}; !slices.Equal(got, want) {
		t.Errorf("requests for 3 tokens = %q, want %q; the client ID and the token should be cached", got, want)
	}
}

// The coordinator receives the token, so it must not choose a resource for
// it: its answer is used only if it is a client ID, and not at all if the
// audience is set.
func TestAzureWorkloadIdentityAudience(t *testing.T) {
	for _, tt := range []struct {
		name               string
		reported, audience string
		want               []string // requests the fakes receive, in order
		refused            bool
	}{
		{"coordinator names a resource", "https://vault.azure.net", "", []string{"config"}, true},
		{"coordinator names an application ID URI", "api://AzureADTokenExchange", "", []string{"config"}, true},
		{"coordinator names two scopes", coordinatorApp + " https://vault.azure.net", "", []string{"config"}, true},
		{"coordinator names a client ID", coordinatorApp, "", []string{"config", coordinatorApp + "/.default"}, false},
		{"audience set", "https://vault.azure.net", coordinatorApp, []string{coordinatorApp + "/.default"}, false},
		{"audience set to an application ID URI", coordinatorApp, "api://tunneler", []string{"api://tunneler/.default"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, cred, requests := fakeAzure(t, tt.reported)
			_, err := AzureWorkloadIdentity(cred, server, tt.audience)(context.Background())
			if (err != nil) != tt.refused {
				t.Errorf("err = %v, want refused %v", err, tt.refused)
			}
			if got := requests(); !slices.Equal(got, tt.want) {
				t.Errorf("requests = %q, want %q", got, tt.want)
			}
		})
	}
}

// fakeAzure serves a coordinator that reports clientID as its own, and the
// token endpoint of the Entra tenant "my-tenant", which exchanges the pod's
// projected token for an access token for any scope. It puts the pod in
// that tenant under the workload identity "exit-identity", and returns the
// coordinator's URL, a credential, and the requests served so far: "config"
// for each question to the coordinator, and the scope of each exchange.
func fakeAzure(t *testing.T, clientID string) (string, *AzureCredential, func() []string) {
	var mu sync.Mutex
	var requests []string
	record := func(r string) {
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, r)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/auth/config", func(w http.ResponseWriter, r *http.Request) {
		record("config")
		json.NewEncoder(w).Encode(map[string]string{"client_id": clientID})
	})
	mux.HandleFunc("POST /my-tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		record(r.PostForm.Get("scope"))
		for k, want := range map[string]string{
			"grant_type":            "client_credentials",
			"client_id":             "exit-identity",
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"client_assertion":      "projected-sa-token",
		} {
			if got := r.PostForm.Get(k); got != want {
				t.Errorf("token request: %s = %q, want %q", k, got, want)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "entra-access-token", "token_type": "Bearer", "expires_in": 3600})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	file := filepath.Join(t.TempDir(), "token")
	os.WriteFile(file, []byte("projected-sa-token\n"), 0o600)
	t.Setenv("AZURE_CLIENT_ID", "exit-identity")
	t.Setenv("AZURE_TENANT_ID", "my-tenant")
	t.Setenv("AZURE_AUTHORITY_HOST", srv.URL+"/")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", file)
	cred, err := NewAzureCredential()
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, cred, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(requests)
	}
}
