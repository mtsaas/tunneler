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

func TestAzureWorkloadIdentity(t *testing.T) {
	if _, err := NewAzureCredential(); err == nil {
		t.Fatal("no error outside a workload identity environment")
	}
	for _, audience := range []string{"4f1b2c3d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "api://tunneler"} {
		t.Run(audience, func(t *testing.T) {
			cred, scopes := fakeEntra(t)
			token := AzureWorkloadIdentity(cred, audience)
			for range 3 {
				got, err := token(context.Background())
				if err != nil || got != "entra-access-token" {
					t.Fatalf("token = %q, %v", got, err)
				}
			}
			if got, want := scopes(), []string{audience + "/.default"}; !slices.Equal(got, want) {
				t.Errorf("exchanges for 3 tokens = %q, want %q; the token should be cached until it nears expiry", got, want)
			}
		})
	}
}

// fakeEntra serves the token endpoint of the Entra tenant "my-tenant", which
// exchanges the pod's projected token for an access token for any scope, and
// puts the pod in that tenant under the workload identity "exit-identity".
// It returns a credential and the scope of each exchange so far.
func fakeEntra(t *testing.T) (*AzureCredential, func() []string) {
	var mu sync.Mutex
	var scopes []string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /my-tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		scopes = append(scopes, r.PostForm.Get("scope"))
		mu.Unlock()
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
	return cred, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(scopes)
	}
}
