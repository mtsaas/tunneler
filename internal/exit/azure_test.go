package exit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAzureWorkloadIdentity(t *testing.T) {
	var exchanges int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/auth/config", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"client_id": "coordinator-app"})
	})
	mux.HandleFunc("POST /my-tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		exchanges++
		r.ParseForm()
		for k, want := range map[string]string{
			"grant_type":            "client_credentials",
			"client_id":             "exit-identity",
			"scope":                 "coordinator-app/.default",
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
	defer srv.Close()

	if _, err := NewAzureCredential(); err == nil {
		t.Fatal("no error outside a workload identity environment")
	}

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
	token := AzureWorkloadIdentity(cred, srv.URL)
	for range 3 {
		got, err := token(context.Background())
		if err != nil || got != "entra-access-token" {
			t.Fatalf("token = %q, %v", got, err)
		}
	}
	if exchanges != 1 {
		t.Errorf("%d exchanges for 3 calls; the token should be cached until it nears expiry", exchanges)
	}
}
