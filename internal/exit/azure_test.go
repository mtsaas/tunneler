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

func TestKeyVaultSecretID(t *testing.T) {
	const want = "https://kv-acme.vault.azure.net/secrets/tunneler-db-uri"
	for _, vaultURI := range []string{
		"https://kv-acme.vault.azure.net",
		"https://kv-acme.vault.azure.net/",
		"HTTPS://KV-Acme.Vault.Azure.Net",
	} {
		if got, err := keyVaultSecretID(vaultURI, "tunneler-db-uri"); got != want || err != nil {
			t.Errorf("%q: %q, %v; want %q", vaultURI, got, err, want)
		}
	}

	// References that could fetch something other than their identifier
	// says.
	for _, ref := range [][2]string{
		{"https://kv-acme.vault.azure.net/secrets/other/..", "tunneler-db-uri"},
		{"https://kv-acme.vault.azure.net?x=", "tunneler-db-uri"},
		{"https://kv-acme.vault.azure.net#", "tunneler-db-uri"},
		{"https://kv-acme.vault.azure.net@kv-other.vault.azure.net", "tunneler-db-uri"},
		{"https://\u212Av-acme.vault.azure.net", "tunneler-db-uri"}, // a Kelvin sign, which lower-cases to k
		{"https://kv-acme.vault.azure.net", "tunneler-db-uri/../other"},
		{"https://kv-acme.vault.azure.net", "tunneler-db-uri/0123abcd"},
		{"https://kv-acme.vault.azure.net", ""},
	} {
		if id, err := keyVaultSecretID(ref[0], ref[1]); err == nil {
			t.Errorf("vault %q secret %q accepted as %s", ref[0], ref[1], id)
		}
	}
}

func TestParseKeyVaultSecrets(t *testing.T) {
	got, err := ParseKeyVaultSecrets([]string{
		"shop=https://kv-shop.vault.azure.net/secrets/orders-db",
		"shop=https://kv-shop.vault.azure.net/secrets/billing-db",
	})
	if err != nil || len(got) != 1 || len(got["shop"]) != 2 || got["shop"][1] != "https://kv-shop.vault.azure.net/secrets/billing-db" {
		t.Errorf("%v, %v", got, err)
	}
	for _, bad := range []string{
		"https://kv-shop.vault.azure.net/secrets/orders-db",
		"=https://kv-shop.vault.azure.net/secrets/orders-db",
		"shop=https://kv-shop.vault.azure.net",
		"shop=https://kv-shop.vault.azure.net/secrets/orders-db/0123abcd",
	} {
		if _, err := ParseKeyVaultSecrets([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
