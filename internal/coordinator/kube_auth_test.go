package coordinator_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
)

// fakeIssuer stands in for a Kubernetes cluster's OIDC issuer.
type fakeIssuer struct {
	url string
	key *rsa.PrivateKey
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	iss := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss.url, "jwks_uri": iss.url + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256"}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	iss.url = srv.URL
	return iss
}

func (iss *fakeIssuer) token(t *testing.T, subject, audience string) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: iss.key},
		(&jose.SignerOptions{}).WithHeader("kid", "k"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: iss.url, Subject: subject, Audience: jwt.Audience{audience},
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestKubeExitAuth(t *testing.T) {
	prodA, prodB := newFakeIssuer(t), newFakeIssuer(t) // "prod", then its rebuilt successor
	stranger := newFakeIssuer(t)
	const sa = "system:serviceaccount:tunneler:tunneler-exit"

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &coordinator.Config{
		Database:     filepath.Join(t.TempDir(), "t.db"),
		SessionTTL:   coordinator.Duration(time.Hour),
		ExitAudience: "tunneler",
		ExitSubject:  sa,
		// Trust the two "AKS" issuers, but not the stranger. (Real patterns
		// have wildcards; test servers differ only by port, so name them.)
		ExitIssuers: []string{prodA.url, prodB.url},
	}
	c, err := coordinator.New(cfg, func(context.Context, string) (*coordinator.Identity, error) {
		return nil, errors.New("not an identity provider token")
	}, log, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := c.Handler()

	try := func(cluster, token string) int {
		req := httptest.NewRequest("POST", "/v1/exit/result?id=none&cluster="+cluster, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, tt := range []struct {
		name, cluster, token string
		want                 int
	}{
		{"first issuer binds the name", "prod", prodA.token(t, sa, "tunneler"), http.StatusOK},
		{"same issuer again", "prod", prodA.token(t, sa, "tunneler"), http.StatusOK},
		{"another issuer claiming the name", "prod", prodB.token(t, sa, "tunneler"), http.StatusUnauthorized},
		{"another issuer under its own name", "dev", prodB.token(t, sa, "tunneler"), http.StatusOK},
		{"wrong audience", "prod", prodA.token(t, sa, "other"), http.StatusUnauthorized},
		{"wrong service account", "prod", prodA.token(t, "system:serviceaccount:default:default", "tunneler"), http.StatusUnauthorized},
		{"untrusted issuer", "staging", stranger.token(t, sa, "tunneler"), http.StatusUnauthorized},
		{"garbage", "prod", "x.y.z", http.StatusUnauthorized},
	} {
		if got := try(tt.cluster, tt.token); got != tt.want {
			t.Errorf("%s: status %d, want %d", tt.name, got, tt.want)
		}
	}

	// A rebuilt cluster: an admin releases the name, the new issuer binds it.
	// (The Authenticator above rejects everything, so bypass it for the admin
	// call by building a second coordinator on the same database.)
	admin := func(context.Context, string) (*coordinator.Identity, error) {
		return &coordinator.Identity{Subject: "a", Username: "admin@example.com", Groups: []string{"admins"}}, nil
	}
	cfg.Admins = []string{"admins"}
	c2, err := coordinator.New(cfg, admin, log, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	// An admin can see who owns which name before releasing one.
	list := httptest.NewRecorder()
	c2.Handler().ServeHTTP(list, httptest.NewRequest("GET", "/v1/clusters/bindings", nil))
	var bindings []api.ClusterBinding
	json.NewDecoder(list.Body).Decode(&bindings)
	if len(bindings) != 2 || bindings[0].Name != "dev" || bindings[0].Issuer != prodB.url ||
		bindings[1].Name != "prod" || bindings[1].Issuer != prodA.url {
		t.Errorf("bindings = %+v", bindings)
	}

	req := httptest.NewRequest("DELETE", "/v1/clusters/prod/binding", nil)
	rec := httptest.NewRecorder()
	c2.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("forget: status %d", rec.Code)
	}
	if got := try("prod", prodB.token(t, sa, "tunneler")); got != http.StatusOK {
		t.Errorf("rebuilt cluster after forget: status %d, want 200", got)
	}
	if got := try("prod", prodA.token(t, sa, "tunneler")); got != http.StatusUnauthorized {
		t.Errorf("old issuer after rebind: status %d, want 401", got)
	}
}
