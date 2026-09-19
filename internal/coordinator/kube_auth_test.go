package coordinator_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
)

// fakeIssuer stands in for a Kubernetes cluster's OIDC issuer. Like a
// forger's, it serves its discovery document at every path but /keys, and it
// counts the requests it is sent.
type fakeIssuer struct {
	url      string // where it serves
	issuer   string // what its tokens and discovery document name; url, unless forged
	cert     *x509.Certificate
	key      *rsa.PrivateKey
	requests atomic.Int32
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	iss := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss.issuer, "jwks_uri": iss.url + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256"}}})
	})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iss.requests.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	iss.url, iss.issuer, iss.cert = srv.URL, srv.URL, srv.Certificate()
	return iss
}

// caFile writes the issuers' certificates to a PEM bundle, for
// exit_issuer_ca_file.
func caFile(t *testing.T, issuers ...*fakeIssuer) string {
	var bundle []byte
	for _, iss := range issuers {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: iss.cert.Raw})...)
	}
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func (iss *fakeIssuer) token(t *testing.T, subject, audience string) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: iss.key},
		(&jose.SignerOptions{}).WithHeader("kid", "k"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: iss.issuer, Subject: subject, Audience: jwt.Audience{audience},
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
		ExitIssuers:      []string{prodA.url, prodB.url},
		ExitIssuerCAFile: caFile(t, prodA, prodB, stranger),
	}
	c, err := coordinator.New(cfg, func(context.Context, string) (*coordinator.Identity, error) {
		return nil, errors.New("not an identity provider token")
	}, log, log.Handler())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := c.Handler()

	for _, tt := range []struct {
		name, cluster, token string
		admitted             bool
	}{
		{"first issuer binds the name", "prod", prodA.token(t, sa, "tunneler"), true},
		{"same issuer again", "prod", prodA.token(t, sa, "tunneler"), true},
		{"another issuer claiming the name", "prod", prodB.token(t, sa, "tunneler"), false},
		{"another issuer under its own name", "dev", prodB.token(t, sa, "tunneler"), true},
		{"wrong audience", "prod", prodA.token(t, sa, "other"), false},
		{"wrong service account", "prod", prodA.token(t, "system:serviceaccount:default:default", "tunneler"), false},
		{"untrusted issuer", "staging", stranger.token(t, sa, "tunneler"), false},
		{"garbage", "prod", "x.y.z", false},
	} {
		if got := admitted(h, tt.cluster, tt.token); got != tt.admitted {
			t.Errorf("%s: admitted = %v, want %v", tt.name, got, tt.admitted)
		}
	}

	// A rebuilt cluster: an admin releases the name, the new issuer binds it.
	// (The Authenticator above rejects everything, so bypass it for the admin
	// call by building a second coordinator on the same database.)
	admin := func(context.Context, string) (*coordinator.Identity, error) {
		return &coordinator.Identity{Subject: "a", Username: "admin@example.com", Groups: []string{"admins"}}, nil
	}
	cfg.Admins = []string{"admins"}
	c2, err := coordinator.New(cfg, admin, log, log.Handler())
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
	if !admitted(h, "prod", prodB.token(t, sa, "tunneler")) {
		t.Error("rebuilt cluster not admitted after forget")
	}
	if admitted(h, "prod", prodA.token(t, sa, "tunneler")) {
		t.Error("old issuer admitted after rebind")
	}
}

// TestForgedExitIssuer checks that an issuer that matches a pattern as text,
// but names another host as a URL, is refused without that host being
// contacted. Each forger's discovery document names the forged issuer, so a
// coordinator that fetched it would admit the forger's token.
func TestForgedExitIssuer(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	const sa = "system:serviceaccount:tunneler:tunneler-exit"
	var forgers []*fakeIssuer
	for _, delim := range []string{"?x=", "#"} {
		f := newFakeIssuer(t)
		f.issuer = f.url + delim + ".oic.prod-aks.azure.com/" + tenant + "/y/"
		forgers = append(forgers, f)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := coordinator.New(&coordinator.Config{
		Database:         filepath.Join(t.TempDir(), "t.db"),
		SessionTTL:       coordinator.Duration(time.Hour),
		ExitAudience:     "tunneler",
		ExitSubject:      sa,
		ExitIssuers:      []string{"https://*.oic.prod-aks.azure.com/" + tenant + "/*/"},
		ExitIssuerCAFile: caFile(t, forgers...),
	}, func(context.Context, string) (*coordinator.Identity, error) {
		return nil, errors.New("not an identity provider token")
	}, log, log.Handler())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for i, f := range forgers {
		if admitted(c.Handler(), fmt.Sprint("forged-", i), f.token(t, sa, "tunneler")) {
			t.Errorf("%s: admitted", f.issuer)
		}
		if n := f.requests.Load(); n != 0 {
			t.Errorf("%s: coordinator sent %d requests to %s", f.issuer, n, f.url)
		}
	}
}
