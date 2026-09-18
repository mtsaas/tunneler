package coordinator_test

import (
	"context"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
	"github.com/mtsaas/tunneler/internal/exit"
	"github.com/mtsaas/tunneler/internal/kube"
)

// TestKubernetesGateway drives a request the whole way: a client of the
// coordinator's API, the coordinator, a real exit node, and a stand-in for
// the cluster's kube-apiserver.
func TestKubernetesGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The kube-apiserver, which notes who it was asked to act as.
	var mu sync.Mutex
	var seen []*http.Request
	apiserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Clone(context.Background()))
		mu.Unlock()
		fmt.Fprintf(w, `{"kind":"PodList","path":%q}`, r.URL.Path)
	}))
	defer apiserver.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: apiserver.Certificate().Raw}), 0o600)
	os.WriteFile(filepath.Join(dir, "token"), []byte("exit-node-token"), 0o600)

	// The coordinator: alice may view, carol is granted more than the exit
	// node will give, and bob is granted nothing.
	cfg := &coordinator.Config{
		Database:         filepath.Join(dir, "t.db"),
		SessionTTL:       coordinator.Duration(time.Hour),
		InsecureExitAuth: true,
		Grants: []coordinator.Grant{
			{User: "alice@example.com", Labels: map[string]string{"cluster": "prod", "kind": "kubernetes"}, Roles: []string{"tunneler:view"}},
			{User: "carol@example.com", Labels: map[string]string{"cluster": "prod"}, Roles: []string{"system:masters"}},
		},
	}
	auth := func(_ context.Context, token string) (*coordinator.Identity, error) {
		if name, ok := strings.CutSuffix(token, "-token"); ok {
			return &coordinator.Identity{Subject: name, Username: name + "@example.com"}, nil
		}
		return nil, errors.New("bad token")
	}
	var audit syncBuffer
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := coordinator.New(cfg, auth, quiet, slog.New(slog.NewJSONHandler(&audit, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// The exit node, offering its cluster's API.
	exitConfig := filepath.Join(dir, "exit.json")
	data, _ := json.Marshal(exit.Config{Services: []exit.ServiceConfig{{
		Name: "kubernetes", Kind: "kubernetes", Roles: []string{"tunneler:view"},
		Kubernetes: kube.Config{Server: apiserver.URL, TokenFile: filepath.Join(dir, "token"), CAFile: filepath.Join(dir, "ca.crt")},
	}}})
	os.WriteFile(exitConfig, data, 0o600)
	agent := &exit.Agent{Server: srv.URL, Cluster: "prod", Log: quiet}
	if err := agent.LoadConfig(exitConfig); err != nil {
		t.Fatal(err)
	}
	go agent.Run(ctx)

	client := func(user string) *coordinator.Client {
		return &coordinator.Client{Server: srv.URL, Token: func(context.Context) (string, error) { return user + "-token", nil }}
	}
	alice := client("alice")
	for ctx.Err() == nil {
		if clusters, _ := alice.Services(ctx); len(clusters) == 1 && clusters[0].Services[0].Ready {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	get := func(user, path string, header http.Header) (int, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, "GET", alice.GatewayURL("prod", "kubernetes")+path, nil)
		req.Header = header.Clone()
		if req.Header == nil {
			req.Header = http.Header{}
		}
		if user != "" {
			req.Header.Set("Authorization", "Bearer "+user+"-token")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// Alice reaches the API as herself, whatever else her request claims.
	code, body := get("alice", "/api/v1/namespaces/shop/pods?limit=5", http.Header{"Impersonate-User": {"cluster-admin"}})
	if code != 200 || !strings.Contains(body, `"/api/v1/namespaces/shop/pods"`) {
		t.Fatalf("alice: status %d, body %s", code, body)
	}
	mu.Lock()
	got := seen[len(seen)-1]
	mu.Unlock()
	if got.Header.Get("Impersonate-User") != "alice@example.com" || got.Header.Get("Impersonate-Group") != "tunneler:view" ||
		got.Header.Get("Authorization") != "Bearer exit-node-token" || got.URL.RawQuery != "limit=5" {
		t.Errorf("the API server was asked: %s %v", got.URL, got.Header)
	}
	if log := audit.String(); !strings.Contains(log, `"msg":"kubernetes request"`) || !strings.Contains(log, `"user":"alice@example.com"`) ||
		!strings.Contains(log, `"resource":"pods"`) || !strings.Contains(log, `"namespace":"shop"`) {
		t.Errorf("audit trail lacks the request:\n%s", log)
	}

	// Everyone else is turned away, each at the right place.
	before := len(seen)
	for _, tt := range []struct {
		name, user string
		want       int
		say        string
	}{
		{"no login", "", 401, "tunneler auth login"},
		{"no grant", "bob", 403, "access denied"},
		{"a grant the exit node will not honor", "carol", 403, "system:masters"},
	} {
		code, body := get(tt.user, "/api/v1/secrets", nil)
		if code != tt.want || !strings.Contains(body, tt.say) {
			t.Errorf("%s: status %d, body %s; want %d mentioning %q", tt.name, code, body, tt.want, tt.say)
		}
	}
	if len(seen) != before {
		t.Error("a refused request reached the API server")
	}
	// A service that does not exist answers exactly as one without a grant.
	code1, body1 := get("bob", "/api/v1/pods", nil)
	req, _ := http.NewRequestWithContext(ctx, "GET", alice.GatewayURL("prod", "nonesuch")+"/api/v1/pods", nil)
	req.Header.Set("Authorization", "Bearer bob-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if code1 != resp.StatusCode || body1 != string(body2) {
		t.Errorf("a missing service is distinguishable from a forbidden one:\n%d %s\n%d %s", code1, body1, resp.StatusCode, body2)
	}

	// The API is not reached through sessions, and says how it is.
	_, err = alice.CreateSession(ctx, map[string]string{"kind": "kubernetes"})
	if apiErr := (*api.Error)(nil); !errors.As(err, &apiErr) || apiErr.Status != 400 || !strings.Contains(apiErr.Message, "/v1/gateway/prod/kubernetes") {
		t.Errorf("connect to a kubernetes service: %v", err)
	}
}
