package coordinator_test

import (
	"bufio"
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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/coordinator"
	"github.com/mtsaas/tunneler/internal/exit"
	"github.com/mtsaas/tunneler/internal/kube"
)

// TestReadvertisingKeepsConnections changes an exit node's services while a
// request through the node streams. The coordinator learns of the new
// services, and the request streams on: a re-advertisement leaves the
// node's session, which carries both, alone.
func TestReadvertisingKeepsConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release := make(chan struct{})
	r := newGatewayRig(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/watch" {
			return // the exit node's readiness check
		}
		fmt.Fprintln(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			fmt.Fprintln(w, "second")
		case <-req.Context().Done():
		}
	}))
	agent := r.startExit(ctx, t, "kubernetes")
	r.await(ctx, t, "kubernetes")

	resp := r.get(ctx, t, "kubernetes", "/watch")
	defer resp.Body.Close()
	body := bufio.NewReader(resp.Body)
	if line, err := body.ReadString('\n'); line != "first\n" {
		t.Fatalf("watch began with %q, %v", line, err)
	}
	if err := agent.LoadConfig(r.offer(t, "kubernetes", "kubernetes-b")); err != nil {
		t.Fatal(err)
	}
	r.await(ctx, t, "kubernetes", "kubernetes-b")
	close(release)
	if line, err := body.ReadString('\n'); line != "second\n" {
		t.Errorf("after the services changed, the watch went on with %q, %v", line, err)
	}
}

// TestWithdrawnAdmission withdraws a connected exit node's admission. The
// node's next answer is refused, and the node is disconnected, as it would
// be refused were it connecting.
func TestWithdrawnAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newGatewayRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "{}") }))
	r.startExit(ctx, t, "kubernetes", "kubernetes-b")
	r.await(ctx, t, "kubernetes", "kubernetes-b")
	if code, body := r.fetch(ctx, t, "kubernetes", "/version"); code != http.StatusOK {
		t.Fatalf("while admitted: status %d, body %s", code, body)
	}

	withdrawn := r.cfg
	withdrawn.InsecureExitAuth = false
	r.c.Reload(&withdrawn)
	// A service not reached before has no connection to reuse, so reaching
	// it asks the exit node.
	if code, body := r.fetch(ctx, t, "kubernetes-b", "/version"); code != http.StatusBadGateway || !strings.Contains(body, "not admitted") {
		t.Errorf("after withdrawal: status %d, body %s; want 502 saying the node is not admitted", code, body)
	}
	r.await(ctx, t) // and nothing of the cluster remains
}

// gatewayRig is a coordinator whose one grant lets alice reach every
// kubernetes service of the cluster prod, and a stand-in for that cluster's
// API server.
type gatewayRig struct {
	cfg   coordinator.Config
	c     *coordinator.Coordinator
	srv   *httptest.Server // the coordinator
	alice *coordinator.Client
	api   kube.Config // the stand-in, as an exit node reaches it
	dir   string
	log   *slog.Logger
}

func newGatewayRig(t *testing.T, apiserver http.Handler) *gatewayRig {
	t.Helper()
	stand := httptest.NewTLSServer(apiserver)
	t.Cleanup(stand.Close)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stand.Certificate().Raw}), 0o600)
	os.WriteFile(filepath.Join(dir, "token"), []byte("exit-node-token"), 0o600)

	r := &gatewayRig{
		cfg: coordinator.Config{
			Database:         filepath.Join(dir, "t.db"),
			SessionTTL:       coordinator.Duration(time.Hour),
			InsecureExitAuth: true,
			Grants:           []coordinator.Grant{{User: "alice@example.com", Labels: map[string]string{"cluster": "prod", "kind": "kubernetes"}}},
		},
		api: kube.Config{Server: stand.URL, TokenFile: filepath.Join(dir, "token"), CAFile: filepath.Join(dir, "ca.crt")},
		dir: dir,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	auth := func(_ context.Context, token string) (*coordinator.Identity, error) {
		if token == "alice" {
			return &coordinator.Identity{Subject: "1", Username: "alice@example.com"}, nil
		}
		return nil, errors.New("bad token")
	}
	cfg := r.cfg
	c, err := coordinator.New(&cfg, auth, r.log, r.log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	r.c = c
	r.srv = httptest.NewServer(c.Handler())
	t.Cleanup(r.srv.Close)
	r.alice = &coordinator.Client{Server: r.srv.URL, Token: func(context.Context) (string, error) { return "alice", nil }}
	return r
}

// offer writes an exit node configuration that offers the stand-in under
// each of names, and returns its path.
func (r *gatewayRig) offer(t *testing.T, names ...string) string {
	t.Helper()
	var services []exit.ServiceConfig
	for _, name := range names {
		services = append(services, exit.ServiceConfig{Name: name, Kind: "kubernetes", Kubernetes: r.api})
	}
	data, _ := json.Marshal(exit.Config{Services: services})
	path := filepath.Join(r.dir, "exit.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startExit runs an exit node of prod that offers the stand-in under each
// of names, until ctx is done.
func (r *gatewayRig) startExit(ctx context.Context, t *testing.T, names ...string) *exit.Agent {
	t.Helper()
	agent := &exit.Agent{Server: r.srv.URL, Cluster: "prod", Log: r.log}
	if err := agent.LoadConfig(r.offer(t, names...)); err != nil {
		t.Fatal(err)
	}
	go agent.Run(ctx)
	return agent
}

// await waits until the services alice can reach are the named ones, all
// ready.
func (r *gatewayRig) await(ctx context.Context, t *testing.T, names ...string) {
	t.Helper()
	var ready []string
	for ctx.Err() == nil {
		clusters, _ := r.alice.Services(ctx)
		ready = nil
		for _, cl := range clusters {
			for _, svc := range cl.Services {
				if svc.Ready {
					ready = append(ready, svc.Name)
				}
			}
		}
		if slices.Equal(ready, names) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("alice can reach %v, never %v", ready, names)
}

// get makes a request as alice to a service behind the gateway.
func (r *gatewayRig) get(ctx context.Context, t *testing.T, service, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, "GET", r.alice.GatewayURL("prod", service)+path, nil)
	req.Header.Set("Authorization", "Bearer alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// fetch is get, for a response that is read whole.
func (r *gatewayRig) fetch(ctx context.Context, t *testing.T, service, path string) (int, string) {
	t.Helper()
	resp := r.get(ctx, t, service, path)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}
