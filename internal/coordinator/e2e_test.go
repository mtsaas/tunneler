package coordinator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
	"github.com/mtsaas/tunneler/internal/exit"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

type syncBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

// TestEndToEnd drives a coordinator, an exit node and a real Postgres:
//
//	docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:17
//	TUNNELER_TEST_DSN=postgres://postgres:pw@localhost:5432/postgres go test ./internal/coordinator/
func TestEndToEnd(t *testing.T) {
	adminDSN := os.Getenv("TUNNELER_TEST_DSN")
	if adminDSN == "" {
		t.Skip("TUNNELER_TEST_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cfg := &coordinator.Config{
		Database:         filepath.Join(t.TempDir(), "tunneler.db"),
		SessionTTL:       coordinator.Duration(time.Hour),
		InsecureExitAuth: true,
		Grants: []coordinator.Grant{
			{Group: "dba", Labels: map[string]string{"cluster": "prod", "kind": "postgres"}, Roles: []string{"pg_read_all_data"}},
		},
	}
	auth := func(_ context.Context, token string) (*coordinator.Identity, error) {
		switch token {
		case "alice":
			return &coordinator.Identity{Subject: "1", Username: "alice@example.com", Groups: []string{"dba"}}, nil
		case "mallory":
			return &coordinator.Identity{Subject: "2", Username: "mallory@example.com"}, nil
		}
		return nil, errors.New("bad token")
	}
	var audit syncBuffer
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := coordinator.New(cfg, auth, log, slog.New(slog.NewJSONHandler(&audit, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// Two services on one database server, told apart by label.
	exitConfig := filepath.Join(t.TempDir(), "exit.json")
	data, _ := json.Marshal(exit.Config{Services: []exit.ServiceConfig{
		{Name: "orders", Kind: "postgres", DSN: adminDSN, Labels: map[string]string{"team": "shop"}, Roles: []string{"pg_read_all_data"}},
		{Name: "billing", Kind: "postgres", DSN: adminDSN, Labels: map[string]string{"team": "finance"}, Roles: []string{"pg_read_all_data"}},
	}})
	os.WriteFile(exitConfig, data, 0o600)
	agent := &exit.Agent{Server: srv.URL, Cluster: "prod", Log: log}
	if err := agent.LoadConfig(exitConfig); err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(ctx)
	go agent.Run(agentCtx)

	call := func(method, path, token string, in, out any) int {
		t.Helper()
		body, _ := json.Marshal(in)
		req, _ := http.NewRequestWithContext(ctx, method, srv.URL+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil && resp.StatusCode < 300 {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode
	}

	// The cluster appears once the exit node has said hello.
	var clusters []api.Cluster
	for len(clusters) == 0 && ctx.Err() == nil {
		time.Sleep(50 * time.Millisecond)
		call("GET", "/v1/clusters", "alice", nil, &clusters)
	}
	if len(clusters) != 1 || clusters[0].Name != "prod" || len(clusters[0].Services) != 2 {
		t.Fatalf("clusters = %+v", clusters)
	}
	clusters = nil
	if call("GET", "/v1/clusters", "mallory", nil, &clusters); len(clusters) != 0 {
		t.Errorf("mallory sees %+v", clusters)
	}

	var status api.AuthStatus
	call("GET", "/v1/auth/status", "alice", nil, &status)
	if status.Username != "alice@example.com" || len(status.Grants) != 1 || len(status.Clusters) != 1 {
		t.Errorf("alice's status = %+v", status)
	}
	status = api.AuthStatus{}
	if call("GET", "/v1/auth/status", "mallory", nil, &status); len(status.Grants) != 0 || len(status.Clusters) != 0 {
		t.Errorf("mallory's status = %+v", status)
	}

	// A selector must narrow to one service.
	var conflict api.Error
	{
		body, _ := json.Marshal(api.SessionRequest{Selector: map[string]string{"cluster": "prod"}})
		r, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/v1/sessions", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer alice")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(resp.Body).Decode(&conflict)
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict || len(conflict.Matches) != 1 || len(conflict.Matches[0].Services) != 2 {
			t.Errorf("ambiguous selector: status %d, matches %+v", resp.StatusCode, conflict.Matches)
		}
	}

	req := api.SessionRequest{Selector: map[string]string{"cluster": "prod", "team": "shop"}}
	if code := call("POST", "/v1/sessions", "mallory", req, nil); code != http.StatusForbidden {
		t.Errorf("mallory creating a session: status %d, want 403", code)
	}
	var s api.Session
	if code := call("POST", "/v1/sessions", "alice", req, &s); code != http.StatusCreated {
		t.Fatalf("creating session: status %d", code)
	}

	connect := func(token, user, password string) (*pgx.Conn, error) {
		pc, _ := pgx.ParseConfig("postgres://localhost/" + s.Database + "?sslmode=disable")
		pc.User, pc.Password = user, password
		pc.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"tunnel"}, nil }
		pc.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return tunnel.Dial(ctx, srv.URL+"/v1/sessions/"+s.ID+"/connect", http.Header{"Authorization": {"Bearer " + token}})
		}
		return pgx.ConnectConfig(ctx, pc)
	}

	if _, err := connect("mallory", s.Username, s.Password); err == nil {
		t.Error("mallory connected to alice's session")
	}
	if _, err := connect("alice", "postgres", "pw"); err == nil || !strings.Contains(err.Error(), "only permits") {
		t.Errorf("logging in as another role: %v", err)
	}
	conn, err := connect("alice", s.Username, s.Password)
	if err != nil {
		t.Fatal(err)
	}
	var who string
	if err := conn.QueryRow(ctx, "SELECT current_user /* marker */").Scan(&who); err != nil || who != s.Username {
		t.Fatalf("current_user = %q, %v; want %q", who, err, s.Username)
	}
	if log := audit.String(); !strings.Contains(log, "marker") || !strings.Contains(log, "alice@example.com") {
		t.Errorf("audit log lacks the query or its owner:\n%s", log)
	}

	if code := call("DELETE", "/v1/sessions/"+s.ID, "alice", nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoking: status %d", code)
	}
	if err := conn.Ping(ctx); err == nil {
		t.Error("connection survived revocation")
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	var exists bool
	admin.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)", s.Username).Scan(&exists)
	if exists {
		t.Errorf("role %s survived revocation", s.Username)
	}

	// Revoke while the exit node is down: the drop must be remembered and
	// carried out when a node for the cluster returns.
	if code := call("POST", "/v1/sessions", "alice", req, &s); code != http.StatusCreated {
		t.Fatalf("creating second session: status %d", code)
	}
	stopAgent()
	for clusters = []api.Cluster{{}}; len(clusters) != 0 && ctx.Err() == nil; time.Sleep(50 * time.Millisecond) {
		clusters = nil
		call("GET", "/v1/clusters", "alice", nil, &clusters)
	}
	if code := call("DELETE", "/v1/sessions/"+s.ID, "alice", nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoking with the exit node down: status %d", code)
	}
	if _, err := connect("alice", s.Username, s.Password); err == nil {
		t.Error("revoked session still accepts connections")
	}
	go agent.Run(ctx)
	for exists = true; exists && ctx.Err() == nil; time.Sleep(50 * time.Millisecond) {
		admin.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)", s.Username).Scan(&exists)
	}
	if exists {
		t.Errorf("role %s was never dropped after the exit node returned", s.Username)
	}
}
