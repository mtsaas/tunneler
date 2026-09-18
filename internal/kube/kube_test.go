package kube

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseRequest(t *testing.T) {
	tests := []struct {
		method, url string
		want        RequestInfo
	}{
		{"GET", "/api/v1/namespaces/shop/pods", RequestInfo{Verb: "list", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "pods"}},
		{"GET", "/api/v1/namespaces/shop/pods/web-0", RequestInfo{Verb: "get", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "pods", Name: "web-0"}},
		{"GET", "/api/v1/pods?watch=true", RequestInfo{Verb: "watch", IsResource: true, APIVersion: "v1", Resource: "pods"}},
		{"GET", "/api/v1/watch/namespaces/shop/pods", RequestInfo{Verb: "watch", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "pods"}},
		{"POST", "/api/v1/namespaces/shop/pods/web-0/exec?command=sh", RequestInfo{Verb: "create", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "pods", Name: "web-0", Subresource: "exec"}},
		{"GET", "/api/v1/namespaces/shop/pods/web-0/log?follow=true", RequestInfo{Verb: "get", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "pods", Name: "web-0", Subresource: "log"}},
		{"PATCH", "/apis/apps/v1/namespaces/shop/deployments/web", RequestInfo{Verb: "patch", IsResource: true, APIGroup: "apps", APIVersion: "v1", Namespace: "shop", Resource: "deployments", Name: "web"}},
		{"PUT", "/apis/apps/v1/namespaces/shop/deployments/web/scale", RequestInfo{Verb: "update", IsResource: true, APIGroup: "apps", APIVersion: "v1", Namespace: "shop", Resource: "deployments", Name: "web", Subresource: "scale"}},
		{"DELETE", "/api/v1/namespaces/shop/secrets/db", RequestInfo{Verb: "delete", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "secrets", Name: "db"}},
		{"DELETE", "/api/v1/namespaces/shop/pods", RequestInfo{Verb: "deletecollection", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "pods"}},
		{"GET", "/api/v1/namespaces", RequestInfo{Verb: "list", IsResource: true, APIVersion: "v1", Resource: "namespaces"}},
		{"GET", "/api/v1/namespaces/shop", RequestInfo{Verb: "get", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "namespaces", Name: "shop"}},
		{"PUT", "/api/v1/namespaces/shop/finalize", RequestInfo{Verb: "update", IsResource: true, APIVersion: "v1", Namespace: "shop", Resource: "namespaces", Name: "shop", Subresource: "finalize"}},
		{"GET", "/apis/rbac.authorization.k8s.io/v1/clusterroles", RequestInfo{Verb: "list", IsResource: true, APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1", Resource: "clusterroles"}},
		{"GET", "/version", RequestInfo{Verb: "get"}},
		{"GET", "/api", RequestInfo{Verb: "get"}},
		{"GET", "/apis/apps/v1", RequestInfo{Verb: "get"}},
		{"GET", "/openapi/v2", RequestInfo{Verb: "get"}},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(tt.method, tt.url, nil)
		tt.want.Path = r.URL.Path
		if got := ParseRequest(r); got != tt.want {
			t.Errorf("%s %s:\n got %+v\nwant %+v", tt.method, tt.url, got, tt.want)
		}
	}
}

// cluster is a stand-in for a kube-apiserver, reached through both halves:
// a Gateway served over HTTP, whose dial is an APIServer's Connect.
type cluster struct {
	t         *testing.T
	gateway   *httptest.Server // what kubectl would talk to
	tokenFile string

	mu   sync.Mutex
	seen []*http.Request // what the kube-apiserver received
	logs bytes.Buffer    // the Gateway's audit trail, as JSON lines
}

func newCluster(t *testing.T, groups []string, apiserver http.HandlerFunc) *cluster {
	c := &cluster{t: t}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.seen = append(c.seen, r.Clone(context.Background()))
		c.mu.Unlock()
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"gitVersion":"v1.33.0"}`)
			return
		}
		apiserver(w, r)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	c.tokenFile = filepath.Join(dir, "token")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600)
	os.WriteFile(c.tokenFile, []byte("exit-node-token\n"), 0o600)

	api, err := NewAPIServer(Config{Server: upstream.URL, TokenFile: c.tokenFile, CAFile: caFile}, groups)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	gw := NewGateway(api.Connect)
	audit := slog.New(slog.NewJSONHandler(&lockedWriter{w: &c.logs, mu: &c.mu}, nil))
	c.gateway = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The coordinator has authenticated the caller as alice by now.
		gw.ServeAs(w, r, "alice@example.com", strings.Split(r.Header.Get("X-Test-Groups"), ","), audit)
	}))
	t.Cleanup(c.gateway.Close)
	return c
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// last returns the most recent request the kube-apiserver received, other
// than the Ping.
func (c *cluster) last() *http.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.seen) - 1; i >= 0; i-- {
		if c.seen[i].URL.Path != "/version" {
			return c.seen[i]
		}
	}
	return nil
}

func (c *cluster) auditRecords() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(c.logs.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil {
			records = append(records, rec)
		}
	}
	return records
}

func (c *cluster) get(path string, header http.Header) *http.Response {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.gateway.URL+path, nil)
	if header != nil {
		req.Header = header.Clone()
	}
	if req.Header.Get("X-Test-Groups") == "" {
		req.Header.Set("X-Test-Groups", "tunneler:view")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func TestIdentity(t *testing.T) {
	c := newCluster(t, []string{"tunneler:view", "tunneler:edit"}, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"kind":"PodList","items":[]}`)
	})

	// Whatever the caller claims to be, the cluster is told who the
	// coordinator says they are, by the exit node's credentials.
	resp := c.get("/api/v1/namespaces/shop/pods", http.Header{
		"Authorization":         {"Bearer the-users-own-id-token"},
		"Impersonate-User":      {"cluster-admin"},
		"Impersonate-Group":     {"system:masters"},
		"Impersonate-Uid":       {"0"},
		"Impersonate-Extra-Foo": {"bar"},
		"X-Test-Groups":         {"tunneler:view,tunneler:edit"},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "PodList") {
		t.Fatalf("status %d, body %q", resp.StatusCode, body)
	}
	got := c.last()
	if h := got.Header.Get("Authorization"); h != "Bearer exit-node-token" {
		t.Errorf("Authorization = %q, want the exit node's token", h)
	}
	if h := got.Header.Get("Impersonate-User"); h != "alice@example.com" {
		t.Errorf("Impersonate-User = %q", h)
	}
	if h := got.Header.Values("Impersonate-Group"); !slices.Equal(h, []string{"tunneler:view", "tunneler:edit"}) {
		t.Errorf("Impersonate-Group = %q", h)
	}
	for _, name := range []string{"Impersonate-Uid", "Impersonate-Extra-Foo"} {
		if got.Header.Get(name) != "" {
			t.Errorf("%s reached the API server", name)
		}
	}

	// The token is re-read, because the kubelet rotates it.
	os.WriteFile(c.tokenFile, []byte("rotated-token"), 0o600)
	c.get("/api/v1/nodes", nil).Body.Close()
	if h := c.last().Header.Get("Authorization"); h != "Bearer rotated-token" {
		t.Errorf("after rotation, Authorization = %q", h)
	}

	// The audit trail says what was asked for and how it went.
	records := c.auditRecords()
	first := records[0]
	for k, want := range map[string]any{"msg": "kubernetes request", "verb": "list", "resource": "pods", "namespace": "shop", "status": float64(200)} {
		if first[k] != want {
			t.Errorf("audit %s = %v, want %v (record %v)", k, first[k], want, first)
		}
	}
}

func TestExitNodeBoundsGroups(t *testing.T) {
	reached := false
	c := newCluster(t, []string{"tunneler:view"}, func(http.ResponseWriter, *http.Request) { reached = true })

	// A coordinator, compromised or misconfigured, asks for more than this
	// exit node was set up to give.
	resp := c.get("/api/v1/secrets", http.Header{"X-Test-Groups": {"tunneler:view,system:masters"}})
	var status struct {
		Kind, Message, Reason string
		Code                  int
	}
	json.NewDecoder(resp.Body).Decode(&status)
	resp.Body.Close()
	if reached {
		t.Error("the request reached the API server")
	}
	if resp.StatusCode != 403 || status.Kind != "Status" || status.Reason != "Forbidden" || !strings.Contains(status.Message, "system:masters") {
		t.Errorf("status %d, body %+v; want a Kubernetes Forbidden Status naming the group", resp.StatusCode, status)
	}
}

func TestExitNodeRefusesSystemUsers(t *testing.T) {
	api, err := NewAPIServer(Config{Server: "https://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"", "system:admin", "system:serviceaccount:kube-system:default"} {
		req := httptest.NewRequest("GET", "/api/v1/pods", nil)
		if user != "" {
			req.Header.Set("Impersonate-User", user)
		}
		rec := httptest.NewRecorder()
		api.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("user %q: status %d, want 403", user, rec.Code)
		}
	}
}

// TestWatchStreams checks that a long-lived response reaches the caller as
// it is written, not when it ends.
func TestWatchStreams(t *testing.T) {
	release := make(chan struct{})
	c := newCluster(t, []string{"tunneler:view"}, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"type":"ADDED"}`)
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprintln(w, `{"type":"DELETED"}`)
	})
	resp := c.get("/api/v1/pods?watch=true", nil)
	defer resp.Body.Close()

	line := make(chan string, 1)
	br := bufio.NewReader(resp.Body)
	go func() { s, _ := br.ReadString('\n'); line <- s }()
	select {
	case got := <-line:
		if !strings.Contains(got, "ADDED") {
			t.Errorf("first event = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first event was held back until the watch ended")
	}
	if rec := c.auditRecords(); len(rec) == 0 || rec[0]["msg"] != "kubernetes request started" || rec[0]["verb"] != "watch" {
		t.Errorf("a watch should be recorded when it starts; audit = %v", rec)
	}
	close(release)
	if rest, _ := io.ReadAll(br); !strings.Contains(string(rest), "DELETED") {
		t.Errorf("rest of watch = %q", rest)
	}
}

// TestExecUpgrades checks that a connection upgrade, as kubectl exec and
// port-forward use, passes through both halves, and that the command is on
// the audit trail.
func TestExecUpgrades(t *testing.T) {
	c := newCluster(t, []string{"tunneler:edit"}, func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
		brw.Flush()
		io.Copy(conn, brw) // a shell that echoes
	})

	conn, err := net.Dial("tcp", strings.TrimPrefix(c.gateway.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "POST /api/v1/namespaces/shop/pods/web-0/exec?command=sh&command=-c&command=id HTTP/1.1\r\n"+
		"Host: x\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Test-Groups: tunneler:edit\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v, %v", resp, err)
	}
	fmt.Fprint(conn, "whoami\n")
	if got, _ := br.ReadString('\n'); got != "whoami\n" {
		t.Errorf("echo through the upgraded connection = %q", got)
	}
	if got := c.last(); got.Header.Get("Impersonate-User") != "alice@example.com" || got.Header.Get("Authorization") != "Bearer exit-node-token" {
		t.Errorf("the upgrade request lost its identity: %v", got.Header)
	}

	rec := c.auditRecords()
	if len(rec) == 0 || rec[0]["subresource"] != "exec" || fmt.Sprint(rec[0]["command"]) != "[sh -c id]" {
		t.Errorf("exec should be recorded with its command when it starts; audit = %v", rec)
	}
}

func TestPingReportsBadCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteStatus(w, http.StatusUnauthorized, "Unauthorized")
	}))
	defer upstream.Close()
	api, err := NewAPIServer(Config{Server: upstream.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Ping = %v, want an error naming the 401", err)
	}
}
