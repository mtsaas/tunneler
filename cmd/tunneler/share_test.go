package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/coordinator"
	"github.com/mtsaas/tunneler/internal/testutil"
)

func TestShareParsingAndImmutableLocalOperation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(os.Getenv("HOME"), ".config"))
	opts := shareOptions{public: true, requestID: "operation-123", waitReady: time.Minute, ttl: "60m"}
	request, targets, err := parseShare([]string{"web=3000", "api=[::1]:8080"}, opts)
	testutil.NoError(t, err)
	testutil.Require(t, targets["web"] == "127.0.0.1:3000" && targets["api"] == "[::1]:8080" && request.TTL == "1h0m0s", "bad parsed manifest: %+v %v", request, targets)
	ordered, _, err := parseShare([]string{"api=[::1]:8080", "web=127.0.0.1:03000"}, opts)
	testutil.Require(t, err == nil && ordered.ManifestDigest == request.ManifestDigest, "equivalent manifest digest differs: %v", err)
	local, existed, err := prepareShareLocal("https://control.example", request, targets, true)
	testutil.Require(t, err == nil && !existed, "first operation: %v, %v", existed, err)
	ordered.StartupDeadline = ordered.StartupDeadline.Add(time.Hour)
	replayed, existed, err := prepareShareLocal(local.Server, ordered, targets, true)
	testutil.Require(t, err == nil && existed && replayed.Request.StartupDeadline.Equal(request.StartupDeadline), "retry changed immutable deadline: %+v %v", replayed, err)
	ordered.ManifestDigest = "different"
	_, _, err = prepareShareLocal(local.Server, ordered, targets, true)
	if code, status := classify(err); code != "idempotency_conflict" || status != exitUsage {
		t.Fatalf("conflicting operation: %s %d", code, status)
	}
	for _, args := range [][]string{{"web=localhost:3000"}, {"web=192.0.2.1:80"}, {"web=0"}, {"web=65536"}, {"web=3000", "web=3001"}, {"web=3000", "other=127.0.0.1:03000"}, {"Upper=3000"}, {"=3000"}} {
		if _, _, err := parseShare(args, opts); err == nil {
			t.Errorf("accepted invalid manifest %v", args)
		}
	}
	opts.public = false
	if _, _, err := parseShare([]string{"3000"}, opts); err == nil {
		t.Fatal("accepted implicit public access")
	}
}

func TestShareJSONAndStableErrorCodes(t *testing.T) {
	s := &api.Share{ID: "share", State: "ready", Services: []api.ShareService{{ID: "svc", Name: "web", URL: "https://web.preview.example"}}}
	data, _ := json.Marshal(shareResult(s, nil))
	testutil.Require(t, bytes.Contains(data, []byte(`"local_target":null`)) && bytes.Contains(data, []byte(`"publisher":null`)), "remote discovery invented local data: %s", data)
	for _, tc := range []struct {
		code               string
		httpStatus, status int
	}{
		{"usage", 400, 2}, {"idempotency_conflict", 409, 2}, {"startup_expired", 400, 6}, {"invalid_attachment", 409, 6}, {"publisher_attached", 409, 6}, {"quota_exceeded", 503, 6}, {"unknown_share", 404, 4}, {"custom_future_error", 403, 4},
	} {
		code, status := classify(&api.Error{Code: tc.code, Status: tc.httpStatus})
		if code != tc.code || status != tc.status {
			t.Errorf("%s classified %s/%d", tc.code, code, status)
		}
	}
	if code, status := classify(&api.Error{Status: 409}); code != "ambiguous_selector" || status != 5 {
		t.Fatal("legacy selector classification changed")
	}
}

func handoffLocal(t *testing.T) *shareLocal {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(os.Getenv("HOME"), ".config"))
	request, targets, err := parseShare([]string{"web=3000"}, shareOptions{public: true, requestID: "handoff-123", waitReady: time.Minute})
	testutil.NoError(t, err)
	local, _, err := prepareShareLocal("https://control.example", request, targets, true)
	testutil.NoError(t, err)
	return local
}

type failSecondWrite struct {
	bytes.Buffer
	writes int
}

func (w *failSecondWrite) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 2 {
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(p)
}

func TestHandoffAcknowledgementAndLostConfirmation(t *testing.T) {
	local := handoffLocal(t)
	s := &api.Share{ID: "share", State: "ready"}
	ack := make(chan error, 1)
	ack <- nil
	w := &failSecondWrite{}
	testutil.NoError(t, acceptShareHandoff(context.Background(), ack, json.NewEncoder(w), local, s))
	persisted, err := readShareLocal(local.Path)
	testutil.Require(t, err == nil && persisted.State == "ready", "lost confirmation discarded committed ownership: %+v %v", persisted, err)
	testutil.Require(t, !bytes.Contains(w.Bytes(), []byte(local.Nonce)) && !bytes.Contains(w.Bytes(), []byte(`"nonce"`)), "readiness exposed private IPC nonce")
	testutil.NoError(t, updateShareLocal(local, "ended", nil, ""))
	if err := updateShareLocal(local, "ready", s, ""); err == nil {
		t.Fatal("terminal local state returned to ready")
	}
}

func TestHandoffRejectsLateACKAfterTerminalControl(t *testing.T) {
	local := handoffLocal(t)
	ctx, cancel := context.WithCancel(context.Background())
	ack := make(chan error, 1)
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- acceptShareHandoff(ctx, ack, json.NewEncoder(&output), local, &api.Share{ID: "share", State: "ready"})
	}()
	deadline := time.Now().Add(time.Second)
	for local.snapshot().State != "proposed" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	ack <- nil
	testutil.Require(t, testutil.Receive(t, done, time.Second, "handoff ignored cancellation") != nil, "late ACK accepted after control cancellation")
	testutil.Require(t, !bytes.Contains(output.Bytes(), []byte(`"type":"accepted"`)) && local.snapshot().State != "ready", "terminal control emitted readiness")
}

func TestPrivateIPCRequiresNonceAndStopsLocally(t *testing.T) {
	local := handoffLocal(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() { <-ctx.Done(); close(stopped) }()
	ln, err := startShareIPC(ctx, local, cancel, stopped)
	testutil.NoError(t, err)
	defer ln.Close()
	wrong := local.snapshot()
	wrong.Nonce = "wrong"
	if _, err := shareIPC(context.Background(), wrong, "inspect"); err == nil {
		t.Fatal("unauthenticated IPC succeeded")
	}
	if reply, err := shareIPC(context.Background(), local, "inspect"); err != nil || reply.Local.WorkerID != local.WorkerID {
		t.Fatalf("authenticated discovery failed: %v", err)
	}
	testutil.Require(t, stopShareLocal(context.Background(), local), "local stop was not confirmed")
}

func TestStartFailureIncludesGeneratedOperationID(t *testing.T) {
	var requestID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/share-operations/"):
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(api.Error{Code: "unknown_share", Message: "unknown operation"})
		case r.Method == "POST" && r.URL.Path == "/v1/shares":
			var request api.ShareRequest
			json.NewDecoder(r.Body).Decode(&request)
			requestID = request.RequestID
			w.WriteHeader(503)
			json.NewEncoder(w).Encode(api.Error{Code: "upstream_unavailable", Message: "unavailable"})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	out, errOut, status := cli(t, srv.URL, "share", "start", "--public", "3000", "--output", "json")
	var failure struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	json.Unmarshal([]byte(errOut), &failure)
	testutil.Require(t, out == "" && status == 6 && failure.Code == "upstream_unavailable" && requestID != "" && failure.RequestID == requestID, "ambiguous start cannot be recovered: stdout=%q stderr=%q status=%d", out, errOut, status)
}

func TestStartPreflightHonorsReadinessDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/share-operations/") {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	started := time.Now()
	_, errOut, status := cli(t, srv.URL, "share", "start", "--public", "3000", "--wait-ready", "50ms", "--request-id", "bounded-preflight", "--output", "json")
	var failure struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	json.Unmarshal([]byte(errOut), &failure)
	testutil.Require(t, time.Since(started) <= time.Second && status == 6 && failure.Code == "startup_timeout" && failure.RequestID == "bounded-preflight", "preflight ignored deadline: status=%d stderr=%s", status, errOut)
}

func installShareLogin(t *testing.T, server string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(os.Getenv("HOME"), ".config"))
	t.Setenv("TUNNELER_SERVER", "")
	t.Setenv("TUNNELER_NO_UPDATE_CHECK", "1")
	dir, _ := os.UserConfigDir()
	os.MkdirAll(filepath.Join(dir, "tunneler"), 0o700)
	state, _ := json.Marshal(authState{Server: server, IDToken: authTestJWT(time.Now().Add(time.Hour))})
	testutil.NoError(t, os.WriteFile(filepath.Join(dir, "tunneler", "config.json"), state, 0o600))
}

func shareTestServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	handler := slog.NewTextHandler(io.Discard, nil)
	c, err := coordinator.New(&coordinator.Config{
		Database: filepath.Join(t.TempDir(), "coordinator.db"),
		Sharing:  &coordinator.SharingConfig{Domain: "preview.example", ControlHosts: []string{"127.0.0.1"}, AllowAuthenticated: true},
	}, func(_ context.Context, token string) (*coordinator.Identity, error) {
		if token == "" {
			return nil, errors.New("missing token")
		}
		return &coordinator.Identity{Issuer: "https://issuer.test", Subject: "cli-user", Username: "cli-user@test", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}, slog.New(handler), handler)
	testutil.NoError(t, err)
	attaches := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/control") {
			attaches.Add(1)
		}
		c.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(func() { c.Close(); server.Close() })
	return server, attaches
}

func TestShareWorkerProcess(t *testing.T) {
	if os.Getenv("TUNNELER_SHARE_TEST_WORKER") != "1" {
		return
	}
	root := rootCmd()
	root.SetArgs([]string{"share", "_worker", "--output", "json"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		os.Exit(fail(os.Stderr, err))
	}
	os.Exit(0)
}

func TestDetachedWorkerReadyRecoveryAndStop(t *testing.T) {
	localApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("local")) }))
	defer localApp.Close()
	srv, attaches := shareTestServer(t)
	installShareLogin(t, srv.URL)
	t.Setenv("TUNNELER_SHARE_TEST_WORKER", "1")
	original := shareWorkerCommand
	shareWorkerCommand = func(executable string) *exec.Cmd {
		return exec.Command(executable, "-test.run=^TestShareWorkerProcess$")
	}
	defer func() { shareWorkerCommand = original }()
	request, targets, err := parseShare([]string{"web=" + strings.TrimPrefix(localApp.URL, "http://")}, shareOptions{public: true, requestID: "detach-operation", waitReady: 10 * time.Second})
	testutil.NoError(t, err)
	local, _, err := prepareShareLocal(srv.URL, request, targets, true)
	testutil.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stopShareLocal(ctx, local)
	})
	out, err := detachShare(context.Background(), local)
	if err != nil {
		log, _ := os.ReadFile(filepath.Join(filepath.Dir(local.Path), "worker.log"))
		t.Fatalf("detach: %v\n%s", err, log)
	}
	testutil.Require(t, out.State == "ready" && out.Publisher != nil && out.Publisher.State == "ready" && out.Readiness.PublisherPathTCP && !out.Readiness.PublicEdgeVerified, "incomplete acknowledged readiness: %+v", out)
	c, err := authed(context.Background())
	testutil.NoError(t, err)
	recovered, err := recoverShareStart(context.Background(), c, local)
	testutil.Require(t, err == nil && recovered.ID == out.ID && recovered.Publisher != nil && attaches.Load() == 1, "recovery replaced worker: %+v %v", recovered, err)
	testutil.Require(t, stopShareLocal(context.Background(), local), "local stop was not confirmed")
	if _, err := c.StopShare(context.Background(), out.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		persisted, _ := readShareLocal(local.Path)
		if persisted != nil && persisted.State == "ended" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("detached worker state never became terminal")
}

func TestOfflineStopReportsPendingRemoteCleanup(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	installShareLogin(t, srv.URL)
	request, targets, _ := parseShare([]string{"web=3000"}, shareOptions{public: true, requestID: "offline-operation", waitReady: time.Minute})
	local, _, err := prepareShareLocal(srv.URL, request, targets, true)
	testutil.NoError(t, err)
	s := &api.Share{ID: "offline-share", State: "ready", ExpiresAt: time.Now().Add(time.Hour), AuthorizationDeadline: time.Now().Add(-time.Minute)}
	testutil.NoError(t, updateShareLocal(local, "ended", s, ""))
	srv.Close()
	r, w, _ := os.Pipe()
	previous := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = previous }()
	outputJSON = true
	cmd := shareStopCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{s.ID})
	err = cmd.ExecuteContext(context.Background())
	w.Close()
	os.Stdout = previous
	out, _ := io.ReadAll(r)
	r.Close()
	var result shareStopOutput
	json.Unmarshal(out, &result)
	code, status := classify(err)
	testutil.Require(t, code == "cleanup_pending" && status == 6 && result.LocalStopped && !result.RemoteStopped && result.CleanupDeadline != nil && result.CleanupDeadline.Equal(s.ExpiresAt), "offline stop lied: %s/%d %s", code, status, out)
}

func TestDetachedParentEOFBeforeReadinessCancelsCreate(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/shares" {
			io.Copy(io.Discard, r.Body)
			close(started)
			<-r.Context().Done()
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	installShareLogin(t, srv.URL)
	t.Setenv("TUNNELER_SHARE_TEST_WORKER", "1")
	request, targets, err := parseShare([]string{"web=3000"}, shareOptions{public: true, requestID: "parent-eof-operation", waitReady: 15 * time.Second})
	testutil.NoError(t, err)
	local, _, err := prepareShareLocal(srv.URL, request, targets, true)
	testutil.NoError(t, err)
	executable, _ := os.Executable()
	command := exec.Command(executable, "-test.run=^TestShareWorkerProcess$")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	stdin, err := command.StdinPipe()
	testutil.NoError(t, err)
	defer stdin.Close()
	testutil.NoError(t, command.Start())
	defer command.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	testutil.NoError(t, json.NewEncoder(stdin).Encode(shareWorkerConfig{local.shareLocalData, local.Path}))
	testutil.Receive(t, started, 5*time.Second, "worker never began create")
	stdin.Close()
	testutil.Receive(t, done, 3*time.Second, "parent EOF left pre-ready worker alive")
	persisted, err := readShareLocal(local.Path)
	testutil.Require(t, err == nil && persisted.State == "ended", "parent EOF left nonterminal state: %+v %v", persisted, err)
}

func TestMissingACKNeverCommitsReadiness(t *testing.T) {
	local := handoffLocal(t)
	ack := make(chan error, 1)
	ack <- io.EOF
	var output bytes.Buffer
	err := acceptShareHandoff(context.Background(), ack, json.NewEncoder(&output), local, &api.Share{ID: "share", State: "ready"})
	testutil.Require(t, err != nil && local.snapshot().State != "ready" && !bytes.Contains(output.Bytes(), []byte(`"type":"accepted"`)), "parent EOF committed detached ownership")
	testutil.Require(t, errors.Is(err, io.EOF), "EOF cause was lost: %v", err)
}
