package coordinator_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/coordinator"
)

// TestAuditRecordsShareFields has the coordinator write the audit records
// that belong to no service in particular, and checks that they carry the
// same who and what as the records of every kind.
func TestAuditRecordsShareFields(t *testing.T) {
	var audit syncBuffer
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &coordinator.Config{
		Database:   filepath.Join(t.TempDir(), "t.db"),
		SessionTTL: coordinator.Duration(time.Hour),
		Admins:     []string{"admins"},
	}
	auth := func(context.Context, string) (*coordinator.Identity, error) {
		return &coordinator.Identity{Subject: "1", Username: "alice@example.com", Groups: []string{"admins"}}, nil
	}
	c, err := coordinator.New(cfg, auth, quiet, slog.NewJSONHandler(&audit, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, call := range []struct{ method, path, body string }{
		{"POST", "/v1/sessions", `{"selector":{"cluster":"prod","name":"orders"}}`}, // no service matches
		{"DELETE", "/v1/clusters/prod/binding", ""},
	} {
		req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		req.Header.Set("Authorization", "Bearer alice")
		c.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}

	records := auditRecords(t, audit.String())
	if len(records) != 2 {
		t.Fatalf("want a refusal and a release, got %d records:\n%s", len(records), audit.String())
	}
	checkAuditFields(t, records)
	if denied := records[0]; denied["cluster"] != "prod" || denied["service"] != "orders" {
		t.Errorf("a refusal should name what the person asked for: %v", denied)
	}
}

// TestUnrecordedGatewayRequests has the audit sink fail. A Kubernetes
// request that stays open, such as a watch or an exec, is refused: it could
// run for hours with nothing on the trail. One that completes at once goes
// ahead, and the record it loses is reported on the operational log.
func TestUnrecordedGatewayRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var failing atomic.Bool
	r := newGatewayRig(t, failingSink{slog.DiscardHandler, &failing},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "{}") }))
	r.startExit(ctx, t, "kubernetes")
	r.await(ctx, t, "kubernetes")

	failing.Store(true)
	if code, body := r.fetch(ctx, t, "kubernetes", "/api/v1/pods?watch=true"); code != http.StatusServiceUnavailable || !strings.Contains(body, "audit trail") {
		t.Errorf("a watch the trail cannot record: status %d, body %s; want 503 saying why", code, body)
	}
	if code, body := r.fetch(ctx, t, "kubernetes", "/api/v1/pods"); code != http.StatusOK {
		t.Errorf("a request that completes at once: status %d, body %s; want it served", code, body)
	}
	if !strings.Contains(r.ops.String(), "the audit sink failed to take a record") {
		t.Errorf("the lost record is not on the operational log:\n%s", r.ops.String())
	}
}

// failingSink is an audit sink that refuses every record while fail is set,
// as a sink on a full disk would.
type failingSink struct {
	slog.Handler
	fail *atomic.Bool
}

func (s failingSink) Handle(ctx context.Context, r slog.Record) error {
	if s.fail.Load() {
		return errors.New("no space left on device")
	}
	return s.Handler.Handle(ctx, r)
}

func (s failingSink) WithAttrs(attrs []slog.Attr) slog.Handler {
	return failingSink{s.Handler.WithAttrs(attrs), s.fail}
}

func (s failingSink) WithGroup(name string) slog.Handler {
	return failingSink{s.Handler.WithGroup(name), s.fail}
}

// auditRecords parses an audit trail of one JSON record per line.
func auditRecords(t *testing.T, trail string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for line := range strings.Lines(trail) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit record is not JSON: %v: %q", err, line)
		}
		records = append(records, rec)
	}
	return records
}

// checkAuditFields fails t for each record that lacks a field that all
// records share, so that one query finds all that a person did.
func checkAuditFields(t *testing.T, records []map[string]any) {
	t.Helper()
	for _, rec := range records {
		for _, k := range []string{"user", "subject", "cluster", "service", "kind"} {
			if _, ok := rec[k].(string); !ok {
				t.Errorf("record %q lacks %q: %v", rec["msg"], k, rec)
			}
		}
	}
}
