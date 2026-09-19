package coordinator_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/coordinator"
)

func TestExitAuth(t *testing.T) {
	auth := func(_ context.Context, token string) (*coordinator.Identity, error) {
		switch token {
		case "workload.prod.jwt":
			return &coordinator.Identity{Subject: "mi-prod", Roles: []string{coordinator.ExitRole("prod")}}, nil
		case "user.alice.jwt": // a valid login, but not an exit node
			return &coordinator.Identity{Subject: "1", Username: "alice@example.com", Groups: []string{"dba"}}, nil
		}
		return nil, errors.New("bad token")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, tt := range []struct {
		name           string
		insecure       bool
		cluster, token string
		admitted       bool
	}{
		{"workload identity with the cluster's role", false, "prod", "workload.prod.jwt", true},
		{"workload identity claiming another cluster", false, "dev", "workload.prod.jwt", false},
		{"user token", false, "prod", "user.alice.jwt", false},
		{"forged token", false, "prod", "x.y.z", false},
		{"no credentials", false, "prod", "", false},
		{"no credentials, insecure mode", true, "prod", "", true},
		{"no cluster, insecure mode", true, "", "", false},
	} {
		cfg := &coordinator.Config{
			Database:         filepath.Join(t.TempDir(), "t.db"),
			SessionTTL:       coordinator.Duration(time.Hour),
			InsecureExitAuth: tt.insecure,
		}
		c, err := coordinator.New(cfg, auth, log, log.Handler())
		if err != nil {
			t.Fatal(err)
		}
		if got := admitted(c.Handler(), tt.cluster, tt.token); got != tt.admitted {
			t.Errorf("%s: admitted = %v, want %v", tt.name, got, tt.admitted)
		}
		c.Close()
	}
}

// admitted reports whether h admits the bearer of token as an exit node of
// the cluster. An admitted request goes on to fail for want of a WebSocket
// handshake, which it does not attempt.
func admitted(h http.Handler, cluster, token string) bool {
	req := httptest.NewRequest("GET", "/v1/exit/connect?cluster="+cluster, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code == http.StatusUpgradeRequired
}
