package coordinator_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
		want           int
	}{
		{"workload identity with the cluster's role", false, "prod", "workload.prod.jwt", http.StatusOK},
		{"workload identity claiming another cluster", false, "dev", "workload.prod.jwt", http.StatusUnauthorized},
		{"user token", false, "prod", "user.alice.jwt", http.StatusUnauthorized},
		{"forged token", false, "prod", "x.y.z", http.StatusUnauthorized},
		{"no credentials", false, "prod", "", http.StatusUnauthorized},
		{"no credentials, insecure mode", true, "prod", "", http.StatusOK},
		{"no cluster, insecure mode", true, "", "", http.StatusUnauthorized},
	} {
		cfg := &coordinator.Config{
			Database:         filepath.Join(t.TempDir(), "t.db"),
			SessionTTL:       coordinator.Duration(time.Hour),
			InsecureExitAuth: tt.insecure,
		}
		c, err := coordinator.New(cfg, auth, log, log)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/v1/exit/result?id=none&cluster="+tt.cluster, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tt.token)
		rec := httptest.NewRecorder()
		c.Handler().ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s: status %d, want %d", tt.name, rec.Code, tt.want)
		}
		c.Close()
	}
}
