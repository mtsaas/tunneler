package coordinator

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

// TestResumeExpiredSessions starts a coordinator on a database of sessions
// that all expired while it was down. Each one's timer fires at once, so its
// revocation runs while New is still resuming the others, which -race
// reports if New resumes them outside c.mu. Every session ends up revoked.
func TestResumeExpiredSessions(t *testing.T) {
	const n = 300
	path := filepath.Join(t.TempDir(), "t.db")
	st, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		s := &session{
			info: api.Session{
				ID:        fmt.Sprint("S", i),
				Owner:     "alice@example.com",
				Cluster:   "prod",
				Service:   "shop-postgres",
				Kind:      "postgres",
				Username:  fmt.Sprint("tnl_alice_", i),
				ExpiresAt: time.Now().Add(-time.Hour),
			},
			subject: "sub-1",
		}
		if err := st.insert(s); err != nil {
			t.Fatal(err)
		}
	}
	st.db.Close()

	c, err := New(&Config{Database: path}, nil, slog.New(slog.DiscardHandler), slog.DiscardHandler)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// With no exit node connected to drop their accounts, the revocations
	// keep the sessions on record as pending drops.
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		saved, err := c.store.load()
		if err != nil {
			t.Fatal(err)
		}
		revoked := 0
		for _, s := range saved {
			if s.revoked {
				revoked++
			}
		}
		if revoked == n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d expired sessions revoked", revoked, n)
		}
	}
}
