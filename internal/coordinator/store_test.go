package coordinator

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

// TestStoreDropsEarlierSessions opens a database that an earlier
// coordinator wrote, whose sessions did not record their roles. The
// sessions are gone and the cluster bindings stay. A session saved now
// keeps its roles when the database is opened again.
func TestStoreDropsEarlierSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE sessions (id TEXT PRIMARY KEY, subject TEXT NOT NULL, owner TEXT NOT NULL, cluster TEXT NOT NULL,
			service TEXT NOT NULL, kind TEXT NOT NULL, database TEXT NOT NULL, username TEXT NOT NULL,
			labels TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0) STRICT;
		CREATE TABLE clusters (name TEXT PRIMARY KEY, issuer TEXT NOT NULL) STRICT;
		INSERT INTO sessions VALUES ('old', '1', 'alice@example.com', 'prod', 'orders', 'postgres', 'orders',
			'tnl_alice_example_com_x', '{"team":"shop"}', 4102444800, 0);
		INSERT INTO clusters VALUES ('prod', 'exit:prod')`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	st, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if sessions, err := st.load(); err != nil || len(sessions) != 0 {
		t.Errorf("sessions of the earlier coordinator: %v, %v; want none", sessions, err)
	}
	if bound, err := st.clusterBindings(); err != nil || bound["prod"] != "exit:prod" {
		t.Errorf("cluster bindings: %v, %v; want prod still bound", bound, err)
	}
	s := &session{info: api.Session{ID: "new", ExpiresAt: time.Now().Add(time.Hour)}, roles: []string{"readonly", "readwrite"}}
	if err := st.insert(s); err != nil {
		t.Fatal(err)
	}
	st.db.Close()

	st, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	sessions, err := st.load()
	if err != nil || len(sessions) != 1 || !slices.Equal(sessions[0].roles, s.roles) {
		t.Errorf("after reopening: %v, %v; want the session with roles %q", sessions, err, s.roles)
	}
}
