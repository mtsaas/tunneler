package coordinator

import (
	"database/sql"
	"encoding/json"
	"net"
	"time"

	_ "modernc.org/sqlite" // pure Go, so the binary stays free of cgo
)

// store persists sessions in SQLite so that a coordinator restart neither
// forgets which accounts it must still revoke nor forces users to reconnect
// with new credentials. Passwords are never stored.
type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection queues writers in Go, in order. With more, SQLite's busy
	// handler retries them unfairly, and a burst of revocations (such as the
	// sessions that expired while the coordinator was down) can outwait the
	// busy timeout and lose a write.
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id         TEXT PRIMARY KEY,
		subject    TEXT NOT NULL,
		owner      TEXT NOT NULL,
		cluster    TEXT NOT NULL,
		service    TEXT NOT NULL,
		kind       TEXT NOT NULL,
		database   TEXT NOT NULL,
		username   TEXT NOT NULL,
		labels     TEXT NOT NULL, -- JSON object
		expires_at INTEGER NOT NULL, -- Unix seconds
		revoked    INTEGER NOT NULL DEFAULT 0 -- ended, but its account is not yet known to be dropped
	) STRICT`)
	if err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS clusters (
			name   TEXT PRIMARY KEY,
			issuer TEXT NOT NULL -- the OIDC issuer whose tokens may claim this name, or the role exit:<name> that may
		) STRICT`)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return &store{db}, nil
}

// bindCluster binds a cluster name to owner, an issuer or the role
// exit:<name>, if it is not yet bound, and returns the name's owner
// afterwards.
func (st *store) bindCluster(name, owner string) (bound string, err error) {
	if _, err := st.db.Exec(`INSERT OR IGNORE INTO clusters VALUES (?, ?)`, name, owner); err != nil {
		return "", err
	}
	err = st.db.QueryRow(`SELECT issuer FROM clusters WHERE name = ?`, name).Scan(&bound)
	return bound, err
}

// clusterBindings returns the issuer or role each bound cluster name
// belongs to.
func (st *store) clusterBindings() (map[string]string, error) {
	rows, err := st.db.Query(`SELECT name, issuer FROM clusters`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := make(map[string]string)
	for rows.Next() {
		var name, issuer string
		if err := rows.Scan(&name, &issuer); err != nil {
			return nil, err
		}
		bindings[name] = issuer
	}
	return bindings, rows.Err()
}

// unbindCluster releases a cluster name so that another owner may claim it.
func (st *store) unbindCluster(name string) error {
	_, err := st.db.Exec(`DELETE FROM clusters WHERE name = ?`, name)
	return err
}

func (st *store) insert(s *session) error {
	labels, err := json.Marshal(s.labels)
	if err != nil {
		return err
	}
	_, err = st.db.Exec(`INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		s.info.ID, s.subject, s.info.Owner, s.info.Cluster, s.info.Service, s.info.Kind,
		s.info.Database, s.info.Username, string(labels), s.info.ExpiresAt.Unix())
	return err
}

func (st *store) delete(id string) error {
	_, err := st.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// markRevoked records that a session has ended while its account may live on.
func (st *store) markRevoked(id string) error {
	_, err := st.db.Exec(`UPDATE sessions SET revoked = 1 WHERE id = ?`, id)
	return err
}

// pruneRevoked forgets revoked sessions whose accounts have expired. Such an
// account can no longer log in, and the exit node's reaper drops it unaided.
func (st *store) pruneRevoked(now time.Time) error {
	_, err := st.db.Exec(`DELETE FROM sessions WHERE revoked = 1 AND expires_at < ?`, now.Unix())
	return err
}

func (st *store) load() ([]*session, error) {
	rows, err := st.db.Query(`SELECT id, subject, owner, cluster, service, kind, database, username, labels, expires_at, revoked FROM sessions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*session
	for rows.Next() {
		s := &session{conns: make(map[net.Conn]struct{})}
		var labels string
		var expires int64
		err := rows.Scan(&s.info.ID, &s.subject, &s.info.Owner, &s.info.Cluster, &s.info.Service,
			&s.info.Kind, &s.info.Database, &s.info.Username, &labels, &expires, &s.revoked)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(labels), &s.labels); err != nil {
			return nil, err
		}
		s.info.ExpiresAt = time.Unix(expires, 0)
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}
