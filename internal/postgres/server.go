// Package postgres provisions short-lived Postgres roles and proxies the
// Postgres wire protocol with statement auditing.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// RolePrefix begins the name of every role this package creates. Roles with
// this prefix are considered owned by the tunnel and are dropped once expired.
const RolePrefix = "tnl_"

// Server is a Postgres database that roles are provisioned on. It is used
// from inside the database's cluster, by the exit node.
type Server struct {
	cfg *pgx.ConnConfig
}

// NewServer returns a Server for the administrative DSN. The DSN's role must
// be allowed to create roles and to grant every role handed to CreateRole.
func NewServer(dsn string) (*Server, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg}, nil
}

// Addr returns the server's host:port. Unlike the DSN it is safe to log.
func (s *Server) Addr() string {
	return net.JoinHostPort(s.cfg.Host, strconv.Itoa(int(s.cfg.Port)))
}

// Database returns the database that sessions are confined to.
func (s *Server) Database() string { return s.cfg.Database }

// Role describes a login role to provision.
type Role struct {
	Name       string // must begin with RolePrefix
	Password   string
	ValidUntil time.Time // Postgres itself refuses logins after this
	MemberOf   []string  // roles to grant, which carry the actual privileges
}

// CreateRole creates a login role.
func (s *Server) CreateRole(ctx context.Context, r Role) error {
	if !strings.HasPrefix(r.Name, RolePrefix) {
		return fmt.Errorf("postgres: role name %q lacks prefix %q", r.Name, RolePrefix)
	}
	conn, err := pgx.ConnectConfig(ctx, s.cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	// Utility statements take no parameters, so values are quoted by hand.
	// ponytail: the password is visible to the server's statement log if
	// log_statement includes ddl. Send a precomputed SCRAM verifier instead
	// if that matters.
	password, err := conn.PgConn().EscapeString(r.Password)
	if err != nil {
		return err
	}
	name := pgx.Identifier{r.Name}.Sanitize()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' VALID UNTIL '%s'",
		name, password, r.ValidUntil.UTC().Format(time.RFC3339)))
	if err != nil {
		return err
	}
	for _, parent := range r.MemberOf {
		if _, err := tx.Exec(ctx, fmt.Sprintf("GRANT %s TO %s", pgx.Identifier{parent}.Sanitize(), name)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DropRole disconnects and drops a role created by CreateRole. Objects the
// role created are kept and reassigned to the administrative role. Dropping
// a role that does not exist is not an error.
func (s *Server) DropRole(ctx context.Context, name string) error {
	conn, err := pgx.ConnectConfig(ctx, s.cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	return dropRole(ctx, conn, name)
}

func dropRole(ctx context.Context, conn *pgx.Conn, name string) error {
	if !strings.HasPrefix(name, RolePrefix) {
		return fmt.Errorf("postgres: refusing to drop role %q without prefix %q", name, RolePrefix)
	}
	var exists bool
	err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)", name).Scan(&exists)
	if err != nil || !exists {
		return err
	}

	ident := pgx.Identifier{name}.Sanitize()
	literal, err := conn.PgConn().EscapeString(name)
	if err != nil {
		return err
	}
	literal = "'" + literal + "'"
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, stmt := range []string{
		// A non-superuser admin must be a member of the role to signal its
		// backends and reassign its objects.
		"GRANT " + ident + " TO CURRENT_USER",
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = " + literal,
		// ponytail: REASSIGN and DROP OWNED act on the current database only.
		// That suffices because Proxy confines sessions to this database.
		"REASSIGN OWNED BY " + ident + " TO CURRENT_USER",
		"DROP OWNED BY " + ident,
		"DROP ROLE " + ident,
	} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Reap drops every tunnel-owned role whose VALID UNTIL has passed, and
// returns the names of those it dropped. Such roles are left behind by
// sessions that were never cleanly revoked, for example after a crash.
func (s *Server) Reap(ctx context.Context) ([]string, error) {
	conn, err := pgx.ConnectConfig(ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx,
		`SELECT rolname FROM pg_roles WHERE starts_with(rolname, $1) AND rolvaliduntil < now()`, RolePrefix)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	var dropped []string
	var errs []error
	for _, name := range names {
		if err := dropRole(ctx, conn, name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		dropped = append(dropped, name)
	}
	return dropped, errors.Join(errs...)
}
