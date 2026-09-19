// Package postgres provisions short-lived Postgres roles and proxies the
// Postgres wire protocol with statement auditing.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
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
//
// As in libpq, whatever the DSN leaves out is taken from the PG* environment
// variables and from files such as ~/.pgpass, so the DSN must be the
// operator's own. For any other, use NewUntrustedServer.
func NewServer(dsn string) (*Server, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg}, nil
}

// untrustedQuery is what the query of a DSN given to NewUntrustedServer may
// set. Anything else would name a file on the exit node, such as a passfile
// or a client key, or is simply not needed.
var untrustedQuery = []string{"sslmode", "connect_timeout"}

// NewUntrustedServer is NewServer for a DSN that someone other than the
// operator may have written, such as a TunnelService's. Nothing is taken from
// the environment or the files that NewServer would consult: they hold the
// operator's credentials, and the DSN's author chooses the server that they
// would be sent to. So the DSN must give its own host, user and password.
//
// ponytail: the DSN must be a postgres:// URL, the form the docs give.
// libpq's keyword/value form would need a parser of its own here, since pgx's
// is what merges the environment in.
func NewUntrustedServer(dsn string) (*Server, error) {
	u, err := url.Parse(dsn)
	var query url.Values
	if err == nil {
		query, err = url.ParseQuery(u.RawQuery)
	}
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		// Not err, which quotes the DSN, password and all.
		return nil, errors.New("the dsn is not a URL of the form postgres://user:password@host:port/database")
	}
	password, _ := u.User.Password()
	switch {
	case strings.Contains(u.Host, ","):
		return nil, errors.New("the dsn may name only one host")
	case u.Hostname() == "", u.User.Username() == "", password == "":
		return nil, errors.New("the dsn must give its own host, user and password: nothing is taken from the exit node's environment or files")
	}

	// Every setting that pgx would otherwise take from the environment or a
	// default file is given, if only as empty, so that pgx looks no further.
	// PGSERVICE cannot be overridden this way. With servicefile empty, it
	// fails the parse instead of reading the operator's service file.
	settings := map[string]string{
		"host": u.Hostname(), "port": u.Port(), "dbname": strings.TrimPrefix(u.Path, "/"), "user": u.User.Username(),
		"password": "", "passfile": "", "servicefile": "",
		"sslmode": "", "sslcert": "", "sslkey": "", "sslpassword": "", "sslrootcert": "", "sslsni": "", "sslnegotiation": "",
		"connect_timeout": "0", "target_session_attrs": "any", "channel_binding": "", "require_auth": "",
		"min_protocol_version": "", "max_protocol_version": "",
	}
	for key, values := range query {
		if !slices.Contains(untrustedQuery, key) {
			return nil, fmt.Errorf("the dsn may not set %q: nothing but %s", key, strings.Join(untrustedQuery, " and "))
		}
		settings[key] = values[len(values)-1]
	}
	var conninfo strings.Builder
	quote := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	for _, key := range slices.Sorted(maps.Keys(settings)) {
		fmt.Fprintf(&conninfo, "%s='%s' ", key, quote.Replace(settings[key]))
	}
	cfg, err := pgx.ParseConfig(conninfo.String())
	if err != nil {
		// Without the conninfo that the error quotes, which the DSN's author
		// never wrote.
		why := err.Error()
		if _, after, ok := strings.Cut(why, "`: "); ok {
			why = after
		}
		return nil, fmt.Errorf("the dsn is not valid: %s", why)
	}
	// The password is set only now, so that no parse error can quote it.
	cfg.Password = password
	// And PGAPPNAME, PGOPTIONS and PGTZ arrive as run-time parameters, which
	// the DSN has no way to set.
	cfg.RuntimeParams = map[string]string{}
	return &Server{cfg: cfg}, nil
}

// Addr returns the server's host:port. Unlike the DSN it is safe to log.
func (s *Server) Addr() string {
	return net.JoinHostPort(s.cfg.Host, strconv.Itoa(int(s.cfg.Port)))
}

// Ping connects with the administrative credentials and disconnects.
func (s *Server) Ping(ctx context.Context) error {
	conn, err := pgx.ConnectConfig(ctx, s.cfg)
	if err != nil {
		return err
	}
	return conn.Close(ctx)
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
