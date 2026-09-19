package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestDropRoleDoesNotEscalate reproduces the privilege escalation that
// reassigning a dropped role's objects to the administrative role allows, and
// checks that dropping a role no longer opens it. It needs a real Postgres:
//
//	docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:17
//	TUNNELER_TEST_DSN=postgres://postgres:pw@localhost:5432/postgres go test ./internal/postgres/
//
// The administrative role is set up as docs/services/postgres.md describes: a
// non-superuser with CREATEROLE, holding ADMIN OPTION on a grantable role. A
// session creates a SECURITY DEFINER function that grants roles and clears
// expiry, then ends; a later session must not be able to run it to escalate.
func TestDropRoleDoesNotEscalate(t *testing.T) {
	adminDSN, sup := testAdmin(t)

	srv, err := NewServer(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A session that is a member of the grantable role, so it can create in
	// the schema, leaves a SECURITY DEFINER function behind.
	victim := RolePrefix + "esc_victim"
	mustCreate(t, srv, Role{Name: victim, Password: "pw", ValidUntil: future(), MemberOf: []string{"rw_esc"}})
	run(t, sup, victim, "pw", `CREATE FUNCTION app_esc.pwn() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS
		$$ BEGIN EXECUTE 'GRANT rw_esc TO ' || quote_ident(session_user);
		         EXECUTE 'ALTER ROLE ' || quote_ident(session_user) || ' VALID UNTIL ''infinity'''; END $$`)
	if err := srv.DropRole(ctx, victim); err != nil {
		t.Fatalf("dropping the victim role: %v", err)
	}

	// A later session, granted nothing, tries to run what the victim left.
	attacker := RolePrefix + "esc_attacker"
	mustCreate(t, srv, Role{Name: attacker, Password: "pw", ValidUntil: future()})
	t.Cleanup(func() { srv.DropRole(context.Background(), attacker) })
	if err := run(t, sup, attacker, "pw", "SELECT app_esc.pwn()"); err == nil {
		t.Error("the function the dropped session left behind still runs")
	}
	if pgHasRole(t, sup, attacker, "rw_esc") {
		t.Error("the attacker granted itself a role it was never given")
	}
	// The attacker was created with a finite expiry; the escalation clears it.
	if exists(t, sup, "SELECT coalesce(rolvaliduntil = 'infinity', true) FROM pg_roles WHERE rolname = $1", attacker) {
		t.Error("the attacker cleared its own expiry")
	}
}

// TestReapDoesNotEscalate checks that Reap, the cleanup of last resort, drops
// an expired role's objects the same safe way DropRole does.
func TestReapDoesNotEscalate(t *testing.T) {
	adminDSN, sup := testAdmin(t)

	srv, err := NewServer(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	victim := RolePrefix + "reap_victim"
	mustCreate(t, srv, Role{Name: victim, Password: "pw", ValidUntil: future(), MemberOf: []string{"rw_esc"}})
	run(t, sup, victim, "pw", `CREATE FUNCTION app_esc.pwn_reap() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS
		$$ BEGIN EXECUTE 'GRANT rw_esc TO ' || quote_ident(session_user); END $$`)
	// Expire it: Reap sweeps up roles whose expiry has passed, left behind by
	// sessions that were never cleanly revoked.
	exec(t, sup, "ALTER ROLE "+pgx.Identifier{victim}.Sanitize()+" VALID UNTIL '2000-01-01'")
	if _, err := srv.Reap(ctx); err != nil {
		t.Fatalf("reaping: %v", err)
	}
	if exists(t, sup, "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)", victim) {
		t.Fatal("Reap did not drop the expired role")
	}
	if exists(t, sup, "SELECT EXISTS (SELECT FROM pg_proc WHERE proname = 'pwn_reap')") {
		t.Error("Reap left the expired session's function behind")
	}
}

// testAdmin creates the grantable role, a schema it may create objects in, and
// a non-superuser administrative role set up as the docs describe, and returns
// the administrative DSN and a superuser connection to check results with. It
// removes all of it when the test ends.
func testAdmin(t *testing.T) (string, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv("TUNNELER_TEST_DSN")
	if dsn == "" {
		t.Skip("TUNNELER_TEST_DSN not set")
	}
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sup, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sup.Close(context.Background()) })

	// Start from a clean slate in case an earlier run was interrupted.
	exec(t, sup, "DROP SCHEMA IF EXISTS app_esc CASCADE")
	exec(t, sup, "DROP ROLE IF EXISTS "+RolePrefix+"esc_victim")
	exec(t, sup, "DROP ROLE IF EXISTS "+RolePrefix+"esc_attacker")
	exec(t, sup, "DROP ROLE IF EXISTS "+RolePrefix+"reap_victim")
	exec(t, sup, "DROP ROLE IF EXISTS tnl_admin_esc")
	exec(t, sup, "DROP ROLE IF EXISTS rw_esc")

	exec(t, sup, "CREATE ROLE rw_esc NOLOGIN")
	exec(t, sup, "CREATE SCHEMA app_esc")
	exec(t, sup, "GRANT USAGE, CREATE ON SCHEMA app_esc TO rw_esc")
	exec(t, sup, "GRANT USAGE ON SCHEMA app_esc TO PUBLIC") // so a later role can name the function
	exec(t, sup, "CREATE ROLE tnl_admin_esc LOGIN PASSWORD 'pw' CREATEROLE")
	exec(t, sup, "GRANT rw_esc TO tnl_admin_esc WITH ADMIN OPTION")
	t.Cleanup(func() {
		c, _ := pgx.ConnectConfig(context.Background(), cfg)
		if c == nil {
			return
		}
		defer c.Close(context.Background())
		for _, stmt := range []string{
			"DROP SCHEMA IF EXISTS app_esc CASCADE",
			"DROP ROLE IF EXISTS " + RolePrefix + "esc_victim",
			"DROP ROLE IF EXISTS " + RolePrefix + "esc_attacker",
			"DROP ROLE IF EXISTS " + RolePrefix + "reap_victim",
			"DROP ROLE IF EXISTS tnl_admin_esc",
			"DROP ROLE IF EXISTS rw_esc",
		} {
			c.Exec(context.Background(), stmt)
		}
	})

	admin := *cfg
	admin.User, admin.Password = "tnl_admin_esc", "pw"
	adminDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		admin.User, admin.Password, admin.Host, admin.Port, admin.Database)
	return adminDSN, sup
}

func future() time.Time { return time.Now().Add(time.Hour) }

func mustCreate(t *testing.T, s *Server, r Role) {
	t.Helper()
	if err := s.CreateRole(context.Background(), r); err != nil {
		t.Fatalf("creating role %s: %v", r.Name, err)
	}
}

// run connects as the given login and runs one statement, so that
// session_user is that login as it would be for a real client.
func run(t *testing.T, ref *pgx.Conn, user, password, stmt string) error {
	t.Helper()
	cfg := ref.Config().Copy()
	cfg.User, cfg.Password = user, password
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connecting as %s: %v", user, err)
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(context.Background(), stmt)
	return err
}

func exec(t *testing.T, conn *pgx.Conn, stmt string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

func exists(t *testing.T, conn *pgx.Conn, query string, args ...any) bool {
	t.Helper()
	var b bool
	if err := conn.QueryRow(context.Background(), query, args...).Scan(&b); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return b
}

func pgHasRole(t *testing.T, conn *pgx.Conn, member, role string) bool {
	t.Helper()
	return exists(t, conn, "SELECT pg_has_role($1, $2, 'MEMBER')", member, role)
}
