package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"maps"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// operatorEnvironment gives the process what an operator might give the exit
// node for its own database: a password, a passfile that matches any server,
// a client certificate, and more besides.
func operatorEnvironment(t *testing.T) {
	dir := t.TempDir()
	passfile := filepath.Join(dir, "pgpass")
	if err := os.WriteFile(passfile, []byte("*:*:*:*:operator-passfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, key := clientCert(t, dir)
	for k, v := range map[string]string{
		"PGPASSWORD": "operator-secret",
		"PGPASSFILE": passfile,
		"PGUSER":     "operator",
		"PGDATABASE": "operator",
		"PGSSLCERT":  cert,
		"PGSSLKEY":   key,
		"PGAPPNAME":  "operator",
		"PGOPTIONS":  "-c search_path=operator",
	} {
		t.Setenv(k, v)
	}
}

// clientCert writes a self-signed client certificate and its key into dir.
func clientCert(t *testing.T, dir string) (cert, key string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, key = filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return cert, key
}

// listen runs a server that does what the attacker of issue #5 does: it asks
// every client for its password in the clear. It reports each login's
// startup parameters, with the password it was sent under "password".
func listen(t *testing.T) (port string, logins <-chan map[string]string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	ch := make(chan map[string]string, 10)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				pkt, err := readStartup(c)
				if err != nil {
					return
				}
				params, err := parseStartup(pkt)
				if err != nil {
					return
				}
				c.Write(message('R', "\x00\x00\x00\x03")) // AuthenticationCleartextPassword
				var hdr [5]byte
				if _, err := io.ReadFull(c, hdr[:]); err == nil && hdr[0] == 'p' {
					body := make([]byte, binary.BigEndian.Uint32(hdr[1:])-4)
					io.ReadFull(c, body)
					params["password"] = strings.TrimSuffix(string(body), "\x00")
				}
				ch <- params
				writeFatal(c, "28P01", "password authentication failed")
			}()
		}
	}()
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port, ch
}

func TestUntrustedServerTakesNothingFromEnvironment(t *testing.T) {
	operatorEnvironment(t)
	port, logins := listen(t)
	ctx := context.Background()

	// A DSN without a password is refused, where libpq would fill one in
	// from the environment and send it to whatever server the DSN names.
	s, err := NewUntrustedServer("postgres://admin@127.0.0.1:" + port + "/app?sslmode=disable")
	if err == nil {
		s.Ping(ctx)
		t.Fatalf("a DSN without a password was accepted, and its server got %v", <-logins)
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("err = %v, want it to say that the password is missing", err)
	}

	// A DSN with its own password sends that, and nothing of the operator's.
	s, err = NewUntrustedServer("postgres://tenant:tenant-pw@127.0.0.1:" + port + "/app?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	s.Ping(ctx)
	want := map[string]string{"user": "tenant", "database": "app", "password": "tenant-pw"}
	if got := <-logins; !maps.Equal(got, want) {
		t.Errorf("the server got %v, want %v", got, want)
	}

	// Nor does the operator's client certificate go along.
	s, err = NewUntrustedServer("postgres://tenant:tenant-pw@127.0.0.1:" + port + "/app?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if tc := s.cfg.TLSConfig; tc == nil {
		t.Error("sslmode=require gave no TLS")
	} else if len(tc.Certificates) != 0 {
		t.Errorf("TLS would present %d client certificates, want none", len(tc.Certificates))
	}

	// The operator's own DSN is completed from the environment, as libpq
	// would; the file-configured services rely on it.
	s, err = NewServer("postgres://admin@127.0.0.1:" + port + "/app?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.Password != "operator-secret" {
		t.Errorf("the operator's DSN got password %q, want the environment's", s.cfg.Password)
	}

	// PGSERVICE cannot be overridden, so while it is set the DSN is refused
	// rather than completed from the operator's service file.
	servicefile := filepath.Join(t.TempDir(), "pg_service.conf")
	os.WriteFile(servicefile, []byte("[admin]\nsslmode=disable\n"), 0o600)
	t.Setenv("PGSERVICEFILE", servicefile)
	t.Setenv("PGSERVICE", "admin")
	if _, err := NewUntrustedServer("postgres://tenant:tenant-pw@127.0.0.1:" + port + "/app"); err == nil {
		t.Error("a DSN was completed from the operator's service file")
	}
}

// TestUntrustedServerConnects logs in to a real server with what
// NewUntrustedServer builds:
//
//	TUNNELER_TEST_DSN=postgres://postgres:pw@localhost:5432/postgres?sslmode=disable go test ./internal/postgres/
func TestUntrustedServerConnects(t *testing.T) {
	dsn := os.Getenv("TUNNELER_TEST_DSN")
	if dsn == "" {
		t.Skip("TUNNELER_TEST_DSN not set")
	}
	s, err := NewUntrustedServer(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUntrustedServerRefuses(t *testing.T) {
	operatorEnvironment(t)
	for _, tt := range []struct{ dsn, why string }{
		{"host=db user=tenant password=s3cret dbname=app", "not a URL"},
		{"postgres://tenant:s3cret@db:bad/app", "not a URL"},
		{"postgres://tenant@db/app", "password"},
		{"postgres://:s3cret@db/app", "user"},
		{"postgres://tenant:s3cret@/app", "host"},
		{"postgres://tenant:s3cret@db1,db2/app", "only one host"},
		{"postgres://tenant@db/app?password=s3cret", "password"},
		{"postgres://tenant:s3cret@db/app?passfile=/etc/pgpass", `"passfile"`},
		{"postgres://tenant:s3cret@db/app?service=admin", `"service"`},
		{"postgres://tenant:s3cret@db/app?servicefile=/etc/pg_service.conf", `"servicefile"`},
		{"postgres://tenant:s3cret@db/app?sslkey=/etc/key.pem", `"sslkey"`},
		{"postgres://tenant:s3cret@db/app?sslrootcert=/etc/ca.pem", `"sslrootcert"`},
		{"postgres://tenant:s3cret@db/app?sslmode=bogus", "the dsn is not valid: failed to configure TLS (sslmode is invalid)"},
	} {
		_, err := NewUntrustedServer(tt.dsn)
		if err == nil || !strings.Contains(err.Error(), tt.why) {
			t.Errorf("%s: err = %v, want it to mention %s", tt.dsn, err, tt.why)
		} else if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: err = %v quotes the password", tt.dsn, err)
		}
	}
}
