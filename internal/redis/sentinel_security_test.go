package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tidwall/redcon"
)

func TestSentinelNOAUTHDoesNotDiscloseAdminPassword(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var sentAdminPassword atomic.Bool
	go func() {
		_ = redcon.Serve(listener, func(conn redcon.Conn, cmd redcon.Command) {
			for _, arg := range cmd.Args {
				if string(arg) == testPassword {
					sentAdminPassword.Store(true)
				}
			}
			conn.WriteError("NOAUTH Authentication required")
		}, nil, nil)
	}()
	cfg := testConfig(ModeSentinel, []string{"127.0.0.1/32"})
	cfg.MasterName = "primary"
	cfg.Sentinels = []string{listener.Addr().String()}
	server, err := NewServer("redis://admin:"+testPassword+"@127.0.0.1:6379/0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := server.sentinelTopology(ctx); err == nil || !strings.Contains(err.Error(), "NOAUTH") {
		t.Fatalf("Sentinel rejection = %v, want NOAUTH", err)
	}
	if sentAdminPassword.Load() {
		t.Fatal("Sentinel received the Redis data node administrative password")
	}
}

func TestSentinelUsesTLSForRediss(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certificateServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: certificateServer.TLS.Certificates})
	t.Cleanup(func() { tlsListener.Close() })
	var sentAdminPassword, sentSentinelPassword atomic.Bool
	go func() {
		_ = redcon.Serve(tlsListener, func(conn redcon.Conn, cmd redcon.Command) {
			for _, arg := range cmd.Args {
				switch string(arg) {
				case testPassword:
					sentAdminPassword.Store(true)
				case "sentinel-only-password":
					sentSentinelPassword.Store(true)
				}
			}
			if len(cmd.Args) > 0 && strings.EqualFold(string(cmd.Args[0]), "HELLO") {
				conn.WriteError("ERR unknown command HELLO")
				return
			}
			if len(cmd.Args) >= 2 && strings.EqualFold(string(cmd.Args[0]), "SENTINEL") {
				switch strings.ToLower(string(cmd.Args[1])) {
				case "get-master-addr-by-name":
					conn.WriteArray(2)
					conn.WriteBulkString("127.0.0.1")
					conn.WriteBulkString("6379")
					return
				case "replicas", "slaves":
					conn.WriteArray(0)
					return
				}
			}
			conn.WriteString("OK")
		}, nil, nil)
	}()
	cfg := testConfig(ModeSentinel, []string{"127.0.0.1/32"})
	cfg.MasterName = "primary"
	cfg.Sentinels = []string{listener.Addr().String()}
	server, err := NewServer("rediss://admin:"+testPassword+"@127.0.0.1:6379/0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificateServer.Certificate())
	server.options.TLSConfig.RootCAs = roots
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	primary, _, err := server.sentinelTopology(ctx)
	if err != nil || primary != "127.0.0.1:6379" {
		t.Fatalf("TLS Sentinel lookup = %q, %v", primary, err)
	}
	sentinelDSN := "rediss://sentinel:sentinel-only-password@" + listener.Addr().String() + "/0"
	withAuth, err := NewServerWithSentinelDSN("rediss://admin:"+testPassword+"@127.0.0.1:6379/0", cfg, sentinelDSN)
	if err != nil {
		t.Fatal(err)
	}
	withAuth.sentinelOptions.TLSConfig.RootCAs = roots
	primary, _, err = withAuth.sentinelTopology(ctx)
	if err != nil || primary != "127.0.0.1:6379" {
		t.Fatalf("authenticated TLS Sentinel lookup = %q, %v", primary, err)
	}
	if !sentSentinelPassword.Load() || sentAdminPassword.Load() {
		t.Fatalf("Sentinel credential sent = %v; data-node administrator credential sent = %v",
			sentSentinelPassword.Load(), sentAdminPassword.Load())
	}
}

func TestSentinelCredentialValidation(t *testing.T) {
	cfg := testConfig(ModeSentinel, []string{"127.0.0.1/32"})
	cfg.MasterName = "primary"
	cfg.Sentinels = []string{"127.0.0.1:26379"}
	for _, tc := range []struct {
		name string
		dsn  string
		want string
	}{
		{"plaintext", "redis://sentinel:separate@127.0.0.1:26379/0", "rediss://"},
		{"admin password reused", "rediss://sentinel:" + testPassword + "@127.0.0.1:26379/0", "must not reuse"},
		{"unlisted Sentinel", "rediss://sentinel:separate@127.0.0.1:26380/0", "configured Sentinel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewServerWithSentinelDSN("rediss://admin:"+testPassword+"@127.0.0.1:6379/0", cfg, tc.dsn)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewServer error = %v, want %q", err, tc.want)
			}
		})
	}
}
