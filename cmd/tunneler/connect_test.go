package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
)

func TestListenStable(t *testing.T) {
	s := &api.Session{Cluster: "prod", Service: "shop-postgres"}
	first, err := listenStable(s)
	if err != nil {
		t.Fatal(err)
	}
	port := first.Addr().(*net.TCPAddr).Port

	// While the usual port is taken, another is used rather than failing.
	second, err := listenStable(s)
	if err != nil || second.Addr().(*net.TCPAddr).Port == port {
		t.Fatalf("second listener: %v, %v", second, err)
	}
	second.Close()
	first.Close()

	// Once free again, the same service gets the same port.
	again, err := listenStable(s)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if got := again.Addr().(*net.TCPAddr).Port; got != port {
		t.Errorf("port = %d, then %d; want the same", port, got)
	}
}

func TestRunCommandEnvironment(t *testing.T) {
	out := filepath.Join(t.TempDir(), "env")
	s := &api.Session{Kind: "postgres", Username: "tnl_me", Password: "s3cret", Database: "orders"}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}
	err := runSessionCommand(context.Background(),
		[]string{"sh", "-c", `echo "$PGHOST $PGPORT $PGUSER $PGPASSWORD $PGDATABASE $PGSSLMODE $DATABASE_URL" > ` + out}, s, addr)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	want := "127.0.0.1 5555 tnl_me s3cret orders disable postgres://tnl_me:s3cret@127.0.0.1:5555/orders?sslmode=disable"
	if strings.TrimSpace(string(got)) != want {
		t.Errorf("environment = %q\nwant          %q", got, want)
	}

	// The command's own exit status comes back, for main to exit with.
	if err := runSessionCommand(context.Background(), []string{"sh", "-c", "exit 3"}, s, addr); err == nil || !strings.Contains(err.Error(), "3") {
		t.Errorf("exit status 3: err = %v", err)
	}
}

func TestSessionCommandArgs(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555}
	s := &api.Session{Kind: "redis", Username: "tnl_me"}
	command := []string{"redis-cli", "GET", "key"}
	want := []string{"-h", "127.0.0.1", "-p", "5555", "--user", "tnl_me", "GET", "key"}
	if got := sessionCommandArgs(command, s, addr); !reflect.DeepEqual(got, want) {
		t.Errorf("standalone args = %v, want %v", got, want)
	}
	s.RedisMode = "sentinel"
	if got := sessionCommandArgs(command, s, addr); !reflect.DeepEqual(got, want) {
		t.Errorf("sentinel args = %v, want %v", got, want)
	}

	s.RedisMode = "cluster"
	want = []string{"-h", "127.0.0.1", "-p", "5555", "--user", "tnl_me", "-c", "GET", "key"}
	if got := sessionCommandArgs(command, s, addr); !reflect.DeepEqual(got, want) {
		t.Errorf("cluster args = %v, want %v", got, want)
	}

	command = []string{"sh", "-c", "redis-cli -u \"$REDIS_URL\""}
	if got := sessionCommandArgs(command, s, addr); !reflect.DeepEqual(got, command[1:]) {
		t.Errorf("other command args = %v, want %v", got, command[1:])
	}
}

func TestRedisCLICommand(t *testing.T) {
	for _, name := range []string{"redis-server", "redis-cli"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not installed", name)
		}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	listener.Close()
	port := strconv.Itoa(addr.Port)
	server := exec.Command("redis-server", "--bind", "127.0.0.1", "--port", port,
		"--save", "", "--appendonly", "no", "--loglevel", "warning")
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr.String(), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Redis did not listen on %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, args := range [][]string{
		{"ACL", "SETUSER", "tnl_test", "reset", "on", ">secret", "+ping"},
		{"ACL", "SETUSER", "default", "off"},
	} {
		output, err := exec.Command("redis-cli", append([]string{"-e", "-h", "127.0.0.1", "-p", port}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("configure Redis ACL: %v: %s", err, output)
		}
	}

	s := &api.Session{Kind: "redis", Username: "tnl_test", Password: "secret", Database: "0"}
	if err := runSessionCommand(context.Background(), []string{"redis-cli", "-e", "PING"}, s, addr); err != nil {
		t.Fatalf("redis-cli did not authenticate as the temporary user: %v", err)
	}
}
