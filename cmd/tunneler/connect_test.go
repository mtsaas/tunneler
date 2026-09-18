package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
