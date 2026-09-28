package redis

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	client "github.com/redis/go-redis/v9"
	"github.com/tidwall/redcon"

	"github.com/mtsaas/tunneler/internal/api"
)

const testPassword = "test-admin-password"

func requireRedis(t *testing.T) {
	t.Helper()
	for _, name := range []string{"redis-server", "redis-cli"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not installed", name)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func runRedis(t *testing.T, args ...string) string {
	t.Helper()
	return runRedisAtPort(t, freePort(t), args...)
}

func runRedisAtPort(t *testing.T, port int, args ...string) string {
	t.Helper()
	dir := t.TempDir()
	args = append([]string{
		"--bind", "127.0.0.1", "--port", strconv.Itoa(port),
		"--save", "", "--appendonly", "no", "--protected-mode", "no",
		"--loglevel", "warning", "--dir", dir,
	}, args...)
	cmd := exec.Command("redis-server", args...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitRedis(t, addr)
	return addr
}

func freeClusterPort(t *testing.T) int {
	t.Helper()
	for {
		port := freePort(t)
		if port < 55000 {
			return port
		}
	}
}

func waitRedis(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Redis did not listen on %s", addr)
}

func configureAdmin(t *testing.T, addr string) {
	t.Helper()
	ctx := context.Background()
	c := client.NewClient(&client.Options{Addr: addr, Protocol: 2})
	defer c.Close()
	if err := c.Do(ctx, "ACL", "SETUSER", "admin", "reset", "on", ">"+testPassword, "+@all", "~*", "&*").Err(); err != nil {
		t.Fatal(err)
	}
	if err := c.Do(ctx, "ACL", "SETUSER", "default", "off").Err(); err != nil {
		t.Fatal(err)
	}
}

func adminDSN(addr string) string {
	return "redis://admin:" + testPassword + "@" + addr + "/0"
}

func createTestUser(t *testing.T, server *Server) api.Role {
	t.Helper()
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	role := api.Role{
		Name:       fmt.Sprintf("%s%s_testuser01", RolePrefix, strconv.FormatInt(expiry.Unix(), 36)),
		Password:   "test-user-password",
		ValidUntil: expiry,
		MemberOf:   []string{"readwrite"},
	}
	if err := server.CreateRole(context.Background(), role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.DropRole(context.Background(), role.Name); err != nil {
			t.Errorf("dropping test user: %v", err)
		}
	})
	return role
}

func testConfig(mode string, allowed []string) Config {
	return Config{
		Mode:         mode,
		AllowedNodes: allowed,
		ACLProfiles: map[string][]string{
			"readwrite": {"+get", "+set", "+ping", "+command", "+cluster|slots", "+cluster|shards", "~*"},
		},
	}
}

func proxyListener(t *testing.T, options ProxyOptions, dial func(context.Context) (net.Conn, error)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go Proxy(context.Background(), conn, dial, options)
		}
	}()
	return listener.Addr().String()
}

func testProxyOptions(role api.Role, mode string) ProxyOptions {
	return ProxyOptions{
		Username: role.Name,
		Mode:     mode,
		Audit:    func(string, []string) error { return nil },
	}
}

func TestStandalone(t *testing.T) {
	requireRedis(t)
	addr := runRedis(t)
	configureAdmin(t, addr)
	server, err := NewServer(adminDSN(addr), testConfig(ModeStandalone, nil))
	if err != nil {
		t.Fatal(err)
	}
	role := createTestUser(t, server)
	proxyAddr := proxyListener(t, testProxyOptions(role, ModeStandalone), server.Connect)
	ctx := context.Background()
	c := client.NewClient(&client.Options{Addr: proxyAddr, Username: role.Name, Password: role.Password, Protocol: 2})
	defer c.Close()
	if err := c.Set(ctx, "single:key", "value", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if value, err := c.Get(ctx, "single:key").Result(); err != nil || value != "value" {
		t.Fatalf("GET = %q, %v", value, err)
	}
	if err := c.Del(ctx, "single:key").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("Redis ACL should deny DEL: %v", err)
	}
	if err := c.Do(ctx, "SELECT", 1).Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("Redis ACL should deny SELECT: %v", err)
	}
	// AUTH is credential verification, not a command permission. Redis allows
	// a connection to switch users when it knows another user's password.
	direct := client.NewClient(&client.Options{Addr: addr, Username: role.Name, Password: role.Password, Protocol: 2})
	defer direct.Close()
	if err := direct.Do(ctx, "AUTH", "admin", testPassword).Err(); err != nil {
		t.Fatalf("Redis itself must allow a credentialed user switch: %v", err)
	}
	if err := c.Do(ctx, "AUTH", "admin", testPassword).Err(); err == nil || !strings.Contains(err.Error(), "temporary user") {
		t.Fatalf("the proxy must keep the connection bound to its audited identity: %v", err)
	}
}

func TestMandatoryDenies(t *testing.T) {
	requireRedis(t)
	addr := runRedis(t)
	c := client.NewClient(&client.Options{Addr: addr, Protocol: 2})
	defer c.Close()
	for _, rule := range mandatoryDenies {
		if err := c.Do(context.Background(), "ACL", "SETUSER", "test", "reset", rule).Err(); err != nil {
			t.Errorf("ACL rule %s: %v", rule, err)
		}
	}
}

func TestGenerationChangesAfterRestart(t *testing.T) {
	requireRedis(t)
	port := freePort(t)
	addr := runRedisAtPort(t, port)
	configureAdmin(t, addr)
	server, err := NewServer(adminDSN(addr), testConfig(ModeStandalone, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := server.Generation()
	if before == "" {
		t.Fatal("Redis generation is empty")
	}

	admin := client.NewClient(&client.Options{Addr: addr, Username: "admin", Password: testPassword, Protocol: 2, MaxRetries: -1})
	_ = admin.Do(context.Background(), "SHUTDOWN", "NOSAVE").Err()
	admin.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			break
		}
		conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	runRedisAtPort(t, port)
	configureAdmin(t, addr)
	if err := server.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if server.Generation() == before {
		t.Fatal("Redis restart did not change the advertised generation")
	}
}

func TestSentinel(t *testing.T) {
	requireRedis(t)
	primary := runRedis(t)
	configureAdmin(t, primary)
	primaryPort, _ := strconv.Atoi(strings.Split(primary, ":")[1])
	replica := runRedis(t,
		"--replicaof", "127.0.0.1", strconv.Itoa(primaryPort),
		"--masteruser", "admin", "--masterauth", testPassword,
	)
	configureAdmin(t, replica)
	sentinelPort := freePort(t)
	sentinelConfig := filepath.Join(t.TempDir(), "sentinel.conf")
	configuration := fmt.Sprintf("port %d\nbind 127.0.0.1\nprotected-mode no\nsentinel monitor testmaster 127.0.0.1 %d 1\nsentinel auth-user testmaster admin\nsentinel auth-pass testmaster %s\n", sentinelPort, primaryPort, testPassword)
	if err := os.WriteFile(sentinelConfig, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("redis-server", sentinelConfig, "--sentinel")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	sentinel := net.JoinHostPort("127.0.0.1", strconv.Itoa(sentinelPort))
	waitRedis(t, sentinel)
	cfg := testConfig(ModeSentinel, []string{"127.0.0.1/32"})
	cfg.MasterName = "testmaster"
	cfg.Sentinels = []string{sentinel}
	server, err := NewServer(adminDSN(primary), cfg)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(server.Nodes()) < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if err := server.Ping(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	role := createTestUser(t, server)
	proxyAddr := proxyListener(t, testProxyOptions(role, ModeSentinel), server.Connect)
	c := client.NewClient(&client.Options{Addr: proxyAddr, Username: role.Name, Password: role.Password, Protocol: 2})
	defer c.Close()
	if err := c.Set(context.Background(), "sentinel:key", "value", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if len(server.Nodes()) < 2 {
		t.Fatal("Sentinel did not discover the replica")
	}
	sentinelClient := client.NewSentinelClient(&client.Options{Addr: sentinel, Protocol: 2})
	defer sentinelClient.Close()
	if err := sentinelClient.Failover(context.Background(), "testmaster").Err(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := server.Ping(context.Background()); err == nil {
			server.mu.RLock()
			newPrimary := server.primary
			server.mu.RUnlock()
			if newPrimary == replica {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	server.mu.RLock()
	newPrimary := server.primary
	server.mu.RUnlock()
	if newPrimary != replica {
		t.Fatalf("Sentinel did not promote %s; primary is %s", replica, newPrimary)
	}
	if err := c.Set(context.Background(), "sentinel:after-failover", "value", 0).Err(); err != nil {
		t.Fatalf("writing through the new primary: %v", err)
	}
}

func TestCluster(t *testing.T) {
	requireRedis(t)
	addresses := make([]string, 3)
	for i := range addresses {
		addresses[i] = runRedisAtPort(t, freeClusterPort(t), "--cluster-enabled", "yes", "--cluster-config-file", "nodes.conf")
	}
	args := append([]string{"--cluster", "create"}, addresses...)
	args = append(args, "--cluster-yes")
	output, err := exec.Command("redis-cli", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("forming Redis Cluster: %v\n%s", err, output)
	}
	for _, addr := range addresses {
		configureAdmin(t, addr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready := true
		for _, addr := range addresses {
			admin := client.NewClient(&client.Options{Addr: addr, Username: "admin", Password: testPassword, Protocol: 2})
			info, err := admin.ClusterInfo(context.Background()).Result()
			admin.Close()
			if err != nil || !strings.Contains(info, "cluster_state:ok") {
				ready = false
				break
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Redis Cluster did not become healthy")
		}
		time.Sleep(100 * time.Millisecond)
	}
	server, err := NewServer(adminDSN(addresses[0]), testConfig(ModeCluster, []string{"127.0.0.1/32"}))
	if err != nil {
		t.Fatal(err)
	}
	role := createTestUser(t, server)
	nodes := server.Nodes()
	ports := make(map[string]int, len(nodes))
	listeners := make([]net.Listener, len(nodes))
	for i, node := range nodes {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners[i] = listener
		ports[node.ID] = listener.Addr().(*net.TCPAddr).Port
		t.Cleanup(func() { listener.Close() })
	}
	for i, node := range nodes {
		options := testProxyOptions(role, ModeCluster)
		options.Nodes = nodes
		options.Ports = ports
		listener := listeners[i]
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go Proxy(context.Background(), conn, func(ctx context.Context) (net.Conn, error) {
					return server.ConnectNode(ctx, node.ID)
				}, options)
			}
		}()
	}
	seed := listeners[0].Addr().String()
	c := client.NewClusterClient(&client.ClusterOptions{
		Addrs: []string{seed}, Username: role.Name, Password: role.Password, Protocol: 2,
	})
	defer c.Close()
	ctx := context.Background()
	for _, key := range []string{"cluster:one", "cluster:two", "cluster:three"} {
		if err := c.Set(ctx, key, key, 0).Err(); err != nil {
			t.Fatal(err)
		}
		if value, err := c.Get(ctx, key).Result(); err != nil || value != key {
			t.Fatalf("GET %s = %q, %v", key, value, err)
		}
	}
	single := client.NewClient(&client.Options{Addr: seed, Username: role.Name, Password: role.Password, Protocol: 2, MaxRetries: -1})
	defer single.Close()
	shards, err := single.ClusterShards(ctx).Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range shards {
		for _, node := range shard.Nodes {
			if node.Endpoint != "127.0.0.1" || ports[node.ID] != int(node.Port) {
				t.Fatalf("untranslated CLUSTER SHARDS node: %+v", node)
			}
		}
	}
	slots, err := single.ClusterSlots(ctx).Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range slots {
		for _, node := range slot.Nodes {
			if node.Addr == "" || !strings.HasPrefix(node.Addr, "127.0.0.1:") {
				t.Fatalf("untranslated CLUSTER SLOTS node: %+v", node)
			}
		}
	}
	foundRedirect := false
	for i := 0; i < 100; i++ {
		err := single.Get(ctx, fmt.Sprintf("moved:%d", i)).Err()
		if err != nil && strings.HasPrefix(err.Error(), "MOVED ") {
			if !strings.Contains(err.Error(), " 127.0.0.1:") {
				t.Fatalf("untranslated MOVED reply: %v", err)
			}
			foundRedirect = true
			break
		}
	}
	if !foundRedirect {
		t.Fatal("did not observe a MOVED reply from the seed node")
	}
}

func TestAskRedirectTranslation(t *testing.T) {
	upstream := "10.0.0.1:6379"
	_, reply := redcon.ReadNextRESP([]byte("-ASK 123 " + upstream + "\r\n"))
	translated, err := translateReply("GET", reply, nil, map[string]string{upstream: "127.0.0.1:49152"})
	if err != nil {
		t.Fatal(err)
	}
	if string(translated) != "-ASK 123 127.0.0.1:49152\r\n" {
		t.Fatalf("translated ASK = %q", translated)
	}
}
