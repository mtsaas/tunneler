// Package redis manages temporary ACL users and upstream connections for
// standalone Redis, Sentinel-managed Redis, and Redis Cluster.
package redis

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	client "github.com/redis/go-redis/v9"

	"github.com/mtsaas/tunneler/internal/api"
)

type Server struct {
	options         *client.Options
	sentinelOptions *client.Options
	config          Config
	policy          addressPolicy

	mu         sync.RWMutex
	nodes      []Node
	primary    string
	generation string
	timers     map[string]*time.Timer
}

func NewServer(dsn string, cfg Config) (*Server, error) {
	return NewServerWithSentinelDSN(dsn, cfg, "")
}

// NewServerWithSentinelDSN configures separate TLS credentials for Sentinel.
func NewServerWithSentinelDSN(dsn string, cfg Config, sentinelDSN string) (*Server, error) {
	options, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	cfg, policy, err := validateConfig(options, cfg)
	if err != nil {
		return nil, err
	}
	var sentinelOptions *client.Options
	if sentinelDSN != "" {
		if cfg.Mode != ModeSentinel {
			return nil, errors.New("redis: sentinelDsn requires Sentinel mode")
		}
		sentinelOptions, err = parseDSN(sentinelDSN)
		if err != nil {
			return nil, fmt.Errorf("redis: invalid Sentinel DSN: %w", err)
		}
		if sentinelOptions.TLSConfig == nil {
			return nil, errors.New("redis: Sentinel credentials require a rediss:// URL")
		}
		if sentinelOptions.Password == options.Password {
			return nil, errors.New("redis: Sentinel credentials must not reuse the data-node administrative password")
		}
		if !slices.Contains(cfg.Sentinels, sentinelOptions.Addr) {
			return nil, errors.New("redis: Sentinel DSN must name a configured Sentinel address")
		}
	}
	return &Server{
		options:         options,
		sentinelOptions: sentinelOptions,
		config:          cfg,
		policy:          policy,
		timers:          make(map[string]*time.Timer),
	}, nil
}

func (s *Server) Addr() string  { return s.options.Addr }
func (s *Server) Mode() string  { return s.config.Mode }
func (s *Server) Database() int { return s.options.DB }

func (s *Server) Nodes() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.nodes)
}

// Generation changes when a Redis data node restarts. Temporary ACL users
// live in server memory unless the operator persists them, so a session
// created against an earlier generation must not be reused after a restart.
func (s *Server) Generation() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

func (s *Server) optionsFor(addr string) *client.Options {
	options := *s.options
	options.Addr = addr
	if s.options.TLSConfig != nil {
		host, _, _ := net.SplitHostPort(addr)
		options.TLSConfig = s.options.TLSConfig.Clone()
		options.TLSConfig.ServerName = host
	}
	return &options
}

func (s *Server) control(addr string) *client.Client {
	return client.NewClient(s.optionsFor(addr))
}

// Ping checks administration and refreshes the set of targets. A changed
// Cluster or Sentinel topology is advertised on the next exit reconcile.
func (s *Server) Ping(ctx context.Context) error {
	var nodes []Node
	var primary string
	var err error

	switch s.config.Mode {
	case ModeStandalone:
		primary = s.options.Addr
		nodes = []Node{{ID: "standalone", Addr: primary}}
	case ModeSentinel:
		primary, nodes, err = s.sentinelTopology(ctx)
	case ModeCluster:
		nodes, err = s.clusterTopology(ctx)
	}
	if err != nil {
		return err
	}
	fingerprint := sha256.New()
	for _, node := range nodes {
		runID, err := s.checkNode(ctx, node.Addr)
		if err != nil {
			return fmt.Errorf("redis: node %s is not ready: %w", node.ID, err)
		}
		fmt.Fprintf(fingerprint, "%s\x00%s\x00", node.ID, runID)
	}

	s.mu.Lock()
	s.nodes = nodes
	s.primary = primary
	s.generation = hex.EncodeToString(fingerprint.Sum(nil))
	s.mu.Unlock()
	return nil
}

func (s *Server) checkNode(ctx context.Context, addr string) (string, error) {
	c := s.control(addr)
	defer c.Close()
	if err := c.Ping(ctx).Err(); err != nil {
		return "", err
	}
	info, err := c.Info(ctx, "server", "cluster").Result()
	if err != nil {
		return "", err
	}
	version := infoField(info, "redis_version")
	major, _, _ := strings.Cut(version, ".")
	majorNumber, _ := strconv.Atoi(major)
	if majorNumber < 7 {
		return "", errors.New("Redis 7 or later is required for ACL selectors")
	}
	isCluster := infoField(info, "cluster_enabled") == "1"
	if isCluster != (s.config.Mode == ModeCluster) {
		return "", errors.New("server cluster mode does not match the service mode")
	}
	runID := infoField(info, "run_id")
	if runID == "" {
		return "", errors.New("Redis did not report a run ID")
	}
	return runID, nil
}

func infoField(info, key string) string {
	for _, line := range strings.Split(info, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && name == key {
			return value
		}
	}
	return ""
}

func (s *Server) clusterTopology(ctx context.Context) ([]Node, error) {
	c := s.control(s.options.Addr)
	defer c.Close()
	shards, err := c.ClusterShards(ctx).Result()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var nodes []Node
	var covered [16384]bool
	for _, shard := range shards {
		for _, slotRange := range shard.Slots {
			if slotRange.Start < 0 || slotRange.End >= int64(len(covered)) || slotRange.Start > slotRange.End {
				return nil, errors.New("redis: invalid cluster slot range")
			}
			for slot := slotRange.Start; slot <= slotRange.End; slot++ {
				if covered[slot] {
					return nil, errors.New("redis: cluster slot ranges overlap")
				}
				covered[slot] = true
			}
		}
		for _, node := range shard.Nodes {
			port := clusterNodePort(node, s.options.TLSConfig != nil)
			if node.ID == "" || node.Endpoint == "" || port < 1 || port > 65535 {
				return nil, errors.New("redis: cluster advertised an incomplete node")
			}
			addr := net.JoinHostPort(node.Endpoint, strconv.FormatInt(port, 10))
			if !s.policy.permits(addr) {
				return nil, errors.New("redis: cluster advertised a node outside allowedNodes")
			}
			if !seen[node.ID] {
				seen[node.ID] = true
				nodes = append(nodes, Node{ID: node.ID, Addr: addr})
			}
		}
	}
	if slices.Contains(covered[:], false) || len(nodes) == 0 || len(nodes) > 64 {
		return nil, errors.New("redis: cluster must cover every slot with at most 64 nodes")
	}
	slices.SortFunc(nodes, func(a, b Node) int { return strings.Compare(a.ID, b.ID) })
	return nodes, nil
}

func clusterNodePort(node client.Node, secure bool) int64 {
	if secure && node.TLSPort > 0 {
		return node.TLSPort
	}
	return node.Port
}

func (s *Server) sentinelTopology(ctx context.Context) (string, []Node, error) {
	var lastErr error
	for _, sentinelAddr := range s.config.Sentinels {
		primary, nodes, err := s.querySentinel(ctx, sentinelAddr)
		if err == nil {
			return primary, nodes, nil
		}
		lastErr = err
	}
	return "", nil, fmt.Errorf("redis: no Sentinel answered: %w", lastErr)
}

func (s *Server) querySentinel(ctx context.Context, addr string) (string, []Node, error) {
	options := &client.Options{Addr: addr, Protocol: 2, MaxRetries: -1}
	tlsOptions := s.options
	if s.sentinelOptions != nil {
		options.Username = s.sentinelOptions.Username
		options.Password = s.sentinelOptions.Password
		tlsOptions = s.sentinelOptions
	}
	if tlsOptions.TLSConfig != nil {
		host, _, _ := net.SplitHostPort(addr)
		options.TLSConfig = tlsOptions.TLSConfig.Clone()
		options.TLSConfig.ServerName = host
		options.TLSConfig.MinVersion = tls.VersionTLS12
	}
	sentinel := client.NewSentinelClient(options)
	defer sentinel.Close()
	master, err := sentinel.GetMasterAddrByName(ctx, s.config.MasterName).Result()
	if err != nil {
		return "", nil, fmt.Errorf("redis: Sentinel master lookup failed: %w", err)
	}
	if len(master) != 2 {
		return "", nil, errors.New("redis: Sentinel returned an invalid master address")
	}
	primary := net.JoinHostPort(master[0], master[1])
	if !s.policy.permits(primary) {
		return "", nil, errors.New("redis: Sentinel advertised a primary outside allowedNodes")
	}
	nodes := []Node{{ID: primary, Addr: primary}}
	replicas, err := sentinel.Replicas(ctx, s.config.MasterName).Result()
	if err != nil {
		return "", nil, err
	}
	for _, replica := range replicas {
		if strings.Contains(replica["flags"], "disconnected") || strings.Contains(replica["flags"], "s_down") {
			continue
		}
		addr := net.JoinHostPort(replica["ip"], replica["port"])
		if !s.policy.permits(addr) {
			return "", nil, errors.New("redis: Sentinel advertised a replica outside allowedNodes")
		}
		nodes = append(nodes, Node{ID: addr, Addr: addr})
	}
	slices.SortFunc(nodes, func(a, b Node) int { return strings.Compare(a.ID, b.ID) })
	return primary, nodes, nil
}

// Connect opens the data path without administrative authentication. The
// client's AUTH is passed to Redis and remains bound to that connection.
func (s *Server) Connect(ctx context.Context) (net.Conn, error) {
	addr := s.options.Addr
	if s.config.Mode == ModeSentinel {
		primary, _, err := s.sentinelTopology(ctx)
		if err != nil {
			return nil, err
		}
		addr = primary
	}
	if s.config.Mode == ModeCluster {
		return nil, errors.New("redis: Cluster connections must name a node")
	}
	return s.dial(ctx, addr)
}

func (s *Server) ConnectNode(ctx context.Context, id string) (net.Conn, error) {
	for _, node := range s.Nodes() {
		if node.ID == id {
			return s.dial(ctx, node.Addr)
		}
	}
	return nil, errors.New("redis: node is not in the advertised topology")
}

func (s *Server) dial(ctx context.Context, addr string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil || s.options.TLSConfig == nil {
		return conn, err
	}
	host, _, _ := net.SplitHostPort(addr)
	config := s.options.TLSConfig.Clone()
	config.ServerName = host
	config.MinVersion = tls.VersionTLS12
	secure := tls.Client(conn, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return secure, nil
}

func (s *Server) CreateRole(ctx context.Context, role api.Role) error {
	expiry, ok := parseExpiry(role.Name)
	if !ok || expiry != role.ValidUntil.Unix() || role.Password == "" {
		return errors.New("redis: invalid temporary account")
	}
	rules := []string{"reset", "on", ">" + role.Password}
	for _, profile := range role.MemberOf {
		permissions, ok := s.config.ACLProfiles[profile]
		if !ok {
			return fmt.Errorf("redis: unknown ACL profile %q", profile)
		}
		selector := append(slices.Clone(permissions), mandatoryDenies...)
		rules = append(rules, "("+strings.Join(selector, " ")+")")
	}
	if err := s.Ping(ctx); err != nil {
		return err
	}
	var created []string
	for _, node := range s.Nodes() {
		c := s.control(node.Addr)
		err := c.ACLSetUser(ctx, role.Name, rules...).Err()
		c.Close()
		if err != nil {
			for _, addr := range created {
				_ = s.deleteAt(ctx, addr, role.Name)
			}
			return fmt.Errorf("redis: creating account on %s: %w", node.ID, err)
		}
		created = append(created, node.Addr)
	}
	s.mu.Lock()
	s.timers[role.Name] = time.AfterFunc(time.Until(role.ValidUntil), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = s.DropRole(ctx, role.Name)
	})
	s.mu.Unlock()
	return nil
}

var mandatoryDenies = []string{
	"-acl", "-client", "-config", "-debug", "-failover", "-module", "-monitor",
	"-replicaof", "-shutdown", "-slaveof", "-sync", "-psync",
	"-select", "-swapdb", "-move", "-migrate", "-copy",
	"-reset", "-flushall", "-flushdb",
}

func (s *Server) deleteAt(ctx context.Context, addr, name string) error {
	c := s.control(addr)
	defer c.Close()
	return c.ACLDelUser(ctx, name).Err()
}

func (s *Server) DropRole(ctx context.Context, name string) error {
	if _, ok := parseExpiry(name); !ok {
		return errors.New("redis: refusing to delete an account without the tunnel prefix and expiry")
	}
	var errs []error
	for _, node := range s.Nodes() {
		if err := s.deleteAt(ctx, node.Addr, name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", node.ID, err))
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	s.mu.Lock()
	if timer := s.timers[name]; timer != nil {
		timer.Stop()
		delete(s.timers, name)
	}
	s.mu.Unlock()
	return nil
}

func (s *Server) Reap(ctx context.Context) ([]string, error) {
	var dropped []string
	var errs []error
	seen := make(map[string]bool)
	for _, node := range s.Nodes() {
		c := s.control(node.Addr)
		users, err := c.ACLUsers(ctx).Result()
		c.Close()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, name := range users {
			expiry, ok := parseExpiry(name)
			if !ok || time.Now().Unix() < expiry {
				continue
			}
			if err := s.deleteAt(ctx, node.Addr, name); err != nil {
				errs = append(errs, err)
				continue
			}
			if !seen[name] {
				seen[name] = true
				dropped = append(dropped, name)
			}
		}
	}
	return dropped, errors.Join(errs...)
}
