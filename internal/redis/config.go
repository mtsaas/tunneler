package redis

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	client "github.com/redis/go-redis/v9"
)

const (
	ModeStandalone = "standalone"
	ModeSentinel   = "sentinel"
	ModeCluster    = "cluster"
	RolePrefix     = "tnlr_"
)

// Config is public service policy. Credentials remain in the DSN Secret.
type Config struct {
	Mode         string              `json:"mode,omitempty"`
	MasterName   string              `json:"masterName,omitempty"`
	Sentinels    []string            `json:"sentinels,omitempty"`
	AllowedNodes []string            `json:"allowedNodes,omitempty"`
	ACLProfiles  map[string][]string `json:"aclProfiles,omitempty"`
}

type Node struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

type addressPolicy struct {
	networks []netip.Prefix
	hosts    []string
}

func newAddressPolicy(entries []string) (addressPolicy, error) {
	var policy addressPolicy
	for _, entry := range entries {
		if network, err := netip.ParsePrefix(entry); err == nil {
			policy.networks = append(policy.networks, network)
			continue
		}
		if entry == "" || strings.ContainsAny(entry, "/:@ \t\r\n") {
			return addressPolicy{}, errors.New("redis: allowedNodes must contain CIDRs or exact hostnames")
		}
		policy.hosts = append(policy.hosts, strings.ToLower(entry))
	}
	return policy, nil
}

func (p addressPolicy) permits(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return slices.ContainsFunc(p.networks, func(network netip.Prefix) bool {
			return network.Contains(ip)
		})
	}
	return slices.Contains(p.hosts, strings.ToLower(host))
}

func parseDSN(dsn string) (*client.Options, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() == "" || (u.Scheme != "redis" && u.Scheme != "rediss") {
		return nil, errors.New("redis: DSN must be a redis:// or rediss:// URL with a host")
	}
	if u.User == nil {
		return nil, errors.New("redis: DSN must include an administrative user and password")
	}
	password, hasPassword := u.User.Password()
	if u.User.Username() == "" || !hasPassword || password == "" {
		return nil, errors.New("redis: DSN must include an administrative user and password")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("redis: DSN query parameters and fragments are not supported")
	}
	options, err := client.ParseURL(dsn)
	if err != nil {
		return nil, errors.New("redis: invalid database or port in DSN")
	}
	if options.DB != 0 {
		return nil, errors.New("redis: only database 0 is supported; Redis ACLs do not isolate numbered databases")
	}
	options.Protocol = 2
	options.MaxRetries = -1
	return options, nil
}

func validateConfig(options *client.Options, cfg Config) (Config, addressPolicy, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeStandalone
	}
	policy, err := newAddressPolicy(cfg.AllowedNodes)
	if err != nil {
		return Config{}, addressPolicy{}, err
	}
	switch cfg.Mode {
	case ModeStandalone:
		if cfg.MasterName != "" || len(cfg.Sentinels) != 0 {
			return Config{}, addressPolicy{}, errors.New("redis: standalone mode takes no Sentinel settings")
		}
	case ModeSentinel:
		if cfg.MasterName == "" || len(cfg.Sentinels) == 0 || len(cfg.AllowedNodes) == 0 {
			return Config{}, addressPolicy{}, errors.New("redis: Sentinel mode needs a master name, sentinels and allowedNodes")
		}
		for _, addr := range cfg.Sentinels {
			if _, _, err := net.SplitHostPort(addr); err != nil {
				return Config{}, addressPolicy{}, errors.New("redis: Sentinel addresses must be host:port")
			}
		}
	case ModeCluster:
		if len(cfg.AllowedNodes) == 0 {
			return Config{}, addressPolicy{}, errors.New("redis: Cluster mode needs allowedNodes")
		}
	default:
		return Config{}, addressPolicy{}, fmt.Errorf("redis: unknown mode %q", cfg.Mode)
	}
	if len(cfg.ACLProfiles) == 0 {
		return Config{}, addressPolicy{}, errors.New("redis: at least one ACL profile is required")
	}
	for name, rules := range cfg.ACLProfiles {
		if name == "" || len(rules) == 0 {
			return Config{}, addressPolicy{}, errors.New("redis: ACL profiles need names and rules")
		}
		for _, rule := range rules {
			if !validProfileRule(rule) {
				return Config{}, addressPolicy{}, fmt.Errorf("redis: invalid rule in ACL profile %q", name)
			}
		}
	}
	return cfg, policy, nil
}

// A profile can add command, key and channel permissions. It cannot change
// passwords, enable a different user, or erase permissions from another
// profile. Every profile is installed as an independent Redis ACL selector.
func validProfileRule(rule string) bool {
	if len(rule) < 2 || strings.ContainsAny(rule, " ()\t\r\n") {
		return false
	}
	switch rule[0] {
	case '+':
		name := strings.ToLower(rule[1:])
		return !slices.Contains(forbiddenCommands, name) &&
			name != "@all" && name != "@connection" && name != "client|reset"
	case '~', '&':
		return true
	default:
		return false
	}
}

var forbiddenCommands = []string{
	"acl", "client", "config", "debug", "module", "monitor", "replicaof",
	"shutdown", "slaveof", "sync", "psync",
}

func parseExpiry(name string) (int64, bool) {
	if !strings.HasPrefix(name, RolePrefix) {
		return 0, false
	}
	stamp, suffix, ok := strings.Cut(strings.TrimPrefix(name, RolePrefix), "_")
	if !ok || len(suffix) < 8 {
		return 0, false
	}
	for _, r := range suffix {
		if r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return 0, false
		}
	}
	expiry, err := strconv.ParseInt(stamp, 36, 64)
	return expiry, err == nil && expiry > 1_700_000_000
}
