package coordinator

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// SharingConfig is separate from cluster grants: publishing exposes a local
// application to visitors who do not authenticate with the coordinator.
type SharingConfig struct {
	Domain       string         `json:"domain"`
	ControlHosts []string       `json:"control_hosts"`
	Grants       []PublishGrant `json:"grants"`
	// AllowAuthenticated permits every verified user to publish without a grant.
	AllowAuthenticated         bool     `json:"allow_authenticated,omitempty"`
	DefaultTTL                 Duration `json:"default_ttl,omitempty"`
	MaxTTL                     Duration `json:"max_ttl,omitempty"`
	SetupTTL                   Duration `json:"setup_ttl,omitempty"`
	HeartbeatInterval          Duration `json:"heartbeat_interval,omitempty"`
	HeartbeatTimeout           Duration `json:"heartbeat_timeout,omitempty"`
	AuthorizationLease         Duration `json:"authorization_lease,omitempty"`
	OperationRetention         Duration `json:"operation_retention,omitempty"`
	MaxServices                int      `json:"max_services,omitempty"`
	MaxSharesPerUser           int      `json:"max_shares_per_user,omitempty"`
	MaxConnectionsPerShare     int      `json:"max_connections_per_share,omitempty"`
	MaxConnectionsPerUser      int      `json:"max_connections_per_user,omitempty"`
	MaxConnections             int      `json:"max_connections,omitempty"`
	MaxPendingDialsPerShare    int      `json:"max_pending_dials_per_share,omitempty"`
	MaxOperationRecords        int      `json:"max_operation_records,omitempty"`
	MaxOperationRecordsPerUser int      `json:"max_operation_records_per_user,omitempty"`
}

type PublishGrant struct {
	User  string `json:"user,omitempty"`
	Group string `json:"group,omitempty"`
}

func (c *Config) sharingConfig() SharingConfig {
	var cfg SharingConfig
	if c.Sharing != nil {
		cfg = *c.Sharing
	}
	defaults := []struct {
		field *Duration
		value time.Duration
	}{
		{&cfg.DefaultTTL, time.Hour}, {&cfg.MaxTTL, 8 * time.Hour},
		{&cfg.SetupTTL, time.Minute}, {&cfg.HeartbeatInterval, 20 * time.Second},
		{&cfg.HeartbeatTimeout, time.Minute}, {&cfg.AuthorizationLease, 90 * time.Second},
		{&cfg.OperationRetention, 24 * time.Hour},
	}
	for _, d := range defaults {
		if *d.field == 0 {
			*d.field = Duration(d.value)
		}
	}
	limits := []struct {
		field *int
		value int
	}{
		{&cfg.MaxServices, 8}, {&cfg.MaxSharesPerUser, 4},
		{&cfg.MaxConnectionsPerShare, 32}, {&cfg.MaxConnectionsPerUser, 128},
		{&cfg.MaxConnections, 1024}, {&cfg.MaxPendingDialsPerShare, 32},
		{&cfg.MaxOperationRecords, 4096}, {&cfg.MaxOperationRecordsPerUser, 128},
	}
	for _, d := range limits {
		if *d.field == 0 {
			*d.field = d.value
		}
	}
	return cfg
}

func (c *Config) canPublish(id *Identity) bool {
	if c.Sharing == nil || id == nil {
		return false
	}
	if c.Sharing.AllowAuthenticated {
		return shareIdentityValid(id)
	}
	for _, grant := range c.Sharing.Grants {
		if (Grant{User: grant.User, Group: grant.Group}).Applies(id) {
			return true
		}
	}
	return false
}

func (c *Config) validateSharing() error {
	if c.Sharing == nil {
		return nil
	}
	s := c.sharingConfig()
	if !sharingDomainValid(s.Domain) {
		return errors.New("sharing.domain must be a lowercase DNS domain without a wildcard, scheme, port, or trailing dot")
	}
	if len(s.Domain) > 191 {
		return errors.New("sharing.domain cannot exceed 191 characters, leaving room for generated service names")
	}
	if _, err := netip.ParseAddr(s.Domain); err == nil {
		return errors.New("sharing.domain must be a DNS domain, not an IP address")
	}
	if len(s.ControlHosts) == 0 {
		return errors.New("sharing.control_hosts must name the coordinator's canonical host")
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(s.Domain); err != nil {
		return fmt.Errorf("sharing.domain: %w", err)
	}
	for _, authority := range s.ControlHosts {
		host := authority
		if h, _, err := net.SplitHostPort(authority); err == nil {
			host = h
		}
		if host == "localhost" {
			continue
		}
		if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			continue
		}
		if !sharingDomainValid(host) {
			return fmt.Errorf("sharing.control_hosts: %q is not a canonical host", authority)
		}
		if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
			return fmt.Errorf("sharing.control_hosts: %w", err)
		}
		if host == s.Domain || strings.HasSuffix(host, "."+s.Domain) {
			return fmt.Errorf("sharing.control_hosts: %q overlaps the sharing.domain preview namespace %q", authority, s.Domain)
		}
	}
	if s.DefaultTTL <= 0 || s.MaxTTL <= 0 || s.DefaultTTL > s.MaxTTL {
		return errors.New("sharing TTLs must be positive and default_ttl cannot exceed max_ttl")
	}
	if s.SetupTTL <= 0 || s.HeartbeatInterval <= 0 || s.HeartbeatTimeout <= s.HeartbeatInterval || s.AuthorizationLease <= 0 || s.OperationRetention <= 0 {
		return errors.New("sharing deadlines must be positive and heartbeat_timeout must exceed heartbeat_interval")
	}
	if s.OperationRetention < s.SetupTTL {
		return errors.New("sharing.operation_retention must cover setup_ttl")
	}
	if s.MaxServices <= 0 || s.MaxServices > 64 || s.MaxSharesPerUser <= 0 || s.MaxConnectionsPerShare <= 0 || s.MaxConnectionsPerUser <= 0 || s.MaxConnections <= 0 || s.MaxPendingDialsPerShare <= 0 || s.MaxOperationRecords <= 0 || s.MaxOperationRecordsPerUser <= 0 {
		return errors.New("sharing limits must be positive and max_services cannot exceed 64")
	}
	for i, grant := range s.Grants {
		if (grant.User == "") == (grant.Group == "") {
			return fmt.Errorf("sharing.grants[%d]: exactly one of user and group is required", i)
		}
	}
	return nil
}

var sharingDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func sharingDomainValid(domain string) bool {
	return len(domain) <= 253 && sharingDomainPattern.MatchString(domain)
}
