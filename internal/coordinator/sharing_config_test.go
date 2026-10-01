package coordinator

import (
	"strings"
	"testing"
	"time"
)

func TestSharingConfigIsolationAndValidation(t *testing.T) {
	valid := func() *SharingConfig {
		return &SharingConfig{Domain: "preview-example.net", ControlHosts: []string{"tunneler.example.com"}, Grants: []PublishGrant{{Group: "developers"}}}
	}
	tests := []struct {
		name   string
		change func(*SharingConfig)
		valid  bool
	}{
		{"defaults", func(*SharingConfig) {}, true},
		{"all authenticated without grants", func(s *SharingConfig) { s.AllowAuthenticated = true; s.Grants = nil }, true},
		{"control port", func(s *SharingConfig) { s.ControlHosts = []string{"tunneler.example.com:8443"} }, true},
		{"local control", func(s *SharingConfig) { s.ControlHosts = []string{"127.0.0.1:8443", "localhost:8443", "[::1]:8443"} }, true},
		{"parent cookies", func(s *SharingConfig) { s.Domain = "preview.example.com" }, false},
		{"same host", func(s *SharingConfig) { s.ControlHosts = []string{"preview-example.net"} }, false},
		{"wildcard", func(s *SharingConfig) { s.Domain = "*.preview-example.net" }, false},
		{"URL", func(s *SharingConfig) { s.Domain = "https://preview-example.net" }, false},
		{"IP preview", func(s *SharingConfig) { s.Domain = "127.0.0.1" }, false},
		{"generated hostname length", func(s *SharingConfig) {
			s.Domain = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 61) + ".net"
		}, false},
		{"empty label", func(s *SharingConfig) { s.Domain = "preview..example.net" }, false},
		{"missing control host", func(s *SharingConfig) { s.ControlHosts = nil }, false},
		{"negative lease", func(s *SharingConfig) { s.AuthorizationLease = -1 }, false},
		{"invalid TTL order", func(s *SharingConfig) { s.DefaultTTL = Duration(9 * time.Hour) }, false},
		{"invalid liveness", func(s *SharingConfig) { s.HeartbeatTimeout = Duration(10 * time.Second) }, false},
		{"unbounded limit", func(s *SharingConfig) { s.MaxConnections = -1 }, false},
		{"unbounded per-user records", func(s *SharingConfig) { s.MaxOperationRecordsPerUser = -1 }, false},
		{"two principals", func(s *SharingConfig) { s.Grants = []PublishGrant{{User: "a", Group: "b"}} }, false},
		{"empty principal", func(s *SharingConfig) { s.Grants = []PublishGrant{{}} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := valid()
			tt.change(s)
			err := (&Config{Sharing: s}).validateSharing()
			if (err == nil) != tt.valid {
				t.Fatalf("validateSharing() = %v; valid=%v", err, tt.valid)
			}
		})
	}
}

func TestSharingOperationRecordDefaults(t *testing.T) {
	cfg := (&Config{Sharing: &SharingConfig{}}).sharingConfig()
	if cfg.MaxOperationRecordsPerUser != 128 || cfg.MaxOperationRecords != 4096 {
		t.Fatalf("operation record limits = per user %d, global %d", cfg.MaxOperationRecordsPerUser, cfg.MaxOperationRecords)
	}
}

func TestPublishingNeedsSeparateGrant(t *testing.T) {
	id := &Identity{Subject: "subject", UserID: "user-id", Username: "clark@example.com", Groups: []string{"developers"}}
	cfg := &Config{Grants: []Grant{{Group: "developers", Labels: map[string]string{"cluster": "prod"}}}}
	if cfg.canPublish(id) {
		t.Fatal("cluster grant enabled publication")
	}
	cfg.Sharing = &SharingConfig{Grants: []PublishGrant{{Group: "others"}}}
	if cfg.canPublish(id) {
		t.Fatal("unrelated publishing grant enabled publication")
	}
	cfg.Sharing.Grants = []PublishGrant{{User: "user-id"}}
	if !cfg.canPublish(id) {
		t.Fatal("matching user grant did not allow publishing")
	}
	cfg.Sharing.Grants = []PublishGrant{{Group: "developers"}}
	if !cfg.canPublish(id) {
		t.Fatal("matching group grant did not allow publishing")
	}
}

func TestPublishingAllowsVerifiedAuthenticatedUsers(t *testing.T) {
	id := &Identity{Issuer: "https://issuer.test", Subject: "subject", Username: "user@example.com", ExpiresAt: time.Now().Add(time.Hour)}
	cfg := &Config{Sharing: &SharingConfig{}}
	if cfg.canPublish(id) {
		t.Fatal("authenticated publishing was enabled by default")
	}
	cfg.Sharing.AllowAuthenticated = true
	if !cfg.canPublish(id) {
		t.Fatal("verified user without groups/grants cannot publish")
	}
	if cfg.canPublish(nil) {
		t.Fatal("nil identity can publish")
	}
	for _, test := range []struct {
		name   string
		change func(*Identity)
	}{
		{"issuer", func(id *Identity) { id.Issuer = "" }},
		{"subject", func(id *Identity) { id.Subject = "" }},
		{"workload", func(id *Identity) { id.Username = "" }},
		{"expiry", func(id *Identity) { id.ExpiresAt = time.Time{} }},
		{"expired", func(id *Identity) { id.ExpiresAt = time.Now().Add(-time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := *id
			test.change(&invalid)
			if cfg.canPublish(&invalid) {
				t.Fatal("unverified/expired identity can publish")
			}
		})
	}
}
