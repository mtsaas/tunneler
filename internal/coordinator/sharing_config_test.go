package coordinator

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtsaas/tunneler/internal/testutil"
	"golang.org/x/net/publicsuffix"
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
		{"shared parent cookies", func(s *SharingConfig) { s.Domain = "preview.example.com" }, true},
		{"nested shares under control host", func(s *SharingConfig) {
			s.Domain, s.ControlHosts = "share.tunneler.example.com", []string{"tunneler.example.com"}
		}, true},
		{"sibling shares in same zone", func(s *SharingConfig) {
			s.Domain, s.ControlHosts = "share.example.com", []string{"tunneler.example.com"}
		}, true},
		{"same host", func(s *SharingConfig) { s.ControlHosts = []string{"preview-example.net"} }, false},
		{"control within preview namespace", func(s *SharingConfig) { s.ControlHosts = []string{"control.preview-example.net"} }, false},
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
			testutil.Require(t, (err == nil) == tt.valid, "validateSharing() = %v; valid=%v", err, tt.valid)
		})
	}
}

func TestSharingCookieBoundary(t *testing.T) {
	control, _ := url.Parse("https://tunneler.example.com")
	for _, tc := range []struct {
		domain string
		shared bool
	}{
		{"share.tunneler.example.com", true},
		{"share.example.com", true},
		{"share.example.net", false},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			preview, _ := url.Parse("https://web." + tc.domain)
			jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
			testutil.NoError(t, err)
			jar.SetCookies(control, []*http.Cookie{{Name: "control", Value: "credential", Domain: "example.com", Path: "/", Secure: true, HttpOnly: true}})
			leaked := len(jar.Cookies(preview)) != 0
			testutil.Require(t, leaked == tc.shared, "parent-domain credential leakage = %v", leaked)
			jar.SetCookies(preview, []*http.Cookie{{Name: "injected", Value: "untrusted", Domain: "example.com", Path: "/", Secure: true}})
			injected := false
			for _, cookie := range jar.Cookies(control) {
				injected = injected || cookie.Name == "injected"
			}
			testutil.Require(t, injected == tc.shared, "share cookie reached control = %v", injected)
			jar.SetCookies(preview, []*http.Cookie{{Name: "application", Value: "session", Path: "/", Secure: true}})
			application := false
			for _, cookie := range jar.Cookies(preview) {
				application = application || cookie.Name == "application"
			}
			testutil.Require(t, application, "host-only application cookie stopped working")
			cfg := &Config{Sharing: &SharingConfig{Domain: tc.domain, ControlHosts: []string{control.Host}}}
			testutil.NoError(t, cfg.validateSharing())
		})
	}
}

func TestSharingOperationRecordDefaults(t *testing.T) {
	cfg := (&Config{Sharing: &SharingConfig{}}).sharingConfig()
	testutil.Require(t, cfg.MaxOperationRecordsPerUser == 128 && cfg.MaxOperationRecords == 4096, "operation record limits = per user %d, global %d", cfg.MaxOperationRecordsPerUser, cfg.MaxOperationRecords)
}

func TestPublishingNeedsSeparateGrant(t *testing.T) {
	id := &Identity{Subject: "subject", UserID: "user-id", Username: "clark@example.com", Groups: []string{"developers"}}
	cfg := &Config{Grants: []Grant{{Group: "developers", Labels: map[string]string{"cluster": "prod"}}}}
	testutil.Require(t, !cfg.canPublish(id), "cluster grant enabled publication")
	cfg.Sharing = &SharingConfig{Grants: []PublishGrant{{Group: "others"}}}
	testutil.Require(t, !cfg.canPublish(id), "unrelated publishing grant enabled publication")
	cfg.Sharing.Grants = []PublishGrant{{User: "user-id"}}
	testutil.Require(t, cfg.canPublish(id), "matching user grant did not allow publishing")
	cfg.Sharing.Grants = []PublishGrant{{Group: "developers"}}
	testutil.Require(t, cfg.canPublish(id), "matching group grant did not allow publishing")
}

func TestPublishingAllowsVerifiedAuthenticatedUsers(t *testing.T) {
	id := &Identity{Issuer: "https://issuer.test", Subject: "subject", Username: "user@example.com", ExpiresAt: time.Now().Add(time.Hour)}
	cfg := &Config{Sharing: &SharingConfig{}}
	testutil.Require(t, !cfg.canPublish(id), "authenticated publishing was enabled by default")
	cfg.Sharing.AllowAuthenticated = true
	testutil.Require(t, cfg.canPublish(id), "verified user without groups/grants cannot publish")
	testutil.Require(t, !cfg.canPublish(nil), "nil identity can publish")
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
			testutil.Require(t, !cfg.canPublish(&invalid), "unverified/expired identity can publish")
		})
	}
}
