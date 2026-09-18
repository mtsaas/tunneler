package coordinator

import (
	"encoding/base64"
	"slices"
	"testing"
)

func TestAccess(t *testing.T) {
	cfg := &Config{Grants: []Grant{
		{Group: "prod-all", Labels: map[string]string{"cluster": "prod"}, Roles: []string{"readwrite"}},
		{Group: "prod-pg", Labels: map[string]string{"cluster": "prod", "kind": "postgres"}, Roles: []string{"readonly"}},
		{Group: "dev", Labels: map[string]string{"cluster": "dev"}},
		{User: "1111-2222", Labels: map[string]string{"cluster": "prod", "name": "orders"}, Roles: []string{"readonly"}},
		{User: "Bob@Example.com", Labels: map[string]string{"cluster": "dev"}},
	}}
	orders := map[string]string{"cluster": "prod", "kind": "postgres", "name": "orders"}
	prodPG := map[string]string{"cluster": "prod", "kind": "postgres", "team": "payments"}
	prodRedis := map[string]string{"cluster": "prod", "kind": "redis"}

	tests := []struct {
		name   string
		groups []string
		labels map[string]string
		ok     bool
		roles  []string
	}{
		{"cluster-wide grant reaches everything on it", []string{"prod-all"}, prodRedis, true, []string{"readwrite"}},
		{"narrower grant reaches postgres", []string{"prod-pg"}, prodPG, true, []string{"readonly"}},
		{"narrower grant does not reach redis", []string{"prod-pg"}, prodRedis, false, nil},
		{"roles are the union across grants", []string{"prod-pg", "prod-all"}, prodPG, true, []string{"readonly", "readwrite"}},
		{"grants are not merged into one selector", []string{"prod-pg", "dev"}, prodRedis, false, nil},
		{"other cluster", []string{"dev"}, prodPG, false, nil},
		{"no groups", nil, prodPG, false, nil},
		{"grant to a user by ID", nil, orders, true, []string{"readonly"}},
		{"user grant does not reach other services", nil, prodPG, false, nil},
	}
	for _, tt := range tests {
		roles, ok := cfg.access(&Identity{UserID: "1111-2222", Username: "alice@example.com", Groups: tt.groups}, tt.labels)
		if ok != tt.ok || !slices.Equal(roles, tt.roles) {
			t.Errorf("%s: access = %v, %v; want %v, %v", tt.name, roles, ok, tt.roles, tt.ok)
		}
	}
	bob := &Identity{UserID: "3333", Username: "bob@example.com"}
	if _, ok := cfg.access(bob, map[string]string{"cluster": "dev"}); !ok {
		t.Error("grant to a user by username should match regardless of case")
	}
	if err := (&Config{OIDC: OIDCConfig{Issuer: "i", ClientID: "c"}, SessionTTL: 1,
		Grants: []Grant{{Labels: map[string]string{"a": "b"}}}}).validate(); err == nil {
		t.Error("a grant with neither group nor user should be rejected")
	}
}

func TestExitIssuerPattern(t *testing.T) {
	const pattern = "https://*.oic.prod-aks.azure.com/11111111-2222-3333-4444-555555555555/*/"
	for issuer, want := range map[string]bool{
		"https://eastus.oic.prod-aks.azure.com/11111111-2222-3333-4444-555555555555/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/":     true,
		"https://westeurope.oic.prod-aks.azure.com/11111111-2222-3333-4444-555555555555/ffffffff-0000-1111-2222-333333333333/": true,
		"https://eastus.oic.prod-aks.azure.com/99999999-8888-7777-6666-555555555555/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/":     false, // another tenant
		"https://evil.example.com/oic.prod-aks.azure.com/11111111-2222-3333-4444-555555555555/x/":                              false,
	} {
		v := &kubeVerifier{patterns: []string{pattern}}
		// A token whose payload is just the issuer claim.
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + issuer + `"}`))
		if _, got := v.trusts("h." + payload + ".s"); got != want {
			t.Errorf("%s: trusted = %v, want %v", issuer, got, want)
		}
	}
}
