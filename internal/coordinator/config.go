package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"
)

// Config is the coordinator's configuration file.
type Config struct {
	Listen     string     `json:"listen"`      // default ":8443"
	Database   string     `json:"database"`    // SQLite file holding session state; default "tunneler.db"
	TLS        *TLSConfig `json:"tls"`         // nil serves plain HTTP, for use behind a TLS-terminating proxy
	SessionTTL Duration   `json:"session_ttl"` // default 8h
	OIDC       OIDCConfig `json:"oidc"`
	Admins     []string   `json:"admins"` // groups that may list and revoke anyone's sessions
	Grants     []Grant    `json:"grants"`
	// InsecureExitAuth admits any exit node as whatever cluster it claims to
	// be, without credentials. It exists for local development only: with it
	// on, anyone who can reach the coordinator can receive users' database
	// traffic. Leave it off and exit nodes must present a workload identity
	// carrying ExitRole for their cluster.
	//
	// Either way clusters are not configured; one exists for as long as an
	// exit node is connected.
	InsecureExitAuth bool `json:"insecure_exit_auth"`
}

// TLSConfig names a PEM certificate and key pair.
type TLSConfig struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// OIDCConfig identifies the OpenID Connect provider that authenticates users.
// For Microsoft Entra the issuer is
// https://login.microsoftonline.com/<tenant-id>/v2.0 and the groups claim
// carries group object IDs.
type OIDCConfig struct {
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	UsernameClaim string `json:"username_claim"` // default "preferred_username"
	UserIDClaim   string `json:"user_id_claim"`  // default "oid", the Entra user object ID; "sub" is app-specific there
	GroupsClaim   string `json:"groups_claim"`   // default "groups"
}

// Grant gives a principal access to every service whose labels include all
// of the grant's labels. The principal is a group, named by ID, or a single
// user, named by ID or username; exactly one must be set.
type Grant struct {
	Group  string            `json:"group,omitempty"`
	User   string            `json:"user,omitempty"`
	Labels map[string]string `json:"labels"`
	// Roles are granted to the account provisioned for the user, in whatever
	// sense the service kind gives them. For Postgres they are existing
	// database roles that carry the actual privileges.
	Roles []string `json:"roles"`
}

// Applies reports whether the grant's principal is id.
func (g Grant) Applies(id *Identity) bool {
	return g.Group != "" && slices.Contains(id.Groups, g.Group) || g.User != "" && id.Is(g.User)
}

// Matches reports whether the grant's labels select a service with the given
// labels.
func (g Grant) Matches(labels map[string]string) bool {
	for k, v := range g.Labels {
		if have, ok := labels[k]; !ok || have != v {
			return false
		}
	}
	return true
}

// Duration is a time.Duration that unmarshals from a string like "8h".
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	*d = Duration(v)
	return err
}

// LoadConfig reads and validates the configuration file at path.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &Config{
		Listen:     ":8443",
		Database:   "tunneler.db",
		SessionTTL: Duration(8 * time.Hour),
		OIDC:       OIDCConfig{UsernameClaim: "preferred_username", UserIDClaim: "oid", GroupsClaim: "groups"},
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields() // a misspelt key must not silently widen or drop access
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
		return errors.New("oidc.issuer and oidc.client_id are required")
	}
	if c.SessionTTL <= 0 {
		return errors.New("session_ttl must be positive")
	}
	for i, g := range c.Grants {
		if (g.Group == "") == (g.User == "") {
			return fmt.Errorf("grants[%d]: exactly one of group and user is required", i)
		}
		// An empty selector matches everything; make that impossible to do
		// by accident.
		if len(g.Labels) == 0 {
			return fmt.Errorf("grants[%d]: labels must not be empty", i)
		}
	}
	return nil
}

// access reports whether id may use a service with the given labels, and the
// union of roles their matching grants confer.
func (c *Config) access(id *Identity, labels map[string]string) (roles []string, ok bool) {
	for _, g := range c.Grants {
		if g.Applies(id) && g.Matches(labels) {
			ok = true
			roles = append(roles, g.Roles...)
		}
	}
	slices.Sort(roles)
	return slices.Compact(roles), ok
}
