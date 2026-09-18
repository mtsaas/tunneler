// Package api defines the JSON types exchanged between the coordinator and
// its clients: the tunneler CLI and the exit nodes.
package api

import "time"

// AuthConfig tells a client how to authenticate against the coordinator's
// identity provider.
type AuthConfig struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// AuthStatus is the caller as the coordinator sees them, and what that
// entitles them to.
type AuthStatus struct {
	Subject  string   `json:"subject"`
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
	Admin    bool     `json:"admin"` // may list and revoke anyone's sessions
	// Grants are the configured grants that the caller's groups satisfy,
	// whether or not any connected service carries their labels.
	Grants []Grant `json:"grants"`
	// Clusters are the services those grants reach right now.
	Clusters []Cluster `json:"clusters"`
}

// Grant gives a group or a user access to every service carrying all of its
// labels.
type Grant struct {
	Group  string            `json:"group,omitempty"`
	User   string            `json:"user,omitempty"`
	Labels map[string]string `json:"labels"`
	Roles  []string          `json:"roles"`
}

// Cluster is a cluster with a connected exit node, and the services on it
// that the caller may access.
type Cluster struct {
	Name     string    `json:"name"`
	Services []Service `json:"services"`
}

// Service is a reachable service within a cluster, as advertised by the
// cluster's exit nodes.
type Service struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Database string            `json:"database,omitempty"` // Postgres: the one database sessions may use
	Labels   map[string]string `json:"labels"`
	// Ready reports whether the exit node can reach the service with its
	// credentials; Status says why not. Sessions are refused on a service
	// that is not ready.
	Ready  bool   `json:"ready"`
	Status string `json:"status,omitempty"`
}

// SessionRequest asks the coordinator to provision access to the one service,
// among those the caller may reach, that carries every label in Selector.
// Every service has the labels "cluster", "kind" and "name" besides its own.
// An empty selector matches every service the caller may reach.
// If several services match, the coordinator answers 409 Conflict with an
// Error listing them.
type SessionRequest struct {
	Selector map[string]string `json:"selector"`
}

// Session is provisioned, time-limited access to a service.
type Session struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	Cluster   string    `json:"cluster"`
	Service   string    `json:"service"`
	Kind      string    `json:"kind"`
	Database  string    `json:"database"`
	Username  string    `json:"username"`
	Password  string    `json:"password,omitempty"` // only returned on creation
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionEvent is one line of the stream at GET /v1/sessions/{id}/events.
// The stream carries keepalives (an empty event) until the session ends,
// then one event with Ended set and the reason, and closes. A stream that
// closes without an Ended event was interrupted, for example by a
// coordinator restart; the session may well still exist.
type SessionEvent struct {
	Ended  bool   `json:"ended,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Error is the body of every non-2xx response.
type Error struct {
	Status  int    `json:"-"` // the HTTP status, set by clients
	Message string `json:"error"`
	// Matches accompanies 409 Conflict: the services an ambiguous selector
	// matched.
	Matches []Cluster `json:"matches,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// Hello is the first thing an exit node writes on its control stream. The
// rest of the stream flows the other way: one JSON ExitRequest per line.
type Hello struct {
	Services []Service `json:"services"`
}

// Operations an exit node performs for the coordinator.
const (
	OpDial       = "dial"        // connect to Service; answered with a data stream
	OpCreateRole = "create_role" // provision Role on Service
	OpDropRole   = "drop_role"   // drop the role named Role.Name on Service
)

// ExitRequest asks an exit node to do something. Every request but a dial is
// answered with an ExitResult. A request with an empty ID is a keepalive.
type ExitRequest struct {
	ID      string `json:"id,omitempty"`
	Op      string `json:"op,omitempty"`
	Service string `json:"service,omitempty"`
	Role    *Role  `json:"role,omitempty"`
}

// ExitResult reports the outcome of an ExitRequest, including a failed dial.
type ExitResult struct {
	Error string `json:"error,omitempty"`
}

// Role is an account to provision on a service.
type Role struct {
	Name       string    `json:"name"`
	Password   string    `json:"password,omitempty"`
	ValidUntil time.Time `json:"valid_until,omitzero"`
	MemberOf   []string  `json:"member_of,omitempty"`
}
