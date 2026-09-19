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

// ClusterBinding is a cluster name and the cluster that owns it, for admins.
type ClusterBinding struct {
	Name string `json:"name"`
	// Issuer is the OIDC issuer the name is bound to: only a cluster with
	// this issuer may use the name. It is empty for a cluster whose exit
	// nodes authenticate some other way, which binds nothing.
	Issuer    string `json:"issuer,omitempty"`
	ExitNodes int    `json:"exit_nodes"` // connected right now
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
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Access says how the service is reached, which follows from its kind:
	// AccessSession, through a session on which a temporary account is
	// provisioned, or AccessGateway, per request through the coordinator's
	// gateway. It is empty for a kind the coordinator does not know, and
	// from coordinators that predate it, which knew only session kinds.
	Access   string            `json:"access,omitempty"`
	Database string            `json:"database,omitempty"` // Postgres: the one database sessions may use
	Labels   map[string]string `json:"labels"`
	// Ready reports whether the exit node can reach the service with its
	// credentials; Status says why not. Sessions are refused on a service
	// that is not ready.
	Ready  bool   `json:"ready"`
	Status string `json:"status,omitempty"`
}

// How a service is reached; see Service.Access.
const (
	AccessSession = "session"
	AccessGateway = "gateway"
)

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

// Hello lists an exit node's services. The node writes one on the first
// stream it opens to the coordinator, and another there whenever its
// services change.
type Hello struct {
	Services []Service `json:"services"`
	// Token proves which cluster the node speaks for; see ExitResult.Token.
	Token string `json:"token,omitempty"`
}

// Operations an exit node performs for the coordinator.
const (
	OpDial       = "dial"        // connect to Service
	OpCreateRole = "create_role" // provision Role on Service
	OpDropRole   = "drop_role"   // drop the role named Role.Name on Service
)

// ExitRequest asks an exit node to do something. The coordinator opens a
// stream to the node for each request and writes the request on it. The
// node answers there with an ExitResult, after which the stream of a
// successful dial carries the connection to the service.
type ExitRequest struct {
	Op      string `json:"op,omitempty"`
	Service string `json:"service,omitempty"`
	Role    *Role  `json:"role,omitempty"`
}

// ExitResult reports the outcome of an ExitRequest.
type ExitResult struct {
	Error string `json:"error,omitempty"`
	// Token proves which cluster the exit node speaks for, as its
	// credentials did when it connected. The coordinator requires one with
	// every Hello and ExitResult, and disconnects a node whose token its
	// rules no longer admit. Thus withdrawing a node's admission cuts the
	// node off when it next speaks rather than when it next connects.
	Token string `json:"token,omitempty"`
}

// Role is an account to provision on a service.
type Role struct {
	Name       string    `json:"name"`
	Password   string    `json:"password,omitempty"`
	ValidUntil time.Time `json:"valid_until,omitzero"`
	MemberOf   []string  `json:"member_of,omitempty"`
}
