package coordinator

import "net/url"

// The coordinator's HTTP API. Every route is defined here once: the pattern
// the server registers in Handler, and beside it the path a client requests.
// Client and ExitClient are the only callers of the builders, so the two
// sides of the API cannot drift apart unnoticed.
//
// Users authenticate with their ID token as a bearer token; exit nodes with
// a token that proves their cluster, which they name in the query.
const (
	routeHealth     = "GET /healthz"        // unauthenticated; reports the version
	routeAuthConfig = "GET /v1/auth/config" // unauthenticated; how to log in
	routeAuthStatus = "GET /v1/auth/status"

	routeServices = "GET /v1/clusters" // the services the caller may reach, by cluster

	routeBindings      = "GET /v1/clusters/bindings"             // admins
	routeForgetCluster = "DELETE /v1/clusters/{cluster}/binding" // admins

	routeSessions       = "GET /v1/sessions"
	routeCreateSession  = "POST /v1/sessions"
	routeRevokeSession  = "DELETE /v1/sessions/{id}"
	routeSessionEvents  = "GET /v1/sessions/{id}/events"  // a stream of api.SessionEvent
	routeSessionConnect = "GET /v1/sessions/{id}/connect" // upgrades to a tunnel stream

	// The gateway serves kinds that are reached per request rather than per
	// session, such as kubernetes. Whatever follows the service is the
	// request the service receives.
	routeGateway = "/v1/gateway/{cluster}/{service}/{rest...}"

	routeExitConnect = "GET /v1/exit/connect" // upgrades to a tunnel.Session; see hub

	// Exit nodes of v0.3.1 and earlier; see legacy.go.
	routeExitControl = "GET /v1/exit/control" // upgrades; api.Hello one way, api.ExitRequest the other
	routeExitData    = "GET /v1/exit/data"    // upgrades; answers a dial
	routeExitResult  = "POST /v1/exit/result" // answers anything else
)

const (
	pathHealth     = "/healthz"
	pathAuthConfig = "/v1/auth/config"
	pathAuthStatus = "/v1/auth/status"
	pathServices   = "/v1/clusters"
	pathBindings   = "/v1/clusters/bindings"
	pathSessions   = "/v1/sessions"

	pathExitConnect = "/v1/exit/connect"
)

func pathForgetCluster(cluster string) string {
	return "/v1/clusters/" + url.PathEscape(cluster) + "/binding"
}

func pathSession(id string) string        { return "/v1/sessions/" + url.PathEscape(id) }
func pathSessionEvents(id string) string  { return pathSession(id) + "/events" }
func pathSessionConnect(id string) string { return pathSession(id) + "/connect" }

// pathGateway returns the base path of a service behind the gateway, to
// which a client appends the service's own paths.
func pathGateway(cluster, service string) string {
	return "/v1/gateway/" + url.PathEscape(cluster) + "/" + url.PathEscape(service)
}
