package coordinator

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/kube"
	"github.com/mtsaas/tunneler/internal/postgres"
)

// dialFunc opens a connection to a service through one of its cluster's exit
// nodes. What it returns speaks whatever the exit node's half of the kind
// put on the other end.
type dialFunc func(ctx context.Context) (net.Conn, error)

// A kind is how the coordinator fronts one type of service. It is the
// coordinator's half; the exit node holds the other, under the same name.
// A kind is reached in one of two ways, and sets the matching field.
//
// To support a new kind of service, add it here and give the exit node its
// half in that package's kinds. Nothing else in the coordinator names a
// kind.
type kind struct {
	// proxy is set for kinds reached through sessions. The user asks for a
	// session, an exit node provisions them a temporary account, and each
	// connection of theirs is handed to proxy, which speaks the service's
	// protocol with the client, admits only the session's account, records
	// what the client does on audit, refusing what is not recorded first
	// (see mustAudit), and closes client before returning.
	proxy func(ctx context.Context, client net.Conn, dial dialFunc, s *api.Session, audit *slog.Logger) error

	// gateway is set for kinds reached per request, over HTTP. There is no
	// session and no account: every request carries the user's login, and
	// the handler acts for them. It is called once per service, and again
	// if the service is withdrawn and then offered anew.
	gateway func(dial dialFunc) gatewayHandler
}

// A gatewayHandler serves one service of a per-request kind.
type gatewayHandler interface {
	// ServeAs serves r, whose path is the service's own, on behalf of user,
	// who holds roles. It records what the request did on audit, and refuses
	// a request that stays open unless its start is recorded first.
	ServeAs(w http.ResponseWriter, r *http.Request, user string, roles []string, audit *slog.Logger)
	// Error answers a request that will not be served, in the manner the
	// kind's clients expect.
	Error(w http.ResponseWriter, code int, message string)
	// CloseIdleConnections closes the connections kept between requests,
	// once the handler's service is withdrawn. Requests in flight keep
	// theirs.
	CloseIdleConnections()
}

// access returns the api.Service.Access of the kind.
func (k kind) access() string {
	switch {
	case k.proxy != nil:
		return api.AccessSession
	case k.gateway != nil:
		return api.AccessGateway
	}
	return ""
}

var kinds = map[string]kind{
	"postgres": {
		proxy: func(ctx context.Context, client net.Conn, dial dialFunc, s *api.Session, audit *slog.Logger) error {
			return postgres.Proxy(ctx, client, dial, s.Username, s.Database, func(query string) error {
				return mustAudit(ctx, audit, "query", "sql", query)
			})
		},
	},
	"kubernetes": {
		gateway: func(dial dialFunc) gatewayHandler { return kube.NewGateway(dial) },
	},
}
