package exit

import (
	"context"
	"errors"
	"net"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/kube"
	"github.com/mtsaas/tunneler/internal/postgres"
)

// A backend is one service, of some kind, as the exit node reaches it from
// inside the cluster. It is the exit node's half of a kind; the coordinator
// holds the other half, which speaks the kind's protocol over what Connect
// returns.
//
// To support a new kind of service, implement backend (and accounts, if its
// users are given accounts), add it to kinds, and give the coordinator its
// half in that package's kinds.
type backend interface {
	// Addr is the service's address, for logs. It holds no credentials.
	Addr() string
	// Ping checks that the service is reachable with the exit node's
	// credentials for it. A service is advertised as ready once it is.
	Ping(ctx context.Context) error
	// Connect opens a connection for the coordinator's half of the kind to
	// speak over, with transport security to the service already in place.
	Connect(ctx context.Context) (net.Conn, error)
}

// accounts is implemented by backends of kinds whose users are each given a
// temporary account on the service, as with a database. Kinds without it
// identify the user some other way, per request.
type accounts interface {
	// CreateRole provisions an account.
	CreateRole(ctx context.Context, r api.Role) error
	// DropRole removes an account and disconnects it.
	DropRole(ctx context.Context, name string) error
	// Reap removes accounts past their expiry that were never dropped, and
	// returns their names.
	Reap(ctx context.Context) (dropped []string, err error)
}

// describer is implemented by backends with something to add to the
// service's advertisement beyond its name, kind and labels.
type describer interface {
	describe(*api.Service)
}

// kinds maps the kind a service declares to what reaches it. The kind is
// advertised to the coordinator, which picks its own half by the same name.
var kinds = map[string]func(ServiceConfig) (backend, error){
	"postgres": func(sc ServiceConfig) (backend, error) {
		if sc.DSN == "" {
			return nil, errors.New("a postgres service needs a dsn")
		}
		s, err := postgres.NewServer(sc.DSN)
		return postgresBackend{s}, err
	},
	"kubernetes": func(sc ServiceConfig) (backend, error) {
		if sc.DSN != "" {
			return nil, errors.New("a kubernetes service takes no dsn: the exit node uses its own service account")
		}
		// Roles are the groups that users may be impersonated into.
		return kube.NewAPIServer(sc.Kubernetes, sc.Roles)
	},
}

// clusterKinds are the kinds that offer the cluster itself rather than
// something a tenant runs in it. Whether to offer those is for whoever
// operates the exit node to decide, so they may be registered only in the
// exit node's own namespace.
var clusterKinds = map[string]bool{"kubernetes": true}

type postgresBackend struct{ *postgres.Server }

func (b postgresBackend) CreateRole(ctx context.Context, r api.Role) error {
	return b.Server.CreateRole(ctx, postgres.Role(r))
}

func (b postgresBackend) describe(svc *api.Service) { svc.Database = b.Database() }
