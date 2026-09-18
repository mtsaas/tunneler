package coordinator

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/mtsaas/tunneler/internal/api"
)

// gateways holds the handler of each service of a per-request kind. A
// handler keeps connections to its service's exit nodes between requests,
// so it is made once and kept.
type gateways struct {
	mu       sync.Mutex
	handlers map[string]gatewayHandler // by cluster/service
}

func (g *gateways) handler(c *Coordinator, cluster string, svc api.Service) gatewayHandler {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := cluster + "/" + svc.Name
	h, ok := g.handlers[key]
	if !ok {
		if g.handlers == nil {
			g.handlers = make(map[string]gatewayHandler)
		}
		h = kinds[svc.Kind].gateway(func(ctx context.Context) (net.Conn, error) {
			return c.hub.call(ctx, cluster, api.ExitRequest{Op: api.OpDial, Service: svc.Name})
		})
		g.handlers[key] = h
	}
	return h
}

// handleGateway serves a service of a per-request kind. Unlike a session,
// nothing is provisioned and nothing can linger: each request is
// authenticated and authorized on its own, so a change of grants or of
// group membership applies to the very next request.
func (c *Coordinator) handleGateway(w http.ResponseWriter, r *http.Request) {
	cluster, name := r.PathValue("cluster"), r.PathValue("service")

	id, err := c.auth(r.Context(), bearer(r))
	if err == nil && id.Username == "" {
		err = fmt.Errorf("token has no %q claim", c.config().OIDC.UsernameClaim)
	}
	if err != nil {
		c.log.Info("gateway request rejected: bad or expired ID token", "cluster", cluster, "service", name, "remote", c.remote(r), "err", err)
		refuseGateway(w, http.StatusUnauthorized, "not logged in, or login expired; run: tunneler auth login")
		return
	}
	// Until the caller is known to have access, the answer is the same
	// whether or not the service exists, and so cannot be in the manner of
	// the service's kind.
	svc, found := c.hub.service(cluster, name)
	audit := c.audit.With(auditSubject(id.Username, id.Subject, cluster, name, svc.Kind), "remote", c.remote(r))
	var roles []string
	allowed := found && kinds[svc.Kind].gateway != nil
	if allowed {
		roles, allowed = c.config().access(id, svc.Labels)
	}
	if !allowed {
		audit.Warn("access denied: no such service, or no grant selects it", "groups", id.Groups)
		refuseGateway(w, http.StatusForbidden, "no such service, or access denied; see: tunneler auth status")
		return
	}
	h := c.gateways.handler(c, cluster, svc)
	if !svc.Ready {
		h.Error(w, http.StatusServiceUnavailable, fmt.Sprintf("%s/%s is registered but its exit node cannot reach it: %s", cluster, name, svc.Status))
		return
	}

	// The service sees its own paths, not the gateway's.
	r = r.Clone(r.Context())
	r.URL.Path = "/" + r.PathValue("rest")
	r.URL.RawPath = ""
	r.RequestURI = ""
	h.ServeAs(w, r, id.Username, roles, audit)
}

// refuseGateway answers a request before the caller is known to have access
// to the service, when the answer must not depend on whether the service
// exists, let alone on its kind. The body is therefore one that every kind's
// clients can read: an api.Error, which is also shaped as the Status object
// that kubectl prints the message of.
func refuseGateway(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]any{
		"error":      message,
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"status":     "Failure",
		"message":    "tunneler: " + message,
		"reason":     map[int]string{http.StatusUnauthorized: "Unauthorized", http.StatusForbidden: "Forbidden"}[code],
		"code":       code,
	})
}
