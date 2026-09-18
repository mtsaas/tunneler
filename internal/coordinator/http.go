package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

// Handler returns the coordinator's HTTP API.
func (c *Coordinator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /v1/auth/config", c.handleAuthConfig)
	mux.HandleFunc("GET /v1/auth/status", c.user(c.handleAuthStatus))
	mux.HandleFunc("GET /v1/clusters", c.user(c.handleListClusters))
	mux.HandleFunc("DELETE /v1/clusters/{name}/binding", c.user(c.handleForgetCluster))
	mux.HandleFunc("GET /v1/sessions", c.user(c.handleListSessions))
	mux.HandleFunc("POST /v1/sessions", c.user(c.handleCreateSession))
	mux.HandleFunc("DELETE /v1/sessions/{id}", c.user(c.handleDeleteSession))
	mux.HandleFunc("GET /v1/sessions/{id}/connect", c.user(c.handleConnect))
	mux.HandleFunc("GET /v1/exit/control", c.exit(c.handleExitControl))
	mux.HandleFunc("GET /v1/exit/data", c.exit(c.handleExitData))
	mux.HandleFunc("POST /v1/exit/result", c.exit(c.handleExitResult))
	return mux
}

func bearer(r *http.Request) string {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token
}

// user wraps a handler that requires an authenticated user.
func (c *Coordinator) user(next func(http.ResponseWriter, *http.Request, *Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := c.auth(r.Context(), bearer(r))
		if err == nil && id.Username == "" {
			err = fmt.Errorf("token has no %q claim; is it a workload's?", c.cfg.OIDC.UsernameClaim)
		}
		if err != nil {
			c.log.Info("request rejected: bad or expired ID token", "path", r.URL.Path, "remote", r.RemoteAddr, "err", err)
			writeError(w, http.StatusUnauthorized, "not logged in, or login expired; run: tunneler auth login")
			return
		}
		if len(id.Groups) == 0 {
			c.log.Warn("user's token carries no groups, so only grants naming the user directly can match; is the identity provider configured to put a groups claim in ID tokens?",
				"user", id.Username, "user_id", id.UserID, "groups_claim", c.cfg.OIDC.GroupsClaim)
		}
		next(w, r, id)
	}
}

// ExitRole returns the application role that lets a workload identity act
// as the named cluster's exit node.
func ExitRole(cluster string) string { return "exit:" + cluster }

// exit wraps a handler that requires an exit node's credentials, passing it
// the name of the authenticated cluster. An exit node presents one of:
//
//   - its Kubernetes service account token, if its cluster's issuer matches
//     exit_issuers; the cluster name is bound to that issuer on first use
//   - a token from the identity provider carrying the role ExitRole(cluster),
//     as an Azure workload identity obtains
//   - nothing, if the coordinator runs with insecure_exit_auth
func (c *Coordinator) exit(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cluster, token := r.URL.Query().Get("cluster"), bearer(r)
		var err error
		issuer, kube := c.kube.trusts(token)
		switch {
		case cluster == "":
			err = errors.New("no cluster named")
		case c.cfg.InsecureExitAuth:
		case kube:
			err = c.authKubeExit(r.Context(), cluster, issuer, token)
		default:
			var id *Identity
			if id, err = c.auth(r.Context(), token); err == nil && !slices.Contains(id.Roles, ExitRole(cluster)) {
				err = fmt.Errorf("identity %s lacks role %q; it has %q", id.Subject, ExitRole(cluster), id.Roles)
			}
			if err != nil && issuer != "" && len(c.cfg.ExitIssuers) > 0 {
				err = fmt.Errorf("%w (issuer %s matches no exit_issuers pattern either)", err, issuer)
			}
		}
		if err != nil {
			c.log.Warn("exit node rejected", "cluster", cluster, "remote", r.RemoteAddr, "err", err)
			writeError(w, http.StatusUnauthorized, "not authorized as an exit node of this cluster")
			return
		}
		next(w, r, cluster)
	}
}

// authKubeExit verifies a service account token from a trusted cluster
// issuer and checks that the issuer is the one bound to the cluster name,
// binding it if the name is new.
func (c *Coordinator) authKubeExit(ctx context.Context, cluster, issuer, token string) error {
	subject, err := c.kube.verify(ctx, issuer, token)
	if err != nil {
		return err
	}
	if c.cfg.ExitSubject != "" && subject != c.cfg.ExitSubject {
		return fmt.Errorf("token subject %q is not exit_subject %q", subject, c.cfg.ExitSubject)
	}
	bound, err := c.store.bindCluster(cluster, issuer)
	if err != nil {
		return err
	}
	if bound == issuer {
		return nil
	}
	return fmt.Errorf("cluster %q is bound to issuer %s, not %s; if the cluster was rebuilt, an admin must run: tunneler clusters forget %s",
		cluster, bound, issuer, cluster)
}

func (c *Coordinator) handleForgetCluster(w http.ResponseWriter, r *http.Request, id *Identity) {
	if !c.isAdmin(id) {
		writeError(w, http.StatusForbidden, "admins only")
		return
	}
	name := r.PathValue("name")
	if err := c.store.unbindCluster(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c.audit.Info("cluster name released; the next issuer to present it will bind it", "cluster", name, "by", id.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) isAdmin(id *Identity) bool {
	return slices.ContainsFunc(c.cfg.Admins, func(p string) bool { return slices.Contains(id.Groups, p) || id.Is(p) })
}

func (c *Coordinator) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, api.AuthConfig{
		Issuer:   c.cfg.OIDC.Issuer,
		ClientID: c.cfg.OIDC.ClientID,
		// offline_access yields a refresh token, sparing users a daily login.
		Scopes: []string{"openid", "profile", "offline_access"},
	})
}

func (c *Coordinator) handleAuthStatus(w http.ResponseWriter, r *http.Request, id *Identity) {
	status := api.AuthStatus{
		Subject:  id.Subject,
		UserID:   id.UserID,
		Username: id.Username,
		Groups:   id.Groups,
		Admin:    c.isAdmin(id),
		Grants:   []api.Grant{},
		Clusters: c.reachable(id),
	}
	for _, g := range c.cfg.Grants {
		if g.Applies(id) {
			status.Grants = append(status.Grants, api.Grant(g))
		}
	}
	writeJSON(w, http.StatusOK, status)
}

// reachable returns the connected clusters and, within each, the services
// the user's grants reach.
func (c *Coordinator) reachable(id *Identity) []api.Cluster {
	clusters := []api.Cluster{}
	for _, name := range c.hub.clusters() {
		out := api.Cluster{Name: name}
		for _, svc := range c.hub.services(name) {
			if _, ok := c.cfg.access(id, svc.Labels); ok {
				out.Services = append(out.Services, svc)
			}
		}
		if len(out.Services) > 0 {
			clusters = append(clusters, out)
		}
	}
	return clusters
}

func (c *Coordinator) handleListClusters(w http.ResponseWriter, r *http.Request, id *Identity) {
	writeJSON(w, http.StatusOK, c.reachable(id))
}

func (c *Coordinator) handleListSessions(w http.ResponseWriter, r *http.Request, id *Identity) {
	admin := c.isAdmin(id)
	sessions := []api.Session{}
	c.mu.Lock()
	for _, s := range c.sessions {
		if admin || s.subject == id.Subject {
			sessions = append(sessions, s.info)
		}
	}
	c.mu.Unlock()
	slices.SortFunc(sessions, func(a, b api.Session) int { return a.ExpiresAt.Compare(b.ExpiresAt) })
	writeJSON(w, http.StatusOK, sessions)
}

func (c *Coordinator) handleCreateSession(w http.ResponseWriter, r *http.Request, id *Identity) {
	var req api.SessionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	// Select only among what the user may reach, so that a selector reveals
	// nothing about services they may not.
	var matches []api.Cluster
	n := 0
	for _, cl := range c.reachable(id) {
		cl.Services = slices.DeleteFunc(cl.Services, func(svc api.Service) bool {
			return !Grant{Labels: req.Selector}.Matches(svc.Labels)
		})
		if len(cl.Services) > 0 {
			matches = append(matches, cl)
			n += len(cl.Services)
		}
	}
	switch {
	case len(req.Selector) == 0:
		writeError(w, http.StatusBadRequest, "a selector is required")
		return
	case n == 0:
		c.audit.Warn("access denied: selector matches no service the user's grants reach",
			"subject", id.Subject, "user", id.Username, "groups", id.Groups, "selector", req.Selector)
		msg := "no service you have access to matches that selector"
		if len(id.Groups) == 0 {
			msg += "; your login carries no groups, so only a grant naming you directly could apply (see: tunneler auth status)"
		}
		writeError(w, http.StatusForbidden, msg)
		return
	case n > 1:
		writeJSON(w, http.StatusConflict, api.Error{
			Message: fmt.Sprintf("the selector matches %d services; add labels until it matches one", n),
			Matches: matches,
		})
		return
	}
	cluster, svc := matches[0].Name, matches[0].Services[0]
	if !svc.Ready {
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("%s/%s is registered but its exit node cannot reach it: %s",
			cluster, svc.Name, svc.Status))
		return
	}
	roles, _ := c.cfg.access(id, svc.Labels)

	s, err := c.createSession(r.Context(), id, cluster, svc, roles)
	if err != nil {
		c.log.Error("creating session", "user", id.Username, "cluster", cluster, "service", svc.Name, "err", err)
		writeError(w, http.StatusBadGateway, "provisioning access failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s)
}

// ownSession returns the session named in the request path if the user may
// act on it, writing an error response otherwise.
func (c *Coordinator) ownSession(w http.ResponseWriter, r *http.Request, id *Identity, adminOK bool) *session {
	c.mu.Lock()
	s := c.sessions[r.PathValue("id")]
	c.mu.Unlock()
	if s == nil || s.subject != id.Subject && !(adminOK && c.isAdmin(id)) {
		writeError(w, http.StatusNotFound, "no such session")
		return nil
	}
	return s
}

func (c *Coordinator) handleDeleteSession(w http.ResponseWriter, r *http.Request, id *Identity) {
	if s := c.ownSession(w, r, id, true); s != nil {
		c.revoke(s.info.ID, "revoked by "+id.Username)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *Coordinator) handleConnect(w http.ResponseWriter, r *http.Request, id *Identity) {
	s := c.ownSession(w, r, id, false)
	if s == nil {
		return
	}
	// Group membership may have changed since the session was created.
	if _, ok := c.cfg.access(id, s.labels); !ok {
		c.revoke(s.info.ID, "owner's groups no longer grant access")
		writeError(w, http.StatusForbidden, "access withdrawn")
		return
	}
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		return
	}
	c.serveSession(r.Context(), s, conn)
}

func (c *Coordinator) handleExitControl(w http.ResponseWriter, r *http.Request, cluster string) {
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		return
	}
	if err := c.hub.serveControl(cluster, conn); err != nil {
		c.log.Info("exit node control stream ended", "cluster", cluster, "remote", r.RemoteAddr, "err", err)
	}
}

// handleExitData accepts the data stream that answers a dial.
func (c *Coordinator) handleExitData(w http.ResponseWriter, r *http.Request, cluster string) {
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		return
	}
	if !c.hub.deliver(cluster, r.URL.Query().Get("id"), conn, api.ExitResult{}) {
		conn.Close() // the dial gave up waiting
	}
}

// handleExitResult accepts the outcome of any request other than a
// successful dial.
func (c *Coordinator) handleExitResult(w http.ResponseWriter, r *http.Request, cluster string) {
	var res api.ExitResult
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&res); err != nil {
		writeError(w, http.StatusBadRequest, "malformed result: "+err.Error())
		return
	}
	c.hub.deliver(cluster, r.URL.Query().Get("id"), nil, res)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.Error{Message: msg})
}

// NewHTTPServer returns an http.Server for the coordinator with timeouts
// suited to an internet-facing listener. Upgraded streams are exempt from
// them.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}
