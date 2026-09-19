package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
	"github.com/mtsaas/tunneler/internal/version"
)

// Handler returns the coordinator's HTTP API, whose client side is Client
// and ExitClient. The routes are described in routes.go.
func (c *Coordinator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": version.String()})
	})
	mux.HandleFunc(routeAuthConfig, c.handleAuthConfig)
	mux.HandleFunc(routeAuthStatus, c.user(c.handleAuthStatus))
	mux.HandleFunc(routeServices, c.user(c.handleListClusters))
	mux.HandleFunc(routeBindings, c.user(c.handleListBindings))
	mux.HandleFunc(routeForgetCluster, c.user(c.handleForgetCluster))
	mux.HandleFunc(routeSessions, c.user(c.handleListSessions))
	mux.HandleFunc(routeCreateSession, c.user(c.handleCreateSession))
	mux.HandleFunc(routeRevokeSession, c.user(c.handleDeleteSession))
	mux.HandleFunc(routeSessionConnect, c.user(c.handleConnect))
	mux.HandleFunc(routeSessionEvents, c.user(c.handleSessionEvents))
	mux.HandleFunc(routeGateway, c.handleGateway) // authenticates for itself, to answer in the kind's manner
	mux.HandleFunc(routeExitConnect, c.exit(c.handleExitConnect))
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
			err = fmt.Errorf("token has no %q claim; is it a workload's?", c.config().OIDC.UsernameClaim)
		}
		if err != nil {
			c.log.Info("request rejected: bad or expired ID token", "path", r.URL.Path, "remote", c.remote(r), "err", err)
			writeError(w, http.StatusUnauthorized, "not logged in, or login expired; run: tunneler auth login")
			return
		}
		if len(id.Groups) == 0 {
			c.log.Warn("user's token carries no groups, so only grants naming the user directly can match; is the identity provider configured to put a groups claim in ID tokens?",
				"user", id.Username, "user_id", id.UserID, "groups_claim", c.config().OIDC.GroupsClaim)
		}
		next(w, r, id)
	}
}

// ExitRole returns the application role that lets a workload identity act
// as the named cluster's exit node.
func ExitRole(cluster string) string { return "exit:" + cluster }

// exit wraps a handler that requires an exit node's credentials, passing it
// the name of the authenticated cluster.
func (c *Coordinator) exit(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cluster := r.URL.Query().Get("cluster")
		if err := c.admitExit(r.Context(), cluster, bearer(r)); err != nil {
			c.log.Warn("exit node rejected", "cluster", cluster, "remote", c.remote(r), "err", err)
			writeError(w, http.StatusUnauthorized, "not authorized as an exit node of this cluster")
			return
		}
		next(w, r, cluster)
	}
}

// admitExit checks that token proves its bearer an exit node of the
// cluster. An exit node presents one of:
//
//   - its Kubernetes service account token, if its cluster's issuer matches
//     exit_issuers; the cluster name is bound to that issuer on first use
//   - a token from the identity provider carrying the role ExitRole(cluster),
//     as an Azure workload identity obtains; the cluster name is bound to
//     that role on first use
//   - nothing, if the coordinator runs with insecure_exit_auth, which binds
//     nothing
//
// A name bound one way is refused the other way, so that no issuer can join
// a cluster whose exit nodes hold the role.
func (c *Coordinator) admitExit(ctx context.Context, cluster, token string) error {
	var err error
	issuer, kube := c.kube.trusts(token, c.config().ExitIssuers)
	switch {
	case cluster == "":
		err = errors.New("no cluster named")
	case c.config().InsecureExitAuth:
	case kube:
		err = c.authKubeExit(ctx, cluster, issuer, token)
	default:
		var id *Identity
		if id, err = c.auth(ctx, token); err == nil && !slices.Contains(id.Roles, ExitRole(cluster)) {
			err = fmt.Errorf("identity %s lacks role %q; it has %q", id.Subject, ExitRole(cluster), id.Roles)
		}
		if err != nil && issuer != "" && len(c.config().ExitIssuers) > 0 {
			err = fmt.Errorf("%w (issuer %s matches no exit_issuers pattern either)", err, issuer)
		}
		if err == nil {
			err = c.claimCluster(cluster, ExitRole(cluster))
		}
	}
	return err
}

// authKubeExit verifies a service account token from a trusted cluster
// issuer and checks that the issuer is the one bound to the cluster name,
// binding it if the name is new.
func (c *Coordinator) authKubeExit(ctx context.Context, cluster, issuer, token string) error {
	subject, err := c.kube.verify(ctx, issuer, c.config().ExitAudience, token)
	if err != nil {
		return err
	}
	if c.config().ExitSubject != "" && subject != c.config().ExitSubject {
		return fmt.Errorf("token subject %q is not exit_subject %q", subject, c.config().ExitSubject)
	}
	return c.claimCluster(cluster, issuer)
}

// claimCluster binds the cluster name to owner if it is not yet bound, and
// refuses it if it is bound to anything else. The owner is the issuer of a
// verified service account token, which is an http(s) URL, or the
// cluster's ExitRole, which is not.
func (c *Coordinator) claimCluster(cluster, owner string) error {
	bound, err := c.store.bindCluster(cluster, owner)
	if err != nil {
		return err
	}
	if bound == owner {
		return nil
	}
	describe := func(who string) string {
		if who == ExitRole(cluster) {
			return "the identity provider's role " + who
		}
		return "issuer " + who
	}
	return fmt.Errorf("cluster %q is bound to %s, not %s; see \"tunneler clusters list\", and if the cluster was rebuilt or its exit nodes changed how they authenticate, an admin must run: tunneler clusters forget %s",
		cluster, describe(bound), describe(owner), cluster)
}

// handleListBindings lists every cluster name that is bound or has an exit
// node connected, so that an admin can see who owns a name before releasing
// it.
func (c *Coordinator) handleListBindings(w http.ResponseWriter, r *http.Request, id *Identity) {
	if !c.isAdmin(id) {
		writeError(w, http.StatusForbidden, "admins only")
		return
	}
	bound, err := c.store.clusterBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, name := range c.hub.clusters() {
		if _, ok := bound[name]; !ok {
			bound[name] = "" // connected, but bound to nothing: under insecure_exit_auth, or just released
		}
	}
	bindings := []api.ClusterBinding{}
	for _, name := range slices.Sorted(maps.Keys(bound)) {
		bindings = append(bindings, api.ClusterBinding{Name: name, Issuer: bound[name], ExitNodes: c.hub.nodes(name)})
	}
	writeJSON(w, http.StatusOK, bindings)
}

func (c *Coordinator) handleForgetCluster(w http.ResponseWriter, r *http.Request, id *Identity) {
	if !c.isAdmin(id) {
		writeError(w, http.StatusForbidden, "admins only")
		return
	}
	name := r.PathValue("cluster")
	if err := c.store.unbindCluster(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c.audit.Info("cluster name released; the next issuer to present it will bind it",
		auditSubject(id.Username, id.Subject, name, "", ""))
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) isAdmin(id *Identity) bool {
	return slices.ContainsFunc(c.config().Admins, func(p string) bool { return slices.Contains(id.Groups, p) || id.Is(p) })
}

func (c *Coordinator) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, api.AuthConfig{
		Issuer:   c.config().OIDC.Issuer,
		ClientID: c.config().OIDC.ClientID,
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
	for _, g := range c.config().Grants {
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
			if _, ok := c.config().access(id, svc.Labels); ok {
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
	case n == 0:
		// The record names what the person asked for, as a refusal at the
		// gateway does.
		c.audit.Warn("access denied: selector matches no service the user's grants reach",
			auditSubject(id.Username, id.Subject, req.Selector["cluster"], req.Selector["name"], req.Selector["kind"]),
			"groups", id.Groups, "selector", req.Selector)
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
	if kinds[svc.Kind].proxy == nil {
		// Known, but not reached through sessions.
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"services of kind %q have no sessions; they are reached per request at %s, which \"tunneler connect\" arranges",
			svc.Kind, pathGateway(cluster, svc.Name)))
		return
	}
	if !svc.Ready {
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("%s/%s is registered but its exit node cannot reach it: %s",
			cluster, svc.Name, svc.Status))
		return
	}
	roles, _ := c.config().access(id, svc.Labels)

	s, err := c.createSession(r.Context(), id, cluster, svc, roles)
	if errors.Is(err, errUnaudited) {
		// The sink's own error is for the operator, who has it on the log.
		writeError(w, http.StatusServiceUnavailable, errUnaudited.Error())
		return
	}
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
	// The owner's groups, the grants and the service's labels may all have
	// changed since the session was created. The session goes on only while
	// the grants reach the service as it is offered now, and still give
	// every role its account was given.
	svc, offered := c.hub.service(s.info.Cluster, s.info.Service)
	if !offered {
		// Nothing reaches the service until an exit node offers it again,
		// and the session is checked then. Revoking here would end every
		// session on a cluster whose exit node merely reconnects.
		// ponytail: a service withdrawn for good leaves its sessions to
		// expire.
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("no connected exit node in cluster %q offers service %q", s.info.Cluster, s.info.Service))
		return
	}
	roles, ok := c.config().access(id, svc.Labels)
	lost := slices.DeleteFunc(slices.Clone(s.roles), func(role string) bool { return slices.Contains(roles, role) })
	if !ok || len(lost) > 0 {
		reason := "owner's grants no longer reach the service"
		if ok {
			reason = fmt.Sprintf("owner's grants no longer give the roles %q", lost)
		}
		c.revoke(s.info.ID, reason)
		writeError(w, http.StatusForbidden, "access withdrawn")
		return
	}
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		return
	}
	c.serveSession(r.Context(), s, conn, c.remote(r))
}

// handleSessionEvents streams SessionEvents until the session ends, so that
// a client learns of a revocation at once rather than at its next
// connection.
func (c *Coordinator) handleSessionEvents(w http.ResponseWriter, r *http.Request, id *Identity) {
	s := c.ownSession(w, r, id, false)
	if s == nil {
		return
	}
	ended, stop := s.watch()
	defer stop()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	rc := http.NewResponseController(w)
	send := func(ev api.SessionEvent) bool {
		// Streams outlive the server's write timeout by design.
		rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if json.NewEncoder(w).Encode(ev) != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send(api.SessionEvent{}) {
		return
	}
	// Keepalives keep idle proxies from cutting the stream.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case reason, ok := <-ended:
			if ok {
				send(api.SessionEvent{Ended: true, Reason: reason})
			}
			return
		case <-ticker.C:
			if !send(api.SessionEvent{}) {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

// handleExitConnect serves an exit node's session; see hub.
func (c *Coordinator) handleExitConnect(w http.ResponseWriter, r *http.Request, cluster string) {
	conn, err := tunnel.Accept(w, r)
	if err != nil {
		return
	}
	if err := c.hub.serve(cluster, c.remote(r), tunnel.Server(conn, c.log)); err != nil {
		c.log.Info("exit node session ended", "cluster", cluster, "remote", c.remote(r), "err", err)
	}
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
