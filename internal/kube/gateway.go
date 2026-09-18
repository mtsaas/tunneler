package kube

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

// Gateway is the coordinator's half: it serves a cluster's Kubernetes API to
// authenticated users, as themselves.
type Gateway struct {
	proxy *httputil.ReverseProxy
}

// NewGateway returns a Gateway that reaches the cluster's APIServer over
// connections from dial. Connections are kept and reused between requests.
func NewGateway(dial func(ctx context.Context) (net.Conn, error)) *Gateway {
	transport := &http.Transport{
		DialContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		// The tunnel is a byte stream to one fixed peer, which speaks HTTP/1.1
		// in the clear; TLS is the tunnel's business and the exit node's.
		DisableCompression: true,
	}
	return &Gateway{proxy: &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "kubernetes"
			pr.Out.Host = "kubernetes"
		},
		FlushInterval: -1, // watches and logs are streams: pass every write on at once
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			WriteStatus(w, http.StatusBadGateway, "tunneler: the cluster's exit node could not be reached: "+err.Error())
		},
	}}
}

// ServeAs serves r, whose path is the Kubernetes API path, on behalf of
// user, as a member of groups. Whatever identity the request itself claims
// is discarded. The request is recorded on audit when it completes, and
// also when it starts if it is one that stays open, such as an exec.
func (g *Gateway) ServeAs(w http.ResponseWriter, r *http.Request, user string, groups []string, audit *slog.Logger) {
	info := ParseRequest(r)
	attrs := []any{
		"verb", info.Verb,
		"path", info.Path,
	}
	if info.IsResource {
		attrs = append(attrs, "api_group", info.APIGroup, "resource", info.Resource, "subresource", info.Subresource,
			"namespace", info.Namespace, "name", info.Name)
	}
	if command := r.URL.Query()["command"]; len(command) > 0 { // exec and attach
		attrs = append(attrs, "command", command)
	}
	audit = audit.With(attrs...)

	r = r.Clone(r.Context())
	stripIdentity(r.Header)
	r.Header.Set(headerUser, user)
	for _, group := range groups {
		r.Header.Add(headerGroup, group)
	}

	longLived := info.Verb == "watch" || r.Header.Get("Upgrade") != ""
	if longLived {
		audit.Info("kubernetes request started")
	}
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w}
	g.proxy.ServeHTTP(rec, r)
	audit.Info("kubernetes request", "status", rec.status, "duration", time.Since(start).Round(time.Millisecond).String())
}

// Error answers a request the coordinator will not serve, in the way kubectl
// expects.
func (g *Gateway) Error(w http.ResponseWriter, code int, message string) {
	WriteStatus(w, code, "tunneler: "+message)
}

// statusRecorder notes the status of a response as it passes. It keeps the
// underlying writer reachable, which a reverse proxy needs in order to flush
// streams and to take over the connection for an upgrade.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(p)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
