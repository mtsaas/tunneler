package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

// A TokenFunc returns the bearer token to present to the coordinator. It is
// called for every request, so it should cache.
type TokenFunc func(ctx context.Context) (string, error)

// Client is the user's side of the coordinator's HTTP API, whose server side
// is Coordinator.Handler. A failure the coordinator reports is returned as
// an *api.Error carrying the HTTP status.
type Client struct {
	Server string       // the coordinator's base URL, without a trailing slash
	Token  TokenFunc    // the user's ID token; may be nil for Version and AuthConfig
	HTTP   *http.Client // nil means http.DefaultClient
}

// Version returns the version of the coordinator.
func (c *Client) Version(ctx context.Context) (string, error) {
	var health struct {
		Version string `json:"version"`
	}
	err := c.do(ctx, http.MethodGet, pathHealth, false, nil, &health)
	return health.Version, err
}

// AuthConfig returns how to log in to the coordinator's identity provider.
func (c *Client) AuthConfig(ctx context.Context) (*api.AuthConfig, error) {
	var ac api.AuthConfig
	return &ac, c.do(ctx, http.MethodGet, pathAuthConfig, false, nil, &ac)
}

// AuthStatus returns the caller as the coordinator sees them, and what that
// entitles them to.
func (c *Client) AuthStatus(ctx context.Context) (*api.AuthStatus, error) {
	var st api.AuthStatus
	return &st, c.do(ctx, http.MethodGet, pathAuthStatus, true, nil, &st)
}

// Services returns the services the caller may reach, by cluster.
func (c *Client) Services(ctx context.Context) ([]api.Cluster, error) {
	var clusters []api.Cluster
	return clusters, c.do(ctx, http.MethodGet, pathServices, true, nil, &clusters)
}

// CreateSession provisions access to the one service the selector matches.
// If it matches several, the *api.Error lists them in Matches.
func (c *Client) CreateSession(ctx context.Context, selector map[string]string) (*api.Session, error) {
	var s api.Session
	err := c.do(ctx, http.MethodPost, pathSessions, true, api.SessionRequest{Selector: selector}, &s)
	return &s, err
}

// Sessions returns the caller's sessions, or everyone's for an admin.
func (c *Client) Sessions(ctx context.Context) ([]api.Session, error) {
	var sessions []api.Session
	return sessions, c.do(ctx, http.MethodGet, pathSessions, true, nil, &sessions)
}

// RevokeSession ends a session: its connections close and its account goes.
func (c *Client) RevokeSession(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, pathSession(id), true, nil, nil)
}

// WatchSession follows a session's event stream until the coordinator says
// the session has ended, and returns the reason. An error means the stream
// was interrupted, not that the session ended, unless it is an *api.Error,
// which means the session does not exist.
func (c *Client) WatchSession(ctx context.Context, id string) (reason string, err error) {
	resp, err := c.send(ctx, http.MethodGet, pathSessionEvents(id), true, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	for {
		var ev api.SessionEvent
		if err := dec.Decode(&ev); err != nil {
			return "", err
		}
		if ev.Ended {
			return ev.Reason, nil
		}
	}
}

// DialSession opens a connection to the session's service, through the
// coordinator's proxy for the service's kind.
func (c *Client) DialSession(ctx context.Context, id string) (net.Conn, error) {
	return dialStream(ctx, c.Server+pathSessionConnect(id), c.Token)
}

// ClusterBindings returns which cluster owns each cluster name. Admins only.
func (c *Client) ClusterBindings(ctx context.Context) ([]api.ClusterBinding, error) {
	var bindings []api.ClusterBinding
	return bindings, c.do(ctx, http.MethodGet, pathBindings, true, nil, &bindings)
}

// ForgetCluster releases a cluster name for another cluster to claim. Admins
// only.
func (c *Client) ForgetCluster(ctx context.Context, cluster string) error {
	return c.do(ctx, http.MethodDelete, pathForgetCluster(cluster), true, nil, nil)
}

// GatewayURL returns the URL at which a service of a per-request kind, such
// as a cluster's Kubernetes API, is served to the caller.
func (c *Client) GatewayURL(cluster, service string) string {
	return c.Server + pathGateway(cluster, service)
}

// do makes a request. A non-nil in is sent as JSON, and a non-nil out
// receives the decoded response.
func (c *Client) do(ctx context.Context, method, path string, authenticate bool, in, out any) error {
	resp, err := c.send(ctx, method, path, authenticate, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// send makes a request and returns its successful response, whose body the
// caller must close.
func (c *Client) send(ctx context.Context, method, path string, authenticate bool, in any) (*http.Response, error) {
	if c.Server == "" {
		return nil, errors.New("no coordinator configured")
	}
	token := TokenFunc(nil)
	if authenticate {
		token = c.Token
	}
	return send(ctx, c.HTTP, method, c.Server+path, token, in)
}

// ExitClient is an exit node's side of the coordinator's HTTP API.
type ExitClient struct {
	Server  string       // the coordinator's base URL, without a trailing slash
	Cluster string       // the cluster the exit node speaks for
	Token   TokenFunc    // proves which cluster this is; nil presents nothing
	HTTP    *http.Client // nil means http.DefaultClient
}

// Connect opens the exit node's session with the coordinator. The node
// opens the first stream, and advertises its services on it; the
// coordinator opens a stream for each of its requests.
func (c *ExitClient) Connect(ctx context.Context, log *slog.Logger) (*tunnel.Session, error) {
	u := c.Server + pathExitConnect + "?" + url.Values{"cluster": {c.Cluster}}.Encode()
	conn, err := dialStream(ctx, u, c.Token)
	if e := (*api.Error)(nil); errors.As(err, &e) && e.Status == http.StatusNotFound {
		return nil, fmt.Errorf("%s does not serve %s: the coordinator is older than this exit node, and must be upgraded: %w",
			c.Server, pathExitConnect, err)
	}
	if err != nil {
		return nil, err
	}
	return tunnel.Client(conn, log), nil
}

// authorization returns the header carrying the token, if there is one.
func authorization(ctx context.Context, token TokenFunc) (http.Header, error) {
	if token == nil {
		return nil, nil
	}
	t, err := token(ctx)
	if err != nil {
		return nil, err
	}
	return http.Header{"Authorization": {"Bearer " + t}}, nil
}

func dialStream(ctx context.Context, url string, token TokenFunc) (net.Conn, error) {
	header, err := authorization(ctx, token)
	if err != nil {
		return nil, err
	}
	conn, err := tunnel.Dial(ctx, url, header)
	if status := (*tunnel.StatusError)(nil); errors.As(err, &status) {
		return nil, apiError(status.Code, strings.NewReader(status.Body))
	}
	return conn, err
}

func send(ctx context.Context, client *http.Client, method, url string, token TokenFunc, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if req.Header, err = authorization(ctx, token); err != nil {
		return nil, err
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, apiError(resp.StatusCode, resp.Body)
	}
	return resp, nil
}

// apiError reads the coordinator's account of a failure.
func apiError(status int, body io.Reader) *api.Error {
	e := &api.Error{Status: status}
	if json.NewDecoder(io.LimitReader(body, 1<<16)).Decode(e) != nil || e.Message == "" {
		e.Message = http.StatusText(status)
	}
	e.Status = status
	return e
}
