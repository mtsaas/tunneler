package kube

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
)

// Where a pod finds its cluster's API server and its own credentials.
const (
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Config says how the exit node reaches its cluster's API server. The zero
// value means the cluster the process runs in.
type Config struct {
	Server    string `json:"server,omitempty"`     // URL; default from KUBERNETES_SERVICE_HOST and _PORT
	TokenFile string `json:"token_file,omitempty"` // service account token; re-read for every request
	CAFile    string `json:"ca_file,omitempty"`    // PEM bundle that signs the API server's certificate
}

// APIServer is the exit node's half: the cluster's API server, reached with
// the exit node's own service account, which must be allowed to impersonate
// users and the configured groups.
type APIServer struct {
	server    *url.URL
	tokenFile string
	groups    []string // the only groups a request may impersonate
	transport *http.Transport

	serve    sync.Once
	listener *pipeListener
}

// NewAPIServer returns the API server that cfg describes. Requests may
// impersonate any user, but no group outside groups.
func NewAPIServer(cfg Config, groups []string) (*APIServer, error) {
	if cfg.Server == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("kube: not running in a Kubernetes pod, and no server configured")
		}
		cfg.Server = "https://" + net.JoinHostPort(host, port)
		cfg.TokenFile, cfg.CAFile = cmp.Or(cfg.TokenFile, inClusterTokenFile), cmp.Or(cfg.CAFile, inClusterCAFile)
	}
	server, err := url.Parse(cfg.Server)
	if err != nil || server.Host == "" {
		return nil, fmt.Errorf("kube: invalid server URL %q", cfg.Server)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	// Upgrades, which exec and port-forward need, exist only in HTTP/1.1.
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig.RootCAs = x509.NewCertPool()
		if !transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kube: %s holds no certificates", cfg.CAFile)
		}
	}
	return &APIServer{server: server, tokenFile: cfg.TokenFile, groups: groups, transport: transport}, nil
}

// Addr returns the API server's address, for logs.
func (s *APIServer) Addr() string { return s.server.Host }

// Ping checks that the API server answers and accepts the credentials.
func (s *APIServer) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.server.JoinPath("/version").String(), nil)
	if err != nil {
		return err
	}
	if err := s.authorize(req.Header); err != nil {
		return err
	}
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kube: %s answered %s", req.URL, resp.Status)
	}
	return nil
}

// Connect returns a connection on which the Gateway speaks HTTP/1.1 to
// Handler. The exit node splices it to a tunnel stream.
func (s *APIServer) Connect(context.Context) (net.Conn, error) {
	s.serve.Do(func() {
		s.listener = newPipeListener()
		go (&http.Server{Handler: s.Handler()}).Serve(s.listener)
	})
	return s.listener.dial()
}

// Handler forwards requests that the Gateway has marked with a user and
// groups to the API server, as the exit node, impersonating them.
func (s *APIServer) Handler() http.Handler {
	proxy := &httputil.ReverseProxy{
		Transport:     s.transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(s.server)
			pr.Out.Host = s.server.Host
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			WriteStatus(w, http.StatusBadGateway, "tunneler: the exit node could not reach the Kubernetes API: "+err.Error())
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, groups := r.Header.Get(headerUser), r.Header.Values(headerGroup)
		switch {
		case user == "":
			WriteStatus(w, http.StatusForbidden, "tunneler: the request names no user to act as")
			return
		case strings.HasPrefix(user, "system:"):
			// Nodes, service accounts and the control plane are not people.
			WriteStatus(w, http.StatusForbidden, fmt.Sprintf("tunneler: refusing to act as the system user %q", user))
			return
		}
		for _, group := range groups {
			if !slices.Contains(s.groups, group) {
				WriteStatus(w, http.StatusForbidden, fmt.Sprintf("tunneler: group %q is not one this exit node may grant", group))
				return
			}
		}
		// Only the user and the vetted groups survive: not an Impersonate-Uid
		// or -Extra the API server would also honor.
		stripIdentity(r.Header)
		r.Header.Set(headerUser, user)
		for _, group := range groups {
			r.Header.Add(headerGroup, group)
		}
		if err := s.authorize(r.Header); err != nil {
			WriteStatus(w, http.StatusBadGateway, "tunneler: the exit node has no credentials: "+err.Error())
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

// authorize adds the exit node's credentials. The kubelet rotates the token,
// so the file is read afresh each time.
func (s *APIServer) authorize(h http.Header) error {
	if s.tokenFile == "" {
		return nil
	}
	token, err := os.ReadFile(s.tokenFile)
	if err != nil {
		return err
	}
	h.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	return nil
}

// pipeListener is a net.Listener whose connections are made in-process, so
// that an http.Server can serve a caller who wants a net.Conn.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

// dial returns the client's end of a new connection to the listener.
func (l *pipeListener) dial() (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
