package coordinator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

// kubeVerifier verifies Kubernetes service account tokens from clusters whose
// OIDC issuer matches one of the configured patterns. Each cluster is its own
// issuer with its own keys, discovered on first sight and cached.
type kubeVerifier struct {
	client *http.Client // nil for the default; set to trust private issuer certificates

	mu        sync.Mutex
	providers map[string]*oidc.Provider // by issuer; only issuers that trusts accepted
}

// issuerURL is an issuer, or a pattern for issuers, split into the parts
// that decide where discovery goes: the host's labels, the port, and the
// path.
type issuerURL struct {
	labels []string
	port   string
	path   string
}

const (
	labelChars   = "abcdefghijklmnopqrstuvwxyz0123456789-"
	segmentChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

// parseIssuer parses s as an https URL. It refuses anything that could read
// one way as a string and another as a URL: user info, a query, a fragment,
// percent-encoding, a host that is not DNS labels of lowercase letters,
// digits and hyphens, and a path that is not segments of letters, digits and
// "-._~". The path may end in "/" but has no other empty segment, and no "."
// or "..". In a pattern, '*' may also appear in any label or segment.
func parseIssuer(s string, pattern bool) (issuerURL, error) {
	wild := ""
	if pattern {
		wild = "*"
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return issuerURL{}, err
	case u.Scheme != "https" || u.Opaque != "":
		return issuerURL{}, errors.New("must be an https:// URL")
	case u.User != nil || strings.ContainsAny(s, "?#%"):
		return issuerURL{}, errors.New("must not have user info, a query, a fragment or percent-encoding")
	}
	host, port, hasPort := strings.Cut(u.Host, ":")
	if hasPort && !only(port, "0123456789") {
		return issuerURL{}, fmt.Errorf("port %q is not a number", port)
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if !only(l, labelChars+wild) {
			return issuerURL{}, fmt.Errorf("host %q is not DNS labels of lowercase letters, digits and hyphens", host)
		}
	}
	// With a host, the path is empty or begins with "/".
	if p := strings.TrimSuffix(u.Path, "/"); p != "" {
		for _, seg := range strings.Split(p[1:], "/") {
			if seg == "." || seg == ".." || !only(seg, segmentChars+wild) {
				return issuerURL{}, fmt.Errorf("path %q is not segments of letters, digits and \"-._~\"", u.Path)
			}
		}
	}
	return issuerURL{labels, port, u.Path}, nil
}

// only reports whether s is not empty and holds nothing but chars.
func only(s, chars string) bool {
	return s != "" && strings.Trim(s, chars) == ""
}

// matches reports whether p, a pattern, matches iss, an issuer: the same
// port, as many labels, and each label and the path matching in the manner
// of path.Match. A '*' thus never reaches past a '.' in the host or a '/' in
// the path.
func (p issuerURL) matches(iss issuerURL) bool {
	if p.port != iss.port || len(p.labels) != len(iss.labels) {
		return false
	}
	for i := range p.labels {
		if ok, _ := path.Match(p.labels[i], iss.labels[i]); !ok {
			return false
		}
	}
	ok, _ := path.Match(p.path, iss.path)
	return ok
}

// trusts reports whether the token's issuer matches one of the patterns. It
// reads the unverified issuer claim, which is safe because the match is on
// the parts of the parsed URL: only an issuer on a host that a pattern allows
// is ever asked for its keys.
func (v *kubeVerifier) trusts(token string, patterns []string) (issuer string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return "", false
	}
	iss, err := parseIssuer(claims.Issuer, false)
	if err != nil {
		return claims.Issuer, false
	}
	for _, p := range patterns {
		if pattern, err := parseIssuer(p, true); err == nil && pattern.matches(iss) {
			return claims.Issuer, true
		}
	}
	return claims.Issuer, false
}

// verify checks the token against its issuer's keys and the audience, and
// returns the subject, such as system:serviceaccount:tunneler:tunneler-exit.
func (v *kubeVerifier) verify(ctx context.Context, issuer, audience, token string) (subject string, err error) {
	if v.client != nil {
		ctx = oidc.ClientContext(ctx, v.client)
	}
	v.mu.Lock()
	provider := v.providers[issuer]
	v.mu.Unlock()
	if provider == nil {
		// Discovery is a network round trip; not under the lock.
		if provider, err = oidc.NewProvider(ctx, issuer); err != nil {
			return "", fmt.Errorf("discovering issuer %s: %w", issuer, err)
		}
		v.mu.Lock()
		v.providers[issuer] = provider
		v.mu.Unlock()
	}
	idToken, err := provider.VerifierContext(ctx, &oidc.Config{ClientID: audience}).Verify(ctx, token)
	if err != nil {
		return "", err
	}
	if idToken.Subject == "" {
		return "", errors.New("token has no subject")
	}
	return idToken.Subject, nil
}

// newKubeVerifier builds the verifier for cfg, loading the CA bundle if one
// is configured.
func newKubeVerifier(cfg *Config) (*kubeVerifier, error) {
	v := &kubeVerifier{providers: make(map[string]*oidc.Provider)}
	if cfg.ExitIssuerCAFile == "" {
		return v, nil
	}
	client, err := caClient(cfg.ExitIssuerCAFile)
	if err != nil {
		return nil, fmt.Errorf("exit_issuer_ca_file: %w", err)
	}
	v.client = client
	return v, nil
}

// caClient returns an HTTP client that trusts the PEM bundle in file, and
// nothing else, when verifying servers.
func caClient(file string) (*http.Client, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificates", file)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	return &http.Client{Transport: transport}, nil
}
