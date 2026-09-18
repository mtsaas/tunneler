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
	patterns []string // path.Match patterns for the issuer URL
	audience string
	client   *http.Client // nil for the default; set to trust private issuer certificates

	mu        sync.Mutex
	providers map[string]*oidc.Provider // by issuer
}

// trusts reports whether the token's issuer matches a pattern. It reads the
// unverified issuer claim, which is safe: it only decides whether to try
// verifying against that issuer's keys.
func (v *kubeVerifier) trusts(token string) (issuer string, ok bool) {
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
	for _, p := range v.patterns {
		if ok, _ := path.Match(p, claims.Issuer); ok {
			return claims.Issuer, true
		}
	}
	return claims.Issuer, false
}

// verify checks the token against its issuer's keys and returns the issuer
// and subject, such as system:serviceaccount:tunneler:tunneler-exit.
func (v *kubeVerifier) verify(ctx context.Context, issuer, token string) (subject string, err error) {
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
	idToken, err := provider.VerifierContext(ctx, &oidc.Config{ClientID: v.audience}).Verify(ctx, token)
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
	v := &kubeVerifier{patterns: cfg.ExitIssuers, audience: cfg.ExitAudience, providers: make(map[string]*oidc.Provider)}
	if cfg.ExitIssuerCAFile == "" {
		return v, nil
	}
	pem, err := os.ReadFile(cfg.ExitIssuerCAFile)
	if err != nil {
		return nil, fmt.Errorf("exit_issuer_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("exit_issuer_ca_file: %s holds no certificates", cfg.ExitIssuerCAFile)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	v.client = &http.Client{Transport: transport}
	return v, nil
}
