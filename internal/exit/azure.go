package exit

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/mtsaas/tunneler/internal/coordinator"
)

// TokenFile returns a TokenFunc that presents the token in the file at path,
// read afresh on every call because Kubernetes rotates it. The file is a
// projected service account token whose audience is the coordinator's
// exit_audience; the coordinator verifies it against the cluster's own OIDC
// issuer, so nothing has to be registered anywhere for a new cluster.
func TokenFile(path string) coordinator.TokenFunc {
	return func(context.Context) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
}

// AzureCredential obtains Entra access tokens for a pod running under Azure
// Workload Identity: the AKS webhook injects AZURE_CLIENT_ID, AZURE_TENANT_ID,
// AZURE_AUTHORITY_HOST and AZURE_FEDERATED_TOKEN_FILE into pods whose service
// account opts in. The pod's projected token is exchanged with Entra for an
// access token for whatever scope is asked, such as Key Vault's. No secret
// is stored anywhere.
type AzureCredential struct {
	clientID, tokenURL, file string

	mu      sync.Mutex
	sources map[string]oauth2.TokenSource // by scope; each caches until near expiry
}

// NewAzureCredential returns an error if the environment is not a workload
// identity pod.
func NewAzureCredential() (*AzureCredential, error) {
	clientID, tenant := os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_TENANT_ID")
	file := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	authority := cmp.Or(os.Getenv("AZURE_AUTHORITY_HOST"), "https://login.microsoftonline.com/")
	if clientID == "" || tenant == "" || file == "" {
		return nil, errors.New("not running under Azure Workload Identity: AZURE_CLIENT_ID, AZURE_TENANT_ID or AZURE_FEDERATED_TOKEN_FILE is unset")
	}
	tokenURL, err := url.JoinPath(authority, tenant, "oauth2/v2.0/token")
	if err != nil {
		return nil, err
	}
	return &AzureCredential{clientID: clientID, tokenURL: tokenURL, file: file, sources: make(map[string]oauth2.TokenSource)}, nil
}

// Token returns an access token for the scope, such as
// "https://vault.azure.net/.default".
func (c *AzureCredential) Token(ctx context.Context, scope string) (string, error) {
	c.mu.Lock()
	source, ok := c.sources[scope]
	if !ok {
		// The exchange runs whenever the cached token nears expiry. The
		// kubelet rotates the file, so it is read afresh each time. The
		// source outlives any one caller, so the exchange cannot use a
		// caller's context; it has 10 seconds of its own instead, so that
		// an Entra that does not answer cannot hold up its callers forever.
		source = oauth2.ReuseTokenSource(nil, tokenSourceFunc(func() (*oauth2.Token, error) {
			assertion, err := os.ReadFile(c.file)
			if err != nil {
				return nil, err
			}
			conf := clientcredentials.Config{
				ClientID:  c.clientID,
				TokenURL:  c.tokenURL,
				Scopes:    []string{scope},
				AuthStyle: oauth2.AuthStyleInParams,
				EndpointParams: url.Values{
					"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
					"client_assertion":      {strings.TrimSpace(string(assertion))},
				},
			}
			ctx, cancel := context.WithTimeoutCause(context.Background(), 10*time.Second, errors.New("no answer within 10s"))
			defer cancel()
			return conf.Token(ctx)
		}))
		c.sources[scope] = source
	}
	c.mu.Unlock()

	tok, err := source.Token()
	if err != nil {
		return "", fmt.Errorf("azure workload identity: %w", err)
	}
	return tok.AccessToken, nil
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (f tokenSourceFunc) Token() (*oauth2.Token, error) { return f() }

// AzureWorkloadIdentity returns a TokenFunc that authenticates to the
// coordinator with an access token for the coordinator's own application,
// which audience names by its client ID or application ID URI. The
// coordinator admits it if Entra put the application role "exit:<cluster>"
// in it, which it does when that role is assigned to the pod's managed
// identity.
//
// The audience is never asked of the coordinator. The coordinator receives
// the token, so it could otherwise name a resource such as Key Vault and
// receive a token for that.
func AzureWorkloadIdentity(cred *AzureCredential, audience string) coordinator.TokenFunc {
	return func(ctx context.Context) (string, error) {
		return cred.Token(ctx, audience+"/.default")
	}
}

// maxKeyVaultResponse is the most of a response from Key Vault that is read.
// Key Vault limits a secret's value to 25 KB; this leaves room for JSON
// escaping and for the rest of the response.
const maxKeyVaultResponse = 256 << 10

// keyVaultSecret reads a secret's current value from Azure Key Vault.
func keyVaultSecret(ctx context.Context, cred *AzureCredential, vaultURI, name string) (string, error) {
	if cred == nil {
		return "", errors.New("no Azure credential: the exit node is not running under Azure Workload Identity")
	}
	token, err := cred.Token(ctx, "https://vault.azure.net/.default")
	if err != nil {
		return "", err
	}
	u, err := url.JoinPath(vaultURI, "secrets", name)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u+"?api-version=7.4", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyVaultResponse+1))
	if err != nil {
		return "", fmt.Errorf("key vault: %s: %w", resp.Status, err)
	}
	if len(b) > maxKeyVaultResponse {
		return "", fmt.Errorf("key vault: %s: the response is over %d KiB, larger than any secret", resp.Status, maxKeyVaultResponse>>10)
	}
	var body struct {
		Value string `json:"value"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		return "", fmt.Errorf("key vault: %s: %w", resp.Status, err)
	}
	if body.Error != nil {
		return "", fmt.Errorf("key vault: %s: %s", body.Error.Code, body.Error.Message)
	}
	if body.Value == "" {
		return "", fmt.Errorf("key vault: %s: secret %s has no value", resp.Status, name)
	}
	return body.Value, nil
}

var (
	// A vault URI is a scheme and a host with an optional port, and nothing
	// else. It is ASCII, so that folding its case cannot turn one host into
	// another.
	vaultURIPattern = regexp.MustCompile(`^([A-Za-z]+://[0-9A-Za-z.:\[\]-]+)/?$`)
	// What Key Vault accepts as the name of a secret.
	secretNamePattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
)

// keyVaultSecretID returns the identifier of the named secret in the vault,
// <vault URI>/secrets/<name>, spelled one way however the vault URI is:
// scheme and host in lower case, no trailing slash. A vault URI with a path,
// a query or a user, or a name that Key Vault would not accept, is refused,
// so that references with the same identifier are the same secret, the one
// keyVaultSecret fetches.
func keyVaultSecretID(vaultURI, name string) (string, error) {
	m := vaultURIPattern.FindStringSubmatch(vaultURI)
	if m == nil {
		return "", fmt.Errorf("vault URI %q is not of the form https://<vault>.vault.azure.net", vaultURI)
	}
	if !secretNamePattern.MatchString(name) {
		return "", fmt.Errorf("%q is not the name of a Key Vault secret", name)
	}
	return strings.ToLower(m[1]) + "/secrets/" + name, nil
}

// ParseKeyVaultSecrets reads the Key Vault secrets that namespaces may use,
// each given as NAMESPACE=https://<vault>.vault.azure.net/secrets/<name>,
// into the KeyVaultSecrets of a Discovery.
func ParseKeyVaultSecrets(allow []string) (map[string][]string, error) {
	secrets := make(map[string][]string)
	for _, a := range allow {
		namespace, secret, _ := strings.Cut(a, "=")
		vaultURI, name, ok := strings.Cut(secret, "/secrets/")
		id, err := keyVaultSecretID(vaultURI, name)
		if namespace == "" || !ok || err != nil {
			return nil, fmt.Errorf("%q is not of the form NAMESPACE=https://<vault>.vault.azure.net/secrets/<name>", a)
		}
		secrets[namespace] = append(secrets[namespace], id)
	}
	return secrets, nil
}
