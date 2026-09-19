package exit

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

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
		// kubelet rotates the file, so it is read afresh each time.
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
			return conf.Token(context.Background())
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
// coordinator at server with an access token for the coordinator's own
// application. The coordinator admits it if Entra put the application role
// "exit:<cluster>" in it, which it does when that role is assigned to the
// pod's managed identity.
//
// The token is for audience, the application's client ID or application ID
// URI. If audience is empty, it is for the client ID that the coordinator
// reports, which must be a GUID. The coordinator receives the token, so it
// must not choose a resource such as https://vault.azure.net, or it would
// receive a Key Vault token for the managed identity. A GUID can still name
// another application, Microsoft Graph's among them, so audience should be
// set.
func AzureWorkloadIdentity(cred *AzureCredential, server, audience string) coordinator.TokenFunc {
	return func(ctx context.Context) (string, error) {
		if audience == "" {
			ac, err := (&coordinator.Client{Server: server}).AuthConfig(ctx)
			if err != nil {
				return "", fmt.Errorf("asking coordinator for its client ID: %w", err)
			}
			if !clientID.MatchString(ac.ClientID) {
				return "", fmt.Errorf("coordinator reports client ID %q, which is not a GUID; refusing to request a token for it", ac.ClientID)
			}
			// The first answer stands for the life of the process, so that
			// a coordinator compromised later cannot change it.
			audience = ac.ClientID
		}
		return cred.Token(ctx, audience+"/.default")
	}
}

// clientID matches an Entra application (client) ID.
var clientID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

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
	var body struct {
		Value string `json:"value"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
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
