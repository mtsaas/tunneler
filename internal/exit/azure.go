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
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/mtsaas/tunneler/internal/api"
)

// AzureWorkloadIdentity returns a TokenFunc for a pod running under Azure
// Workload Identity, or an error if the environment is not one: the AKS
// webhook injects AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_AUTHORITY_HOST and
// AZURE_FEDERATED_TOKEN_FILE into pods whose service account opts in.
//
// The pod's projected service account token is exchanged with Entra for an
// access token addressed to the coordinator's own application, whose client
// ID is asked of the coordinator at server. The coordinator admits the token
// if Entra put the application role "exit:<cluster>" in it, which it does
// when that role is assigned to the pod's managed identity. No secret is
// stored anywhere, and nothing about the cluster is configured on the
// coordinator.
func AzureWorkloadIdentity(server string) (TokenFunc, error) {
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

	// exchange runs whenever the cached access token nears expiry. The
	// kubelet rotates the file, so it is read afresh each time.
	exchange := tokenSourceFunc(func() (*oauth2.Token, error) {
		ctx := context.Background()
		audience, err := coordinatorClientID(ctx, server)
		if err != nil {
			return nil, fmt.Errorf("asking coordinator for its client ID: %w", err)
		}
		assertion, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		conf := clientcredentials.Config{
			ClientID:  clientID,
			TokenURL:  tokenURL,
			Scopes:    []string{audience + "/.default"},
			AuthStyle: oauth2.AuthStyleInParams,
			EndpointParams: url.Values{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"client_assertion":      {strings.TrimSpace(string(assertion))},
			},
		}
		return conf.Token(ctx)
	})
	source := oauth2.ReuseTokenSource(nil, exchange)
	return func(context.Context) (string, error) {
		tok, err := source.Token()
		if err != nil {
			return "", fmt.Errorf("azure workload identity: %w", err)
		}
		return tok.AccessToken, nil
	}, nil
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (f tokenSourceFunc) Token() (*oauth2.Token, error) { return f() }

func coordinatorClientID(ctx context.Context, server string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/v1/auth/config", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var ac api.AuthConfig
	if err := json.NewDecoder(resp.Body).Decode(&ac); err != nil {
		return "", err
	}
	if ac.ClientID == "" {
		return "", fmt.Errorf("%s: no client ID in response", resp.Status)
	}
	return ac.ClientID, nil
}
