package coordinator

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Identity is an authenticated user or, when it has no Username, workload.
type Identity struct {
	Subject  string   // stable and unique; what audit trails should key on
	UserID   string   // how the provider's directory names the user, for grants; may equal Subject
	Username string   // human-readable; used to name provisioned accounts
	Groups   []string // what grants are matched against
	Roles    []string // application roles; "exit:<cluster>" lets a workload be that cluster's exit node
}

// Is reports whether principal names this identity: its user ID, or its
// username compared case-insensitively.
func (id *Identity) Is(principal string) bool {
	return principal != "" && (principal == id.UserID || strings.EqualFold(principal, id.Username))
}

// An Authenticator verifies a bearer token and returns who it belongs to.
type Authenticator func(ctx context.Context, token string) (*Identity, error)

// NewOIDCAuthenticator returns an Authenticator that accepts ID tokens issued
// by the configured provider for the configured client. It fetches the
// provider's discovery document, so the issuer must be reachable.
func NewOIDCAuthenticator(ctx context.Context, cfg OIDCConfig) (Authenticator, error) {
	if cfg.CAFile != "" {
		client, err := caClient(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("oidc.ca_file: %w", err)
		}
		ctx = oidc.ClientContext(ctx, client) // the provider keeps it, for fetching keys later
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return func(ctx context.Context, token string) (*Identity, error) {
		idToken, err := verifier.Verify(ctx, token)
		if err != nil {
			return nil, err
		}
		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			return nil, err
		}
		// Entra omits the groups claim from tokens of users in too many
		// groups and points at the Graph API instead. Failing beats silently
		// treating the user as a member of nothing.
		if names, _ := claims["_claim_names"].(map[string]any); names[cfg.GroupsClaim] != nil {
			return nil, errors.New("token has a groups overage; configure the app registration to emit only groups assigned to the application")
		}

		id := &Identity{Subject: idToken.Subject}
		id.Username, _ = claims[cfg.UsernameClaim].(string)
		if id.UserID, _ = claims[cfg.UserIDClaim].(string); id.UserID == "" {
			id.UserID = idToken.Subject
		}
		id.Groups = stringsClaim(claims[cfg.GroupsClaim])
		id.Roles = stringsClaim(claims["roles"])
		return id, nil
	}, nil
}

func stringsClaim(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
