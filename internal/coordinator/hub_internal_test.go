package coordinator

import (
	"log/slog"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mtsaas/tunneler/internal/api"
)

// TestUnprintableServices offers services with control characters in their
// names or labels, as a rogue exit node could, or a tenant through the
// labels of their TunnelService. Those services are refused, and only
// those: the node's other services are offered as usual.
func TestUnprintableServices(t *testing.T) {
	c, err := New(&Config{Database: filepath.Join(t.TempDir(), "t.db")}, nil, slog.New(slog.DiscardHandler), slog.DiscardHandler)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.hub.advertise("prod", &exitConn{remote: "one"}, api.Hello{Services: []api.Service{
		{Name: "orders", Kind: "postgres"},
		{Name: "shop\x1b[2J", Kind: "postgres"},
		{Name: "billing", Kind: "postgres\U0000202e"},
		{Name: "stock", Kind: "postgres", Database: "stock\U0000009b2J"},
		{Name: "ledger", Kind: "postgres", Labels: map[string]string{"team": "shop\x1b]0;pwned\a"}},
		{Name: "audit", Kind: "postgres", Labels: map[string]string{"team\n": "shop"}},
		// A status is free text, from errors the exit node meets; the CLI
		// escapes it as it prints it.
		{Name: "unreachable", Kind: "postgres", Status: "lookup db\x1b[2J: no such host"},
	}})
	var offered []string
	for _, svc := range c.hub.services("prod") {
		offered = append(offered, svc.Name)
	}
	if want := []string{"orders", "unreachable"}; !slices.Equal(offered, want) {
		t.Errorf("offered %q, want %q", offered, want)
	}
}
