package coordinator

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/mtsaas/tunneler/internal/api"
)

// TestGatewayHandlerLifetime keeps a service's handler while any exit node
// offers the service, and drops it once none does: offered anew after its
// exit nodes disconnected, the service is served by a new handler.
func TestGatewayHandlerLifetime(t *testing.T) {
	c, err := New(&Config{Database: filepath.Join(t.TempDir(), "t.db")}, nil, slog.New(slog.DiscardHandler), slog.DiscardHandler)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	svc := api.Service{Name: "kubernetes", Kind: "kubernetes"}
	hello := api.Hello{Services: []api.Service{svc}}
	one, two := &exitConn{remote: "one"}, &exitConn{remote: "two"}
	c.hub.advertise("prod", one, hello)
	c.hub.advertise("prod", two, hello)
	first := c.gateways.handler(c, "prod", svc)

	c.hub.remove("prod", one)
	if c.gateways.handler(c, "prod", svc) != first {
		t.Error("the handler was dropped while an exit node still offered its service")
	}
	c.hub.remove("prod", two)
	c.hub.advertise("prod", &exitConn{remote: "three"}, hello)
	if c.gateways.handler(c, "prod", svc) == first {
		t.Error("offered anew after its exit nodes disconnected, the service was served by the handler from before")
	}
}
