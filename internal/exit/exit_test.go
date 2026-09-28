package exit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/mtsaas/tunneler/internal/api"
	"github.com/mtsaas/tunneler/internal/tunnel"
)

// A TunnelService never takes the place of the service that the operator's
// file defines under the same name. Sources were once merged in map order,
// so the one that won changed from one reconcile to the next.
func TestDesiredPrefersFile(t *testing.T) {
	file := &service{advert: api.Service{Name: "shared-db"}}
	resource := &service{advert: api.Service{Name: "shared-db", Labels: map[string]string{"namespace": "tunneler"}}}
	a := &Agent{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.SetServices("kubernetes", map[string]*service{"shared-db": resource})
	a.SetServices("file", map[string]*service{"shared-db": file})
	for range 1000 {
		if a.desired()["shared-db"] != file {
			t.Fatal("the TunnelService's shared-db replaced the file's")
		}
	}
}

func TestHelloDropsOversizedServices(t *testing.T) {
	services := make([]api.Service, 0, 5)
	for i := range 4 {
		services = append(services, api.Service{
			Name: string(rune('a' + i)), Labels: map[string]string{"large": strings.Repeat("x", 1<<20)},
		})
	}
	services = append(services, api.Service{Name: "healthy", Labels: map[string]string{"team": "orders"}})
	a := &Agent{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.adverts.Store(&services)

	hello, err := a.hello(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := tunnel.WriteMessage(&wire, hello); err != nil {
		t.Fatalf("the oversized service prevented every service from being advertised: %v", err)
	}
	var sent api.Hello
	if err := tunnel.ReadMessage(&wire, &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent.Services) != 1 || sent.Services[0].Name != "healthy" {
		t.Fatalf("only the healthy service should be advertised: %+v", sent.Services)
	}
}

func TestHelloKeepsLaterServicesWhenFrameFills(t *testing.T) {
	services := make([]api.Service, 0, 71)
	for i := range 70 {
		services = append(services, api.Service{
			Name: fmt.Sprintf("large-%02d", i), Labels: map[string]string{"data": strings.Repeat("x", 60<<10)},
		})
	}
	services = append(services, api.Service{Name: "healthy", Labels: map[string]string{"team": "orders"}})
	a := &Agent{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.adverts.Store(&services)

	hello, err := a.hello(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := tunnel.WriteMessage(&wire, hello); err != nil {
		t.Fatalf("the combined advertisement could not be sent: %v", err)
	}
	var sent api.Hello
	if err := tunnel.ReadMessage(&wire, &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent.Services) == 0 || len(sent.Services) >= len(services) || sent.Services[len(sent.Services)-1].Name != "healthy" {
		t.Fatalf("later healthy service was crowded out: %d services", len(sent.Services))
	}
}
