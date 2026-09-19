package exit

import (
	"io"
	"log/slog"
	"testing"

	"github.com/mtsaas/tunneler/internal/api"
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
