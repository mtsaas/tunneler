package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/mtsaas/tunneler/internal/api"
)

// Sequences that a namespace tenant, an exit node or the coordinator could
// hide in what the CLI prints.
const (
	clearScreen = "\x1b[2J"           // CSI, as ESC [
	setTitle    = "\x1b]0;pwned\a"    // OSC
	clearC1     = "\U0000009b2J"      // CSI, as the one C1 character
	reorder     = "\U0000202egnp.exe" // right-to-left override
)

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"":                   "",
		"prod":               "prod",
		"team=shop,env=prod": "team=shop,env=prod",
		`C:\dir "quoted"`:    `C:\dir "quoted"`,
		"Zoë, 日本語":           "Zoë, 日本語",
		clearScreen:          `\x1b[2J`,
		setTitle:             `\x1b]0;pwned\a`,
		clearC1:              `\u009b2J`,
		reorder:              `\u202egnp.exe`,
		"a\nforged\trow\r":   `a\nforged\trow\r`,
		"del\x7f nul\x00":    `del\x7f nul\x00`,
		"not utf-8 \x9b2J":   "not utf-8 \U0000fffd2J",
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestUntrustedTextIsPrintable runs each command that prints what the
// coordinator relays, with a sequence hidden in every field: as a rogue exit
// node could send them, and as a tenant could through the status of their
// database, whose host the exit node's error repeats. The terminal gets
// each sequence as visible text, never as the characters themselves.
func TestUntrustedTextIsPrintable(t *testing.T) {
	unreachable := "dial tcp: lookup db" + clearScreen + clearC1 + ": no such host"
	hostile := api.Cluster{Name: "prod" + setTitle, Services: []api.Service{{
		Name: "shop" + clearScreen, Kind: "postgres" + reorder, Status: unreachable,
		Labels: map[string]string{"name": "shop", "team": "shop" + clearScreen + setTitle},
	}}}
	ready := api.Cluster{Name: "dev", Services: []api.Service{{
		Name: "orders", Kind: "postgres", Ready: true, Labels: map[string]string{"name": "orders"},
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/clusters":
			json.NewEncoder(w).Encode([]api.Cluster{hostile, ready})
		case "GET /v1/auth/status":
			json.NewEncoder(w).Encode(api.AuthStatus{
				Subject: "1" + clearScreen, Username: "alice" + setTitle, Groups: []string{"dba" + reorder, "ops" + clearC1},
				Grants: []api.Grant{{Group: "dba" + reorder, Labels: map[string]string{"team": "shop" + clearScreen},
					Roles: []string{"readonly" + setTitle}}},
				Clusters: []api.Cluster{hostile},
			})
		case "POST /v1/sessions":
			// The listing said ready, but by now the exit node cannot reach
			// the service, and the coordinator's refusal repeats why.
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(api.Error{Message: "dev/orders is registered but its exit node cannot reach it: " + unreachable})
		case "GET /v1/sessions":
			json.NewEncoder(w).Encode([]api.Session{{ID: "s1", Owner: "alice" + setTitle, Cluster: hostile.Name,
				Service: hostile.Services[0].Name, Username: "tnl_" + reorder}})
		case "GET /v1/clusters/bindings":
			json.NewEncoder(w).Encode([]api.ClusterBinding{{Name: hostile.Name, Issuer: "https://evil.example.com" + clearScreen, ExitNodes: 1}})
		case "GET /healthz":
			json.NewEncoder(w).Encode(map[string]string{"version": "v9.9.9" + setTitle})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	for _, args := range [][]string{
		{"services", "list"},
		{"auth", "status"},
		{"connect", "name=shop"},   // refused by the CLI, which repeats the status
		{"connect", "name=orders"}, // refused by the coordinator, likewise
		{"sessions", "list"},
		{"clusters", "list"},
		{"version"},
	} {
		out, errOut, _ := cli(t, srv.URL, args...)
		if raw(out + errOut) {
			t.Errorf("tunneler %s printed control characters:\n%q\n%q", strings.Join(args, " "), out, errOut)
		}
		if !strings.Contains(out+errOut, `\x1b`) {
			t.Errorf("tunneler %s did not show the sequence as text:\n%s%s", strings.Join(args, " "), out, errOut)
		}
	}

	// Nor in the timeline that connect writes as it goes.
	var timeline bytes.Buffer
	record := slog.NewRecord(time.Now(), slog.LevelWarn, "Requesting access to "+hostile.Name+"/shop...", 0)
	record.AddAttrs(slog.Any("err", errors.New(unreachable)))
	statusHandler{w: &timeline, mu: new(sync.Mutex)}.Handle(context.Background(), record)
	if raw(timeline.String()) || !strings.Contains(timeline.String(), `\x1b[2J`) {
		t.Errorf("status line = %q", timeline.String())
	}
}

// TestPlainServices renders a listing with nothing to escape, which must
// look as it always has.
func TestPlainServices(t *testing.T) {
	var out bytes.Buffer
	printServices(&out, []api.Cluster{{Name: "dev", Services: []api.Service{
		{Name: "orders", Kind: "postgres", Ready: true, Labels: map[string]string{"cluster": "dev", "name": "orders"}},
		{Name: "billing", Kind: "postgres", Status: "no such host", Labels: map[string]string{"cluster": "dev", "name": "billing"}},
	}}}, true)
	want := "" +
		"    CLUSTER   SERVICE   KIND       STATUS                      LABELS\n" +
		"1   dev       orders    postgres   ready                       cluster=dev,name=orders\n" +
		"2   dev       billing   postgres   unreachable: no such host   cluster=dev,name=billing\n"
	if out.String() != want {
		t.Errorf("printServices wrote\n%s\nwant\n%s", out.String(), want)
	}
}

// raw reports whether s holds a control character other than a line end,
// or a character that reorders text.
func raw(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r))
	})
}
