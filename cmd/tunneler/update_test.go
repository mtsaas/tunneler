package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateNotice(t *testing.T) {
	serverVersion := "v0.3.0 (abcdef0)"
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		json.NewEncoder(w).Encode(map[string]string{"version": serverVersion})
	}))
	defer srv.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("TUNNELER_SERVER", "")
	dir, _ := os.UserConfigDir()
	if err := os.MkdirAll(filepath.Join(dir, "tunneler"), 0o700); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(map[string]string{"server": srv.URL})
	if err := os.WriteFile(filepath.Join(dir, "tunneler", "config.json"), config, 0o600); err != nil {
		t.Fatal(err)
	}

	cache := filepath.Join(t.TempDir(), "update.json")
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	checkUpdate(context.Background(), cache, "v0.2.3 (1234567)", now, &out)
	if got := out.String(); !strings.Contains(got, "v0.2.3 -> v0.3.0") {
		t.Fatalf("notice = %q", got)
	}

	// The cached coordinator version avoids another request, but the same
	// release is shown after every command until it is explicitly hidden.
	out.Reset()
	checkUpdate(context.Background(), cache, "v0.2.3", now.Add(time.Hour), &out)
	if got := out.String(); !strings.Contains(got, "v0.2.3 -> v0.3.0") ||
		!strings.Contains(got, "tunneler update hide") || requests != 1 {
		t.Fatalf("second check wrote %q after %d requests", out.String(), requests)
	}

	state := readUpdateState(cache)
	state.HiddenVersion = state.Coordinator
	if err := writeUpdateState(cache, state); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	checkUpdate(context.Background(), cache, "v0.2.3", now.Add(2*time.Hour), &out)
	if out.Len() != 0 || requests != 1 {
		t.Fatalf("hidden notice wrote %q after %d requests", out.String(), requests)
	}

	// A later coordinator release is not hidden by dismissing the prior one.
	serverVersion = "v0.4.0"
	checkUpdate(context.Background(), cache, "v0.2.3", now.Add(25*time.Hour), &out)
	if got := out.String(); !strings.Contains(got, "v0.2.3 -> v0.4.0") || requests != 2 {
		t.Fatalf("new release notice = %q after %d requests", got, requests)
	}
}

func TestUpdateHideCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	state := updateState{Server: "https://tunneler.example.com", Coordinator: "v0.3.0"}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	path := updateStatePath(cacheDir)
	if err := writeUpdateState(path, state); err != nil {
		t.Fatal(err)
	}

	cmd, _, err := rootCmd().Find([]string{"update", "hide"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if got := readUpdateState(path).HiddenVersion; got != "v0.3.0" {
		t.Fatalf("hidden version = %q, want v0.3.0", got)
	}
}

func TestOldNotificationCacheDoesNotHideNotice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.json")
	oldState := `{"server":"https://tunneler.example.com","coordinator":"v0.3.0","notified_version":"v0.3.0"}`
	if err := os.WriteFile(path, []byte(oldState), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readUpdateState(path).HiddenVersion; got != "" {
		t.Fatalf("old automatic notification became an explicit dismissal: %q", got)
	}
}

func TestUpdateNoticeNeedsComparableReleases(t *testing.T) {
	for _, version := range []string{"", "unknown", "abcdef0", "release-0.2.0"} {
		if got := releaseVersion(version); got != "" {
			t.Errorf("releaseVersion(%q) = %q", version, got)
		}
	}
	if got := releaseVersion("v1.2.3 (abcdef0)"); got != "v1.2.3" {
		t.Errorf("releaseVersion tagged build = %q", got)
	}
	if got := releaseVersion("v1.2.3+abcdef0 (abcdef0)"); got != "v1.2.3" {
		t.Errorf("releaseVersion main build = %q", got)
	}
}
