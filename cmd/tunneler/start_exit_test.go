package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Under Azure Workload Identity, with no service account token, the exit
// node does not start until it is told which application to request tokens
// for.
func TestStartExitAudience(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "federated-token"), []byte("projected-sa-token"), 0o600)
	t.Setenv("AZURE_CLIENT_ID", "exit-identity")
	t.Setenv("AZURE_TENANT_ID", "my-tenant")
	t.Setenv("AZURE_AUTHORITY_HOST", "http://127.0.0.1:1/")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", filepath.Join(dir, "federated-token"))

	const app = "4f1b2c3d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	for _, tt := range []struct {
		name, flag, env string
		want            string // in the error
	}{
		{"no audience", "", "", "--audience or $TUNNELER_AUDIENCE is required"},
		// With no services to offer, a start that gets past its
		// credentials fails there instead, before it connects.
		{"--audience", app, "", "no services"},
		{"$TUNNELER_AUDIENCE", "", app, "no services"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TUNNELER_AUDIENCE", tt.env)
			args := []string{"start", "exit", "--server", "http://127.0.0.1:1", "--cluster", "dev", "--health-addr", "",
				"--token-file", filepath.Join(dir, "no-token"), "--config", filepath.Join(dir, "no-exit.json")}
			if tt.flag != "" {
				args = append(args, "--audience", tt.flag)
			}
			if _, errOut, status := cli(t, "http://127.0.0.1:1", args...); status == 0 || !strings.Contains(errOut, tt.want) {
				t.Errorf("status %d, %q; want an error with %q", status, errOut, tt.want)
			}
		})
	}
}
