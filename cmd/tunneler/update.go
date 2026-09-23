package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
	"golang.org/x/term"

	"github.com/mtsaas/tunneler/internal/version"
)

const updateCheckInterval = 24 * time.Hour

type updateState struct {
	Server        string    `json:"server"`
	CheckedAt     time.Time `json:"checked_at"`
	Coordinator   string    `json:"coordinator"`
	HiddenVersion string    `json:"hidden_version,omitempty"`
}

// notifyUpdate quietly checks whether this interactive client trails its
// coordinator. A newer coordinator version is shown after every successful
// command until the person hides it. Automated output and server processes
// are left alone.
func notifyUpdate(cmd *cobra.Command) {
	if outputJSON || os.Getenv("TUNNELER_NO_UPDATE_CHECK") != "" || !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}
	path := cmd.CommandPath()
	if path == "tunneler version" || strings.HasPrefix(path, "tunneler start ") || strings.HasPrefix(path, "tunneler completion ") {
		return
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), time.Second)
	defer cancel()
	checkUpdate(ctx, updateStatePath(dir), version.String(), time.Now(), os.Stderr)
}

// checkUpdate writes a notice if the configured coordinator has a newer
// release than the client. Failures are ignored because update discovery must
// never make a command fail; the caller bounds the check after command output.
func checkUpdate(ctx context.Context, cachePath, clientVersion string, now time.Time, out io.Writer) {
	c, err := loadClient()
	if err != nil || c.Server == "" {
		return
	}
	state := readUpdateState(cachePath)
	if state.Server != c.Server {
		state = updateState{Server: c.Server}
	}
	if state.CheckedAt.IsZero() || now.Sub(state.CheckedAt) >= updateCheckInterval {
		coordinatorVersion, err := c.Version(ctx)
		if err != nil {
			return
		}
		state.CheckedAt = now
		state.Coordinator = releaseVersion(coordinatorVersion)
	}

	clientVersion = releaseVersion(clientVersion)
	newer := semver.IsValid(clientVersion) && semver.IsValid(state.Coordinator) &&
		semver.Compare(state.Coordinator, clientVersion) > 0
	if newer && state.HiddenVersion != state.Coordinator {
		if writeUpdateState(cachePath, state) == nil {
			fmt.Fprintf(out, "\nA newer tunneler client is available: %s -> %s (your coordinator's version).\nRun the install command again to update, or `tunneler update hide` to hide this notice.\n", clientVersion, state.Coordinator)
		}
		return
	}
	_ = writeUpdateState(cachePath, state)
}

func updateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Manage client update notices",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "hide",
		Short: "Hide the current client update notice",
		Args:  usage(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			dir, err := os.UserCacheDir()
			if err != nil {
				return err
			}
			path := updateStatePath(dir)
			state := readUpdateState(path)
			state.HiddenVersion = state.Coordinator
			if err := writeUpdateState(path, state); err != nil {
				return err
			}
			result(map[string]string{"hidden": state.HiddenVersion}, "The current client update notice is hidden.")
			return nil
		},
	})
	return cmd
}

func updateStatePath(cacheDir string) string {
	return filepath.Join(cacheDir, "tunneler", "update.json")
}

func releaseVersion(v string) string {
	v, _, _ = strings.Cut(strings.TrimSpace(v), " ")
	if semver.IsValid(v) {
		return semver.Canonical(v)
	}
	return ""
}

func readUpdateState(path string) updateState {
	data, err := os.ReadFile(path)
	if err != nil {
		return updateState{}
	}
	var state updateState
	if json.Unmarshal(data, &state) != nil {
		return updateState{}
	}
	return state
}

func writeUpdateState(path string, state updateState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
