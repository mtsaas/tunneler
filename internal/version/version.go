// Package version reports which build is running, from the VCS information
// the Go toolchain stamps into binaries built inside a git checkout.
package version

import "runtime/debug"

// String returns the short commit the binary was built from, with "+dirty"
// if the tree had uncommitted changes, or "unknown" for a build made outside
// a checkout (such as a Docker build that excludes .git).
func String() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "+dirty"
			}
		}
	}
	if rev == "" {
		return "unknown"
	}
	return rev[:min(len(rev), 7)] + dirty
}
