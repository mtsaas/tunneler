// Package version reports which build is running, from the VCS information
// the Go toolchain stamps into binaries built inside a git checkout.
package version

import "runtime/debug"

// tag is the release, such as v0.1.0, set by the linker for release builds.
var tag string

// String returns the release, if this is a release build, and the short
// commit the binary was built from, with "+dirty" if the tree had uncommitted
// changes. A build made outside a checkout (such as a Docker build that
// excludes .git) has no commit.
func String() string {
	switch rev := revision(); {
	case tag != "" && rev != "":
		return tag + " (" + rev + ")"
	case tag != "":
		return tag
	case rev != "":
		return rev
	}
	return "unknown"
}

func revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
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
		return ""
	}
	return rev[:min(len(rev), 7)] + dirty
}
