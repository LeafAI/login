package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/LeafAI/securl/internal/mcpserver"
)

// versionLine describes this build: the release version (set with -ldflags, see mcpserver.Version),
// the commit it was built from when known, and the Go toolchain.
func versionLine() string {
	rev := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch {
			case s.Key == "vcs.revision" && len(s.Value) >= 7:
				rev = " (" + s.Value[:7] + ")"
			case s.Key == "vcs.modified" && s.Value == "true" && rev != "":
				rev = rev[:len(rev)-1] + ", modified)"
			}
		}
	}
	return fmt.Sprintf("login %s%s %s %s/%s", mcpserver.Version, rev, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
