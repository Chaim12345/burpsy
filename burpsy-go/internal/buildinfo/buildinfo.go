// Package buildinfo answers "which build is this" for every binary (burpsy-react-ui-release-version).
//
// The release workflow stamps Version with -ldflags -X from the tag. Without a stamp the module
// version from the build metadata is used, and without that "dev". The stamp exists because the Go
// module lives in burpsy-go/, so a repository tag such as v1.2.0 is not the module's version and
// `go build` from a tagged checkout reports "(devel)".
package buildinfo

import "runtime/debug"

// Version is set at link time: -ldflags "-X github.com/burpsy-go/burpsy/internal/buildinfo.Version=v1.2.0".
var Version string

// String reports the stamped version, else the module version, else "dev".
func String() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}
