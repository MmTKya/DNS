// Package version carries build identity.
//
// The values are stamped by the linker (see the Makefile and .goreleaser.yaml).
// A binary built without stamping reports "dev", which is what tells the update
// checker in phase 6 not to offer an upgrade over a locally built binary.
package version

import "runtime/debug"

var (
	// Version is the release version, e.g. "v0.1.0".
	Version = "dev"

	// Commit is the git revision the binary was built from.
	Commit = ""

	// Date is the build timestamp in RFC 3339 format.
	Date = ""
)

// Info describes the running build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
}

// Get returns the build identity, falling back to the revision Go embeds in
// the binary when the linker flags were not supplied.
func Get() Info {
	info := Info{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
	}

	build, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}

	info.GoVersion = build.GoVersion

	for _, s := range build.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		}
	}

	return info
}

// IsDevBuild reports whether this binary came from a release pipeline.
func IsDevBuild() bool { return Version == "dev" }
