// Package version holds build identity for the aksum binary.
//
// The values are compile-time defaults; release builds stamp them via:
//
//	go build -ldflags "-X github.com/QYVORA/qyvora-aksum/internal/version.Version=<tag> ..."
//
// Unstamped dev builds report "dev" — release artifacts must never do so
// (QYVORA output spec, section 4).
package version

var (
	Version   = "dev"
	Commit    = "none"
	Date      = "unknown"
	BuildUser = "unknown"
)
