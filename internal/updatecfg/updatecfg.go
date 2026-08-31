// Package updatecfg pins aksum's updater to its official release source:
// the QYVORA/qyvora-aksum GitHub repository and nothing else. Both the
// one-shot CLI command and the interactive console share this single
// configuration.
package updatecfg

import (
	"fmt"

	"github.com/QYVORA/qyvora-aksum/internal/selfupdate"
	"github.com/QYVORA/qyvora-aksum/internal/version"
)

// Config returns the official release source for aksum self-updates.
func Config() selfupdate.Config {
	return selfupdate.Config{
		Owner:    "QYVORA",
		Repo:     "qyvora-aksum",
		ToolName: "aksum",
		CurrentVersion: func() string {
			return version.Version
		},
		ArtifactName: func(goos, goarch string) string {
			name := fmt.Sprintf("aksum-%s-%s", goos, goarch)
			if goos == "darwin" {
				name = fmt.Sprintf("aksum-macos-%s", goarch)
			}
			if goos == "windows" {
				name += ".exe"
			}
			return name
		},
		ChecksumAsset: func(string) string { return "checksums.txt" },
	}
}
