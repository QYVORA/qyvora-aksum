// Package updatecfg pins aksum's updater to its official release source:
// the QYVORA/qyvora-aksum GitHub repository and nothing else. Both the
// one-shot CLI command and the interactive console share this single
// configuration.
package updatecfg

import (
	"fmt"
	"strings"

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
		// The release pipeline publishes versioned archives
		// (aksum_<version>_<os>_<arch>.tar.gz, .zip on windows), so the asset
		// name embeds the tag. GoReleaser strips the leading "v" and names
		// darwin assets "macos".
		ArtifactName: func(version, goos, goarch string) string {
			os := goos
			if os == "darwin" {
				os = "macos"
			}
			ver := strings.TrimPrefix(strings.TrimPrefix(version, "v"), "V")
			name := fmt.Sprintf("aksum_%s_%s_%s", ver, os, goarch)
			if goos == "windows" {
				return name + ".zip"
			}
			return name + ".tar.gz"
		},
		ChecksumAsset: func(string) string { return "checksums.txt" },
		// The asset is an archive, not the raw binary: extract the single
		// executable entry before installing it.
		ArchiveFor: func(goos, goarch string) (selfupdate.ArchiveKind, string) {
			if goos == "windows" {
				return selfupdate.ArchiveZip, "aksum.exe"
			}
			return selfupdate.ArchiveTarGz, "aksum"
		},
	}
}
