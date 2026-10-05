package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/version"
)

func newVersionCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the aksum version",
		RunE: func(_ *cobra.Command, _ []string) error {
			info := version.GetInfo()
			// Both the local --json flag and the global --output json select
			// machine-readable output, matching the toolchain-wide contract.
			if jsonOut || newPrinter().Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(info) //nolint:err113 // stable payload
			}
			fmt.Printf("aksum %s\n", info.Version)
			fmt.Printf("  framework:  %s\n", info.Framework)
			fmt.Printf("  commit:     %s\n", info.Commit)
			fmt.Printf("  built:      %s\n", info.Date)
			fmt.Printf("  by:         %s\n", info.BuildUser)
			fmt.Printf("  go:         %s %s/%s\n", info.GoVersion, info.OS, info.Arch)
			fmt.Printf("  website:    %s\n", info.Website)
			fmt.Printf("  support:    %s\n", info.Support)
			fmt.Printf("  built in:   %s\n", info.BuiltIn)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output in JSON format")
	return cmd
}
