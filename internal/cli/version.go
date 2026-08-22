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
			// Both the local --json flag and the global --format json select
			// machine-readable output, matching the toolchain-wide contract.
			if jsonOut || newPrinter().Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]string{ //nolint:err113 // stable payload
					"framework": "aksum",
					"version":   version.Version,
				})
			}
			fmt.Printf("aksum %s\n  Commit:    %s\n  Built:     %s\n  BuildUser: %s\n",
				version.Version, version.Commit, version.Date, version.BuildUser)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output in JSON format")
	return cmd
}
