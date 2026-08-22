package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/version"
)

func newVersionCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the aksum version",
		RunE: func(_ *cobra.Command, _ []string) error {
			if jsonOut {
				fmt.Printf("{\"framework\":\"aksum\",\"version\":%q}\n", version.Version)
				return nil
			}
			fmt.Printf("aksum %s\n  Commit:    %s\n  Built:     %s\n  BuildUser: %s\n",
				version.Version, version.Commit, version.Date, version.BuildUser)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output in JSON format")
	return cmd
}
