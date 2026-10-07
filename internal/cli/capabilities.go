package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/capabilities"
	"github.com/QYVORA/qyvora-aksum/internal/table"
)

func newCapabilitiesCmd() *cobra.Command {
	var tableMode bool

	cmd := &cobra.Command{
		Use:   "capabilities",
		Short: "Print the machine-readable capability contract",
		Long: `The capabilities command outputs aksum's complete capability contract.

By default, it outputs JSON. Use --table to render as a terminal table.

This contract lists:
  - Supported binary formats (ELF implemented, PE/Mach-O documented)
  - Supported architectures (x86/x86-64 implemented, ARM64 documented)
  - Analysis capabilities (disassembly, function discovery, CFG, dataflow)
  - Security checks and hardening detection
  - Output formats and event verbs
  - Exit codes and confidence levels

Automation and AI systems can query this to understand what aksum can do
without parsing prose documentation.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tableMode {
				return renderCapabilitiesTable()
			}
			return renderCapabilitiesJSON()
		},
	}

	cmd.Flags().BoolVar(&tableMode, "table", false, "render as a compact terminal table")
	return cmd
}

func renderCapabilitiesJSON() error {
	data, err := capabilities.RenderJSON()
	if err != nil {
		return fmt.Errorf("encoding capabilities: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func renderCapabilitiesTable() error {
	rows := capabilities.RenderTable()
	t := table.New("Capability", "Name", "Implemented", "Notes")
	for _, row := range rows {
		t.AddRow(row...)
	}
	t.Render(os.Stdout)
	return nil
}
