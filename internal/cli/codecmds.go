package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
)

// registerCodeCommands adds the disassembly/analysis command family.
func registerCodeCommands(root *cobra.Command) {
	root.AddCommand(
		newFunctionsCmd(),
		newDisassembleCmd(),
		newCallsCmd(),
		newCfgCmd(),
		newXrefsCmd(),
	)
}

func newFunctionsCmd() *cobra.Command {
	var minConf string
	cmd := &cobra.Command{
		Use:   "functions <target>",
		Short: "Discover functions with evidence-backed confidence",
		Long: `Discovers functions from symbol tables, the entry point, direct call
targets, and prologue heuristics. Every function reports its confidence
and which sources support it. Stripped binaries yield fewer high-
confidence results by design — aksum does not fabricate names.`,
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			rank, ok := engine.ConfidenceOrder[minConf]
			if !ok {
				return usagef("invalid --min-confidence %q (high, medium, low)", minConf)
			}
			ac, err := engine.OpenAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only
			filtered := make([]engine.FunctionSummary, 0, len(ac.Funcs))
			for _, f := range engine.SummarizeFuncs(ac.Funcs) {
				if engine.ConfidenceOrder[f.Confidence] >= rank {
					filtered = append(filtered, f)
				}
			}
			return emit(c, filtered)
		},
	}
	cmd.Flags().StringVar(&minConf, "min-confidence", "low", "minimum confidence to report: high, medium, low")
	return cmd
}

func newDisassembleCmd() *cobra.Command {
	var symbol, addrStr string
	var limit int
	cmd := &cobra.Command{
		Use:     "disassemble <target>",
		Aliases: []string{"disasm"},
		Short:   "Disassemble a function or the executable region",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			ac, err := engine.OpenAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only

			var insts []disasm.Instruction
			var header string
			switch {
			case addrStr != "":
				addr, perr := strconv.ParseUint(strings.TrimPrefix(addrStr, "0x"), 16, 64)
				if perr != nil {
					return usagef("invalid --addr %q (hexadecimal)", addrStr)
				}
				f := ac.ByAddr(addr)
				if f == nil {
					return usagef("no discovered function starts at %#x (see 'aksum functions')", addr)
				}
				insts, header = f.Instructions, fmt.Sprintf("function %s at %#x (%d bytes)", engine.DisplayName(f), f.Address, f.Size)
			case symbol != "":
				f := ac.BySymbol(symbol)
				if f == nil {
					return usagef("no function named %q (see 'aksum functions')", symbol)
				}
				insts, header = f.Instructions, fmt.Sprintf("function %s at %#x (%d bytes)", engine.DisplayName(f), f.Address, f.Size)
			default:
				base, bytes, rerr := ac.Im.ExecutableRegion()
				if rerr != nil {
					return rerr
				}
				insts, err = ac.Decoder.Decode(bytes, base)
				if err != nil {
					return err
				}
				header = fmt.Sprintf("executable region (%d instructions)", len(insts))
			}

			p := newPrinter()
			if p.Format() == "json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{ //nolint:err113 // ad-hoc payload
					"instructions": insts,
					"count":        len(insts),
				})
			}
			fmt.Printf("; %s\n", header)
			shown := 0
			for i := range insts {
				in := &insts[i]
				fmt.Printf("%#08x  %-22s %s %s\n",
					in.Addr, hexBytes(in.Bytes), in.Mnemonic, strings.Join(operandTexts(in), ", "))
				shown++
				if limit > 0 && shown >= limit {
					fmt.Printf("; ... truncated at %d instructions (--limit)\n", limit)
					break
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&symbol, "symbol", "", "disassemble the named function")
	cmd.Flags().StringVar(&addrStr, "addr", "", "disassemble the function starting at this hex address")
	cmd.Flags().IntVar(&limit, "limit", 0, "cap printed instructions (0 = no cap)")
	return cmd
}

func hexBytes(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}

func operandTexts(in *disasm.Instruction) []string {
	out := make([]string, len(in.Operands))
	for i, op := range in.Operands {
		out[i] = op.Text
	}
	return out
}

func newCallsCmd() *cobra.Command {
	var fnName string
	cmd := &cobra.Command{
		Use:   "calls <target>",
		Short: "Show the call graph (direct calls between functions)",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			ac, err := engine.OpenAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only
			return emit(c, engine.BuildCallEdges(ac, fnName))
		},
	}
	cmd.Flags().StringVar(&fnName, "func", "", "restrict to calls made by this function")
	return cmd
}

func newCfgCmd() *cobra.Command {
	var fnName string
	var showBlocks bool
	cmd := &cobra.Command{
		Use:   "cfg <target>",
		Short: "Per-function control-flow graph metrics (or full blocks)",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			ac, err := engine.OpenAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only
			reports, rerr := engine.BuildCFGReports(ac, fnName, showBlocks)
			if rerr != nil {
				return usagef("%v", rerr)
			}
			return emit(c, reports)
		},
	}
	cmd.Flags().StringVar(&fnName, "func", "", "analyze only this function")
	cmd.Flags().BoolVar(&showBlocks, "blocks", false, "include block-level detail (JSON mode)")
	return cmd
}

func newXrefsCmd() *cobra.Command {
	var addrStr, substr string
	cmd := &cobra.Command{
		Use:   "xrefs <target>",
		Short: "Cross-references to an address or data string",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			switch {
			case addrStr == "" && substr == "":
				return usagef("one of --addr or --string is required")
			case addrStr != "" && substr != "":
				return usagef("--addr and --string are mutually exclusive")
			}
			ac, err := engine.OpenAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only
			var refs []engine.XrefView
			if addrStr != "" {
				addr, perr := strconv.ParseUint(strings.TrimPrefix(addrStr, "0x"), 16, 64)
				if perr != nil {
					return usagef("invalid --addr %q (hexadecimal)", addrStr)
				}
				refs = engine.BuildXrefsToAddr(ac, addr)
			} else {
				refs = engine.BuildXrefsToString(ac, substr)
			}
			return emit(c, refs)
		},
	}
	cmd.Flags().StringVar(&addrStr, "addr", "", "cross-reference this hex address")
	cmd.Flags().StringVar(&substr, "string", "", "cross-reference data strings containing this substring")
	return cmd
}
