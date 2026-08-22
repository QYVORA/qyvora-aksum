package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-aksum/internal/disasm"

	"github.com/QYVORA/qyvora-aksum/internal/cfg"
	"github.com/QYVORA/qyvora-aksum/internal/functions"
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

// funcSummary is the user-facing function record.
type funcSummary struct {
	Name       string   `json:"name"`
	Address    uint64   `json:"address"`
	Size       int      `json:"size"`
	Confidence string   `json:"confidence"`
	Sources    []string `json:"sources"`
	PLT        bool     `json:"plt,omitempty"`
	CallsOut   int      `json:"callees"`
	CallsIn    int      `json:"callers"`
}

var confOrder = map[string]int{"low": 1, "medium": 2, "high": 3}

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
			if _, ok := confOrder[minConf]; !ok {
				return usagef("invalid --min-confidence %q (high, medium, low)", minConf)
			}
			ac, err := openAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only
			out := summarizeFuncs(ac.funcs)
			filtered := make([]funcSummary, 0, len(out))
			for _, f := range out {
				if confOrder[f.Confidence] >= confOrder[minConf] {
					filtered = append(filtered, f)
				}
			}
			return emit(c, filtered)
		},
	}
	cmd.Flags().StringVar(&minConf, "min-confidence", "low", "minimum confidence to report: high, medium, low")
	return cmd
}

func summarizeFuncs(funcs []*functions.Function) []funcSummary {
	out := make([]funcSummary, 0, len(funcs))
	for _, f := range funcs {
		name := f.Name
		if name == "" {
			name = fmt.Sprintf("sub_%x", f.Address)
		}
		out = append(out, funcSummary{
			Name: name, Address: f.Address, Size: f.Size,
			Confidence: f.Confidence, Sources: f.Sources, PLT: f.PLT,
			CallsOut: len(f.Calls), CallsIn: len(f.Callers),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

func printFuncTable(rows []funcSummary) {
	fmt.Printf("%-16s %-38s %-8s %7s  %-24s %s\n", "ADDRESS", "NAME", "CONF", "SIZE", "SOURCES", "CALLS")
	for _, f := range rows {
		fmt.Printf("%-16x %-38s %-8s %7d  %-24s in:%d out:%d\n",
			f.Address, truncate(f.Name, 38), f.Confidence, f.Size,
			strings.Join(f.Sources, ","), f.CallsIn, f.CallsOut)
	}
	fmt.Printf("\n%d functions\n", len(rows))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

func newDisassembleCmd() *cobra.Command {
	var symbol, addrStr string
	var limit int
	cmd := &cobra.Command{
		Use:   "disassemble <target>",
		Short: "Disassemble a function or the executable region",
		RunE: func(c *cobra.Command, args []string) error {
			path, err := oneArg(c, args)
			if err != nil {
				return err
			}
			ac, err := openAnalysis(path)
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
				f := ac.byAddr(addr)
				if f == nil {
					return usagef("no discovered function starts at %#x (see 'aksum functions')", addr)
				}
				insts, header = f.Instructions, fmt.Sprintf("function %s at %#x (%d bytes)", displayName(f), f.Address, f.Size)
			case symbol != "":
				f := ac.bySymbol(symbol)
				if f == nil {
					return usagef("no function named %q (see 'aksum functions')", symbol)
				}
				insts, header = f.Instructions, fmt.Sprintf("function %s at %#x (%d bytes)", displayName(f), f.Address, f.Size)
			default:
				base, bytes, rerr := ac.im.ExecutableRegion()
				if rerr != nil {
					return rerr
				}
				insts, err = ac.decoder.Decode(bytes, base)
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

func displayName(f *functions.Function) string {
	if f.Name != "" {
		return f.Name
	}
	return fmt.Sprintf("sub_%x", f.Address)
}

// byAddr / bySymbol lookups over discovered functions.
func (a *analysisContext) byAddr(addr uint64) *functions.Function {
	for _, f := range a.funcs {
		if f.Address == addr {
			return f
		}
	}
	return nil
}

func (a *analysisContext) bySymbol(name string) *functions.Function {
	for _, f := range a.funcs {
		if displayName(f) == name {
			return f
		}
	}
	return nil
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
			ac, err := openAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only

			names := callgraphNames(ac.funcs)
			var edges []callEdge
			for _, f := range ac.funcs {
				if fnName != "" && displayName(f) != fnName {
					continue
				}
				seen := map[uint64]bool{}
				for _, callee := range f.Calls {
					if seen[callee] {
						continue
					}
					seen[callee] = true
					edges = append(edges, callEdge{From: displayName(f), To: names[callee]})
				}
			}
			sort.Slice(edges, func(i, j int) bool {
				if edges[i].From != edges[j].From {
					return edges[i].From < edges[j].From
				}
				return edges[i].To < edges[j].To
			})
			if edges == nil {
				edges = []callEdge{}
			}
			return emit(c, edges)
		},
	}
	cmd.Flags().StringVar(&fnName, "func", "", "restrict to calls made by this function")
	return cmd
}

func callgraphNames(funcs []*functions.Function) map[uint64]string {
	m := map[uint64]string{}
	for _, f := range funcs {
		m[f.Address] = displayName(f)
	}
	return m
}

type cfgReport struct {
	Function    string      `json:"function"`
	Address     uint64      `json:"address"`
	Metrics     cfg.Stats   `json:"metrics"`
	Unreachable []uint64    `json:"unreachable_blocks,omitempty"`
	Blocks      []cfg.Block `json:"blocks,omitempty"`
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
			ac, err := openAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only

			targets := ac.funcs
			if fnName != "" {
				f := ac.bySymbol(fnName)
				if f == nil {
					return usagef("no function named %q", fnName)
				}
				targets = []*functions.Function{f}
			}
			reports := make([]cfgReport, 0, len(targets))
			for _, f := range targets {
				g := cfg.Build(f.Address, f.Instructions)
				r := cfgReport{Function: displayName(f), Address: f.Address, Metrics: g.Metrics()}
				if g.Loops > 0 || len(g.Unreachable) > 0 {
					r.Unreachable = g.Unreachable
				} else {
					r.Unreachable = nil
				}
				if showBlocks {
					for _, b := range orderedBlocks(g) {
						r.Blocks = append(r.Blocks, *b)
					}
				}
				reports = append(reports, r)
			}
			return emit(c, reports)
		},
	}
	cmd.Flags().StringVar(&fnName, "func", "", "analyze only this function")
	cmd.Flags().BoolVar(&showBlocks, "blocks", false, "include block-level detail (JSON mode)")
	return cmd
}

func orderedBlocks(g *cfg.Graph) []*cfg.Block {
	out := make([]*cfg.Block, 0, len(g.ByAddr))
	for _, b := range g.ByAddr {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
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
			ac, err := openAnalysis(path)
			if err != nil {
				return err
			}
			defer ac.Close() //nolint:errcheck // read-only

			names := callgraphNames(ac.funcs)
			var refs []xrefView
			if addrStr != "" {
				addr, perr := strconv.ParseUint(strings.TrimPrefix(addrStr, "0x"), 16, 64)
				if perr != nil {
					return usagef("invalid --addr %q (hexadecimal)", addrStr)
				}
				for _, r := range ac.xr.XrefsTo(addr) {
					refs = append(refs, xrefView{Kind: r.Kind, From: r.From, Function: names[r.FromFunc]})
				}
			} else {
				hits, herr := ac.stringAddresses(substr)
				if herr != nil {
					return herr
				}
				for _, hitAddr := range hits {
					for _, r := range ac.xr.XrefsTo(hitAddr) {
						refs = append(refs, xrefView{Kind: r.Kind, From: r.From, Function: names[r.FromFunc]})
					}
				}
			}
			sort.Slice(refs, func(i, j int) bool { return refs[i].From < refs[j].From })
			if refs == nil {
				refs = []xrefView{}
			}
			return emit(c, refs)
		},
	}
	cmd.Flags().StringVar(&addrStr, "addr", "", "cross-reference this hex address")
	cmd.Flags().StringVar(&substr, "string", "", "cross-reference data strings containing this substring")
	return cmd
}

// callEdge is one direct-call relation in the call graph.
type callEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func printCallEdges(rows []callEdge) {
	fmt.Printf("%-38s -> %s\n", "CALLER", "CALLEE")
	for _, e := range rows {
		fmt.Printf("%-38s -> %s\n", truncate(e.From, 38), truncate(e.To, 38))
	}
	fmt.Printf("\n%d edges\n", len(rows))
}

func printCfgReports(reports []cfgReport) {
	fmt.Printf("%-38s %-16s %6s %6s %6s %12s\n", "FUNCTION", "ADDRESS", "BLOCKS", "EDGES", "LOOPS", "UNREACHABLE")
	for _, r := range reports {
		fmt.Printf("%-38s %#016x %6d %6d %6d %12d\n",
			truncate(r.Function, 38), r.Address,
			r.Metrics.Blocks, r.Metrics.Edges, r.Metrics.Loops, r.Metrics.Unreachable)
	}
	fmt.Printf("\n%d functions\n", len(reports))
}

// xrefView is one cross-reference record for user output.
type xrefView struct {
	Kind     string `json:"kind"`
	From     uint64 `json:"from"`
	Function string `json:"function"`
}

func printXrefTable(rows []xrefView) {
	fmt.Printf("%-8s %-16s %s\n", "KIND", "FROM", "FUNCTION")
	for _, r := range rows {
		fmt.Printf("%-8s %#016x %s\n", r.Kind, r.From, r.Function)
	}
	fmt.Printf("\n%d references\n", len(rows))
}
