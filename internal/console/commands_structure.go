// commands_structure.go implements the STRUCTURE and ANALYSIS console
// commands. Every runner composes the cached session context with the
// shared engine renderers — no analysis logic lives here.
package console

import (
	"fmt"
	"strings"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
)

// runSections lists ELF sections.
func runSections(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil // guidance already printed
	}
	secs := ac.Im.Sections()
	if emitJSON(c, p, secs) {
		return nil
	}
	c.phase("ENUM", "%d sections", len(secs))
	engine.RenderSections(c.out, secs)
	return nil
}

// runSegments lists program headers.
func runSegments(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	segs := ac.Im.Segments()
	if emitJSON(c, p, segs) {
		return nil
	}
	c.phase("ENUM", "%d segments", len(segs))
	engine.RenderSegments(c.out, segs)
	return nil
}

// runSymbols lists static or dynamic symbol-table entries.
func runSymbols(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	syms := ac.Im.Symbols()
	label := "static symbol table"
	dyn := p.Bool("dynamic")
	if dyn {
		syms = ac.Im.DynamicSymbols()
		label = ".dynsym"
	}
	if emitJSON(c, p, syms) {
		return nil
	}
	if len(syms) == 0 && !dyn && ac.Im.Target.Stripped == binary.PropertyEnabled {
		c.warnf("No static symbol table (binary is stripped). Try: symbols --dynamic")
		return nil
	}
	c.phase("ENUM", "%d symbols (%s)", len(syms), label)
	engine.RenderSymbols(c.out, syms)
	if len(syms) == 0 {
		c.printf("    (none)\n")
	}
	return nil
}

// runImports lists imports grouped by security relevance.
func runImports(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	imports := ac.Im.Imports()
	uncat := engine.UncategorizedImports(imports)
	if emitJSON(c, p, map[string]any{
		"total":         len(imports),
		"groups":        engine.ClassifyImports(imports),
		"uncategorized": uncat,
	}) {
		return nil
	}
	c.phase("ENUM", "%d imports (%d security-relevant)", len(imports), len(imports)-len(uncat))
	if len(imports) == 0 {
		c.printf("    (none)\n")
		return nil
	}
	engine.RenderImports(c.out, imports)
	return nil
}

// runStrings extracts and classifies strings honoring scan options. The
// default view reuses the pipeline's cached extraction; custom options
// trigger a fresh scan of the same image.
func runStrings(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	minLen := p.Int("min-length", 4)
	maxN := p.Int("max", 0)
	utf16 := p.Bool("utf16")

	var classified []strscan.Classified
	if minLen == 4 && maxN == 0 && !utf16 {
		classified = ac.ClassifiedStrings() // cached default view
	} else {
		opts := strscan.Options{MinLength: minLen, MaxStrings: maxN, UTF16: utf16}
		extracted := strscan.Extract(ac.Im.RawFile(), opts)
		classified = strscan.ClassifyAll(extracted)
	}
	if emitJSON(c, p, classified) {
		return nil
	}
	c.phase("ANALYSIS", "%d security-relevant strings", len(classified))
	if len(classified) == 0 {
		c.printf("    (none)\n")
		return nil
	}
	engine.RenderStrings(c.out, classified)
	return nil
}

// runFunctions lists discovered functions with confidence filtering.
func runFunctions(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	minConf := strings.ToLower(p.Str("min-confidence"))
	if minConf == "" {
		minConf = "low"
	}
	floor, ok := engine.ConfidenceOrder[minConf]
	if !ok {
		return fmt.Errorf("invalid --min-confidence %q (low, medium, high)", minConf)
	}
	all := engine.SummarizeFuncs(ac.Funcs)
	filtered := make([]engine.FunctionSummary, 0, len(all))
	for _, f := range all {
		if engine.ConfidenceOrder[f.Confidence] >= floor {
			filtered = append(filtered, f)
		}
	}
	if emitJSON(c, p, filtered) {
		return nil
	}
	c.phase("ANALYSIS", "%d functions discovered", len(filtered))
	if len(filtered) == 0 {
		c.printf("    (none)\n")
		return nil
	}
	engine.RenderFunctions(c.out, filtered)
	return nil
}

// runDisasm disassembles a function by address/name or the executable region.
func runDisasm(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	insts, header, derr := engine.SelectInstructions(ac, p.Arg(0), p.Int("limit", 0))
	if derr != nil {
		return derr
	}
	if emitJSON(c, p, map[string]any{
		"header":       header,
		"instructions": insts,
		"count":        len(insts),
	}) {
		return nil
	}
	c.phase("ANALYSIS", "%d instructions decoded", len(insts))
	engine.RenderDisasm(c.out, header, insts)
	return nil
}

// runXrefs shows cross-references to an address or matching data string(s).
func runXrefs(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	addrArg := p.Arg(0)
	substr := p.Str("string")
	switch {
	case addrArg == "" && substr == "":
		return fmt.Errorf("xrefs requires an address or --string <substr>: see 'help xrefs'")
	case addrArg != "" && substr != "":
		return fmt.Errorf("--string and an address argument are mutually exclusive")
	}
	var refs []engine.XrefView
	if substr != "" {
		refs = engine.BuildXrefsToString(ac, substr)
	} else {
		a, aerr := parseAddr(addrArg)
		if aerr != nil {
			return aerr
		}
		refs = engine.BuildXrefsToAddr(ac, a)
	}
	if emitJSON(c, p, refs) {
		return nil
	}
	c.phase("ANALYSIS", "%d cross-references found", len(refs))
	if len(refs) == 0 {
		c.printf("    (none)\n")
		return nil
	}
	engine.RenderXrefs(c.out, refs)
	return nil
}

// runCalls shows direct-call relationships, optionally scoped to one function.
func runCalls(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	fnName := p.Str("func")
	if fnName != "" && ac.BySymbol(fnName) == nil {
		return fmt.Errorf("no discovered function named %q", fnName)
	}
	edges := engine.BuildCallEdges(ac, fnName)
	if emitJSON(c, p, edges) {
		return nil
	}
	c.phase("ANALYSIS", "%d call edges mapped", len(edges))
	if len(edges) == 0 {
		c.printf("    (none)\n")
		return nil
	}
	engine.RenderCallEdges(c.out, edges)
	return nil
}

// runCfg reports per-function control-flow metrics.
func runCfg(c *Console, p *Parsed) error {
	ac, err := requireContext(c)
	if err != nil {
		return nil
	}
	reports, rerr := engine.BuildCFGReports(ac, p.Str("func"), false)
	if rerr != nil {
		return rerr
	}
	if emitJSON(c, p, reports) {
		return nil
	}
	c.phase("ANALYSIS", "%d functions analyzed", len(reports))
	engine.RenderCFGReports(c.out, reports)
	return nil
}
