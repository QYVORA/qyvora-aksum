package cli

import (
	"encoding/json"
	"os"

	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/engine"
	"github.com/QYVORA/qyvora-aksum/internal/output"
)

// newPrinter builds the shared human-output renderer from global flags.
func newPrinter() *output.Printer {
	p := output.New()
	if formatFlag != "" {
		p.SetFormat(formatFlag)
	}
	p.SetQuiet(quietFlag)
	return p
}

// emit renders v: a table in terminal mode, JSON in json mode. Terminal
// rendering delegates to the shared engine views so the one-shot CLI and
// the interactive console always look identical.
func emit(_ any, v any) error {
	if newPrinter().Format() == "json" {
		return json.NewEncoder(os.Stdout).Encode(v)
	}
	switch rows := v.(type) {
	case []structure.Section:
		engine.RenderSections(os.Stdout, rows)
	case []structure.Segment:
		engine.RenderSegments(os.Stdout, rows)
	case []structure.Symbol:
		engine.RenderSymbols(os.Stdout, rows)
	case []engine.FunctionSummary:
		engine.RenderFunctions(os.Stdout, rows)
	case []engine.CallEdge:
		engine.RenderCallEdges(os.Stdout, rows)
	case []engine.CFGReport:
		engine.RenderCFGReports(os.Stdout, rows)
	case []engine.XrefView:
		engine.RenderXrefs(os.Stdout, rows)
	default:
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		if _, werr := os.Stdout.WriteString(string(data) + "\n"); werr != nil {
			return werr
		}
	}
	return nil
}

// mapLoadErr distinguishes unsupported targets from ordinary failures at the
// exit-code layer (kept as a seam for future error typing).
func mapLoadErr(err error) error { return err }
