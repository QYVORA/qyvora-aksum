// views_render.go holds aksum's shared result renderers: every dataset the
// tool produces (sections, symbols, functions, findings, ...) has exactly
// one tabular presentation here, consumed by both the one-shot CLI and the
// interactive console. Machine-readable JSON paths never touch these.
package engine

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
	"github.com/QYVORA/qyvora-aksum/internal/surface"
	"github.com/QYVORA/qyvora-aksum/internal/table"
)

// Addr renders an address as a cell value: minimal hex, always 0x-prefixed.
func Addr(v uint64) string { return fmt.Sprintf("0x%x", v) }

// PropertyRow is one NAME/VALUE pair for identification-style tables.
type PropertyRow struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// TargetProperties converts a Target into ordered property rows. Values the
// file cannot determine stay honestly "unknown".
func TargetProperties(t *binary.Target) []PropertyRow {
	props := []PropertyRow{
		{"Path", t.Path},
		{"Format", string(t.Format)},
	}
	if t.Format != binary.FormatRaw {
		props = append(props,
			PropertyRow{"Class", fmt.Sprintf("%s (%s)", t.Class, t.Type)},
			PropertyRow{"Architecture", string(t.Arch)},
			PropertyRow{"Endianness", string(t.Endianness)},
			PropertyRow{"OS/ABI", t.OSType},
			PropertyRow{"Entry point", Addr(t.Entry)},
			PropertyRow{"Linking", string(t.Linking)},
			PropertyRow{"PIE", t.PIE.String()},
			PropertyRow{"NX", t.NX.String()},
			PropertyRow{"RELRO", t.RELRO},
			PropertyRow{"Canary", t.Canary.String()},
			PropertyRow{"Fortify", t.Fortify.String()},
			PropertyRow{"Symbols", strippedDisplay(t.Stripped)},
			PropertyRow{"Debug info", t.DebugInfo.String()},
		)
	} else {
		props = append(props, PropertyRow{
			"Note", "unidentified container (no parser); strings analysis only"})
	}
	if t.Interpreter != "" {
		props = append(props, PropertyRow{"Interpreter", t.Interpreter})
	}
	for _, lib := range t.Needed {
		props = append(props, PropertyRow{"Library", lib})
	}
	if t.BuildID != "" {
		props = append(props, PropertyRow{"Build ID", t.BuildID})
	}
	for _, h := range t.CompilerHints {
		props = append(props, PropertyRow{"Hint", h})
	}
	return props
}

func strippedDisplay(stripped binary.Property) string {
	switch stripped {
	case binary.PropertyEnabled:
		return "stripped"
	case binary.PropertyDisabled:
		return "present"
	default:
		return "unknown"
	}
}

// RenderTargetProperties draws the binary-identification property table.
func RenderTargetProperties(w io.Writer, t *binary.Target) {
	tt := table.New("property", "value")
	for _, pr := range TargetProperties(t) {
		tt.AddRow(pr.Name, pr.Value)
	}
	tt.Render(w)
}

// RenderSections draws the section table (header-null rows suppressed).
func RenderSections(w io.Writer, sections []structure.Section) {
	t := table.New("name", "type", "address", "offset", "size", "flags").
		SetAlign(2, table.AlignRight).SetAlign(3, table.AlignRight).
		SetAlign(4, table.AlignRight)
	for _, s := range sections {
		if s.Name == "" && s.Type == "NULL" {
			continue // header-null row is noise in human output
		}
		t.AddRow(s.Name, s.Type, Addr(s.Address), Addr(s.Offset),
			strconv.FormatUint(s.Size, 10), joinStrings(s.Flags))
	}
	t.Render(w)
}

// RenderSegments draws the program-header table.
func RenderSegments(w io.Writer, segments []structure.Segment) {
	t := table.New("type", "flags", "vaddr", "offset", "filesz", "memsz", "align").
		SetAlign(2, table.AlignRight).SetAlign(3, table.AlignRight).
		SetAlign(4, table.AlignRight).SetAlign(5, table.AlignRight).
		SetAlign(6, table.AlignRight)
	for _, s := range segments {
		t.AddRow(s.Type, s.Flags, Addr(s.VirtualAddr), Addr(s.Offset),
			strconv.FormatUint(s.FileSize, 10), strconv.FormatUint(s.MemSize, 10),
			fmt.Sprintf("%#x", s.Alignment))
	}
	t.Render(w)
}

// RenderSymbols draws the symbol table.
func RenderSymbols(w io.Writer, syms []structure.Symbol) {
	if len(syms) == 0 {
		return // caller messages the stripped-binary case
	}
	t := table.New("address", "size", "scope", "kind", "defined", "name").
		SetAlign(0, table.AlignRight).SetAlign(1, table.AlignRight)
	for _, s := range syms {
		defined := "yes"
		if !s.Defined {
			defined = "no"
		}
		t.AddRow(Addr(s.Value), strconv.FormatUint(s.Size, 10), s.Scope, s.Kind, defined, s.Name)
	}
	t.Render(w)
}

// RenderImports draws the security-relevance import view: categorized rows
// first, then uncategorized symbols marked "-".
func RenderImports(w io.Writer, imports []structure.Import) {
	groups := ClassifyImports(imports)
	categorized := map[string]bool{}
	t := table.New("category", "symbol", "risk context")
	for _, g := range groups {
		for _, s := range g.Symbols {
			t.AddRow(g.Category, s, "review")
			categorized[s] = true
		}
	}
	var rest []string
	for _, im := range imports {
		if !categorized[im.Name] {
			rest = append(rest, im.Name)
		}
	}
	for _, name := range rest {
		t.AddRow("-", name, "-")
	}
	t.Render(w)
}

// RenderStrings draws the classified-string table.
func RenderStrings(w io.Writer, classified []strscan.Classified) {
	t := table.New("class", "confidence", "value", "section", "address")
	for _, c := range classified {
		addrCell := "-"
		if c.Address != 0 {
			addrCell = Addr(c.Address)
		}
		classCell := c.Class
		if classCell == "" {
			classCell = "-"
		}
		conf := c.Confidence
		if conf == "" {
			conf = "-"
		}
		t.AddRow(classCell, conf, c.Value, c.Section, addrCell)
	}
	t.Render(w)
}

// RenderFunctions draws the discovered-function table plus a count footer.
func RenderFunctions(w io.Writer, rows []FunctionSummary) {
	t := table.New("address", "name", "conf", "size", "calls in/out", "sources").
		SetAlign(0, table.AlignRight).SetAlign(3, table.AlignRight)
	for _, f := range rows {
		t.AddRow(Addr(f.Address), f.Name, f.Confidence,
			strconv.Itoa(f.Size), fmt.Sprintf("%d/%d", f.CallsIn, f.CallsOut),
			joinStrings(f.Sources))
	}
	t.Render(w)
	fmt.Fprintf(w, "\n%d functions\n", len(rows))
}

// RenderCallEdges draws the call-graph edge table plus a count footer.
func RenderCallEdges(w io.Writer, rows []CallEdge) {
	t := table.New("caller", "", "callee")
	for _, e := range rows {
		t.AddRow(e.From, "->", e.To)
	}
	t.Render(w)
	fmt.Fprintf(w, "\n%d edges\n", len(rows))
}

// RenderCFGReports draws per-function CFG metrics plus a count footer.
func RenderCFGReports(w io.Writer, reports []CFGReport) {
	t := table.New("function", "address", "blocks", "edges", "loops", "unreachable").
		SetAlign(1, table.AlignRight).SetAlign(2, table.AlignRight).
		SetAlign(3, table.AlignRight).SetAlign(4, table.AlignRight).
		SetAlign(5, table.AlignRight)
	for _, r := range reports {
		t.AddRow(r.Function, Addr(r.Address),
			strconv.Itoa(r.Metrics.Blocks), strconv.Itoa(r.Metrics.Edges),
			strconv.Itoa(r.Metrics.Loops), strconv.Itoa(r.Metrics.Unreachable))
	}
	t.Render(w)
	fmt.Fprintf(w, "\n%d functions\n", len(reports))
}

// RenderXrefs draws the cross-reference table plus a count footer.
func RenderXrefs(w io.Writer, rows []XrefView) {
	t := table.New("from", "type", "function").SetAlign(0, table.AlignRight)
	for _, r := range rows {
		t.AddRow(Addr(r.From), r.Kind, r.Function)
	}
	t.Render(w)
	fmt.Fprintf(w, "\n%d references\n", len(rows))
}

// RenderSurface draws the aggregated attack-surface view as stacked tables.
func RenderSurface(w io.Writer, r *surface.Report) {
	if len(r.Categories) > 0 {
		fmt.Fprintln(w, "\nSECURITY-RELEVANT IMPORT CATEGORIES")
		ct := table.New("category", "count", "symbols").SetAlign(1, table.AlignRight)
		for _, cat := range r.Categories {
			names := cat.Names
			sort.Strings(names)
			limit := names
			if len(limit) > 8 {
				limit = append(append([]string{}, limit[:8]...), "…")
			}
			ct.AddRow(cat.Category, strconv.Itoa(cat.Count), joinLimit(limit))
		}
		ct.Render(w)
	}

	if len(r.EntryPoints) > 0 {
		fmt.Fprintln(w, "\nENTRY POINTS (entry + first exported functions)")
		et := table.New("kind", "name", "address")
		for _, e := range r.EntryPoints {
			addrCell := "-"
			if e.Addr != 0 {
				addrCell = Addr(e.Addr)
			}
			et.AddRow(e.Kind, e.Name, addrCell)
		}
		et.Render(w)
	}

	if len(r.StringClasses) > 0 {
		fmt.Fprintln(w, "\nSTRING CLASSES")
		keys := make([]string, 0, len(r.StringClasses))
		for k := range r.StringClasses {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		st := table.New("class", "count").SetAlign(1, table.AlignRight)
		for _, k := range keys {
			st.AddRow(k, strconv.Itoa(r.StringClasses[k]))
		}
		st.Render(w)
	}
}

// RenderFindings draws the findings table and, when detailed, the
// reason/validation/evidence block per finding. Detail text is sanitized;
// evidence locations come from structured records.
func RenderFindings(w io.Writer, fs []findings.Finding, detailed bool) {
	if len(fs) == 0 {
		fmt.Fprintln(w, "  none")
		return
	}
	ft := table.New("severity", "confidence", "id", "title")
	for _, f := range fs {
		ft.AddRow(string(f.Severity), string(f.Confidence), f.ID, f.Title)
	}
	ft.Render(w)

	if !detailed {
		return
	}
	for _, f := range fs {
		fmt.Fprintf(w, "\n[%s] %-8s %-10s %s\n", f.Severity, f.Confidence, f.ID, f.Title)
		fmt.Fprintf(w, "  reason:     %s\n", sanitizeText(f.Reason))
		fmt.Fprintf(w, "  validation: %s\n", sanitizeText(f.Validation))
		if len(f.Evidence) > 0 {
			locs := make([]string, 0, len(f.Evidence))
			for _, e := range f.Evidence {
				detail := ""
				if e.Detail != "" {
					detail = " (" + sanitizeText(e.Detail) + ")"
				}
				locs = append(locs, e.Kind+":"+sanitizeText(e.Location)+detail)
			}
			fmt.Fprintf(w, "  evidence:   %s\n", strings.Join(locs, "; "))
		}
	}
}

// sanitizeText strips control characters from binary-derived text before it
// reaches the terminal.
func sanitizeText(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < ' ' || r == 0x7f {
			b.WriteByte('.')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func joinStrings(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

func joinLimit(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
