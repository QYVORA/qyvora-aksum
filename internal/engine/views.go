package engine

import (
	"fmt"
	"sort"

	"github.com/QYVORA/qyvora-aksum/internal/functions"
)

// FunctionSummary is the user-facing function record.
type FunctionSummary struct {
	Name       string   `json:"name"`
	Address    uint64   `json:"address"`
	Size       int      `json:"size"`
	Confidence string   `json:"confidence"`
	Sources    []string `json:"sources"`
	PLT        bool     `json:"plt,omitempty"`
	CallsOut   int      `json:"callees"`
	CallsIn    int      `json:"callers"`
}

// ConfidenceOrder ranks discovery confidence for filtering.
var ConfidenceOrder = map[string]int{"low": 1, "medium": 2, "high": 3}

// SummarizeFuncs converts discovered functions into address-sorted,
// user-facing rows.
func SummarizeFuncs(funcs []*functions.Function) []FunctionSummary {
	out := make([]FunctionSummary, 0, len(funcs))
	for _, f := range funcs {
		out = append(out, FunctionSummary{
			Name: DisplayName(f), Address: f.Address, Size: f.Size,
			Confidence: f.Confidence, Sources: f.Sources, PLT: f.PLT,
			CallsOut: len(f.Calls), CallsIn: len(f.Callers),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// CallEdge is one direct-call relation in the call graph.
type CallEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// BuildCallEdges collects direct-call edges, optionally restricted to one
// caller function name. Unnamed callees get honest synthetic labels.
func BuildCallEdges(c *Context, fnName string) []CallEdge {
	names := CallNames(c.Funcs)
	var edges []CallEdge
	for _, f := range c.Funcs {
		if fnName != "" && DisplayName(f) != fnName {
			continue
		}
		seen := make(map[uint64]bool, len(f.Calls))
		for _, callee := range f.Calls {
			if seen[callee] {
				continue
			}
			seen[callee] = true
			to := names[callee]
			if to == "" {
				to = fmt.Sprintf("sub_%x", callee)
			}
			edges = append(edges, CallEdge{From: DisplayName(f), To: to})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	if edges == nil {
		edges = []CallEdge{}
	}
	return edges
}

// XrefView is one cross-reference record for user output.
type XrefView struct {
	Kind     string `json:"kind"`
	From     uint64 `json:"from"`
	Function string `json:"function"`
}

// BuildXrefsToAddr lists references to a virtual address.
func BuildXrefsToAddr(c *Context, addr uint64) []XrefView {
	names := CallNames(c.Funcs)
	raw := c.Xrefs.XrefsTo(addr)
	refs := make([]XrefView, 0, len(raw))
	for _, r := range raw {
		refs = append(refs, XrefView{Kind: r.Kind, From: r.From, Function: names[r.FromFunc]})
	}
	return sortXrefs(refs)
}

// BuildXrefsToString lists references to every extracted string containing
// substr (case-insensitive).
func BuildXrefsToString(c *Context, substr string) []XrefView {
	names := CallNames(c.Funcs)
	var refs []XrefView
	for _, hitAddr := range c.StringAddresses(substr) {
		for _, r := range c.Xrefs.XrefsTo(hitAddr) {
			refs = append(refs, XrefView{Kind: r.Kind, From: r.From, Function: names[r.FromFunc]})
		}
	}
	return sortXrefs(refs)
}

func sortXrefs(refs []XrefView) []XrefView {
	sort.Slice(refs, func(i, j int) bool { return refs[i].From < refs[j].From })
	if refs == nil {
		refs = []XrefView{}
	}
	return refs
}
