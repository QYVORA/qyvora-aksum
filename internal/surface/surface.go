// Package surface aggregates the externally observable attack surface of a
// binary from evidence already extracted by earlier stages: entry points,
// imported security-relevant APIs, exported symbols, and classified
// strings. Nothing here is speculative — every count traces back to a
// concrete observation recorded in the report.
package surface

import (
	"sort"

	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/analysis/structure"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/security/class"
)

// maxExportEntryPoints bounds the entry-point list; the full export table
// remains available via `aksum exports`.
const maxExportEntryPoints = 64

// CategorySummary counts one class of security-relevant imports.
type CategorySummary struct {
	Category string   `json:"category"`
	Count    int      `json:"count"`
	Names    []string `json:"names"`
}

// EntryPoint is one externally reachable code origin.
type EntryPoint struct {
	Kind string `json:"kind"` // entry | export-func
	Name string `json:"name"`
	Addr uint64 `json:"addr,omitempty"`
}

// Report is the aggregated attack-surface view.
type Report struct {
	Framework     string            `json:"framework"` // "aksum"
	Schema        string            `json:"schema_version"`
	Target        *binary.Target    `json:"target"`
	TotalImports  int               `json:"imports_total"`
	RiskyImports  int               `json:"imports_security_relevant"`
	Categories    []CategorySummary `json:"import_categories,omitempty"`
	ExportFuncs   int               `json:"exported_functions"`
	EntryPoints   []EntryPoint      `json:"entry_points,omitempty"`
	SurfaceStrs   int               `json:"surface_strings"` // security-classified strings
	StringClasses map[string]int    `json:"string_classes,omitempty"`
}

// Build aggregates the surface report from structural views and strings.
func Build(target *binary.Target, im *structure.Image, exports []structure.Export, strs []strscan.Classified) *Report {
	r := &Report{
		Framework:     "aksum",
		Schema:        "1.0",
		Target:        target,
		StringClasses: map[string]int{},
	}

	if im != nil {
		for _, i := range im.Imports() {
			r.TotalImports++
			cat := class.Category(i.Name)
			if cat == "" {
				continue
			}
			r.RiskyImports++
			found := false
			for k := range r.Categories {
				if r.Categories[k].Category == cat {
					r.Categories[k].Count++
					r.Categories[k].Names = append(r.Categories[k].Names, i.Name)
					found = true
					break
				}
			}
			if !found {
				r.Categories = append(r.Categories, CategorySummary{
					Category: cat, Count: 1, Names: []string{i.Name},
				})
			}
		}
	}
	sort.Slice(r.Categories, func(i, j int) bool {
		return r.Categories[i].Category < r.Categories[j].Category
	})

	if target.Entry != 0 {
		r.EntryPoints = append(r.EntryPoints,
			EntryPoint{Kind: "entry", Name: "_start", Addr: target.Entry})
	}

	funcExports := make([]structure.Export, 0, len(exports))
	for _, e := range exports {
		if e.Kind == "func" {
			funcExports = append(funcExports, e)
		}
	}
	r.ExportFuncs = len(funcExports)
	sort.Slice(funcExports, func(i, j int) bool { return funcExports[i].Name < funcExports[j].Name })
	for i, e := range funcExports {
		if i >= maxExportEntryPoints {
			break
		}
		r.EntryPoints = append(r.EntryPoints,
			EntryPoint{Kind: "export-func", Name: e.Name, Addr: e.Value})
	}

	for _, s := range strs {
		if s.Class == "" {
			continue
		}
		r.SurfaceStrs++
		r.StringClasses[s.Class]++
	}
	return r
}
