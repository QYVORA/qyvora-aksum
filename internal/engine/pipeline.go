package engine

import (
	strscan "github.com/QYVORA/qyvora-aksum/internal/analysis/strings"
	"github.com/QYVORA/qyvora-aksum/internal/binary"
	"github.com/QYVORA/qyvora-aksum/internal/checks"
	"github.com/QYVORA/qyvora-aksum/internal/dataflow"
	"github.com/QYVORA/qyvora-aksum/internal/findings"
	"github.com/QYVORA/qyvora-aksum/internal/validation"
)

// AnalyzeReport is the full-pipeline machine-readable result.
type AnalyzeReport struct {
	Framework string             `json:"framework"` // always "aksum"
	Schema    string             `json:"schema_version"`
	Target    *binary.Target     `json:"target"`
	Summary   AnalyzeSummary     `json:"summary"`
	Findings  []findings.Finding `json:"findings"`
}

// AnalyzeSummary is the aggregate counters block of a report.
type AnalyzeSummary struct {
	Functions         int            `json:"functions_discovered"`
	StringsExtracted  int            `json:"strings_extracted"`
	StringsClassified int            `json:"strings_classified"`
	Imports           int            `json:"imports"`
	CallSitesResolved int            `json:"call_sites_resolved"`
	ValidatedCount    int            `json:"findings_validated"`
	BySeverity        map[string]int `json:"by_severity"`
	ByConfidence      map[string]int `json:"by_confidence"`
}

// Observer receives lifecycle callbacks while the pipeline runs so callers
// can drive event streams without the engine depending on them. All fields
// are optional; a nil Observer is valid.
type Observer struct {
	// Phase reports analysis phase transitions (strings, dataflow, checks).
	Phase func(name string, start bool, data map[string]any)
	// Validation reports validation-pass boundaries.
	Validation func(done bool, data map[string]any)
	// Finding fires once per finding kept at or above MinSeverity.
	Finding func(f findings.Finding)
}

// PipelineOptions bound one full static assessment run.
type PipelineOptions struct {
	MinSeverity findings.Severity // minimum severity to keep in the report
}

var sevRank = map[findings.Severity]int{
	findings.SevInfo: 0, findings.SevLow: 1, findings.SevMedium: 2,
	findings.SevHigh: 3, findings.SevCritical: 4,
}

// ValidMinSeverity reports whether s names a known severity.
func ValidMinSeverity(s findings.Severity) bool {
	_, ok := sevRank[s]
	return ok
}

// RunPipeline executes the complete static assessment pipeline against an
// open context: strings, dataflow call-site resolution, every static rule,
// validation escalation, and severity-filtered deduplicated output.
func RunPipeline(c *Context, opts PipelineOptions, obs *Observer) (*AnalyzeReport, error) {
	if obs == nil {
		obs = &Observer{}
	}
	phase := func(name string, start bool, data map[string]any) {
		if obs.Phase != nil {
			obs.Phase(name, start, data)
		}
	}
	if opts.MinSeverity == "" {
		opts.MinSeverity = findings.SevInfo
	}
	min := sevRank[opts.MinSeverity]

	phase("strings", true, nil)
	extracted := strscan.Extract(c.Im.RawFile(), strscan.Options{})
	classified := strscan.ClassifyAll(extracted)
	c.strings = classified // share the cache; strings never re-extract
	phase("strings", false, map[string]any{"extracted": len(extracted), "classified": len(classified)})

	phase("dataflow", true, nil)
	sites := dataflow.New(c.Im.Relocs(), c.Funcs, classified).AnalyzeAll(c.Funcs)
	phase("dataflow", false, map[string]any{"call_sites_resolved": len(sites)})

	ctx := &checks.Context{
		Target:    c.Im.Target,
		Imports:   c.Im.Imports(),
		Segments:  c.Im.Segments(),
		Strings:   classified,
		CallSites: sites,
	}
	phase("checks", true, nil)
	found, err := checks.Run(ctx)
	if err != nil {
		return nil, err
	}
	phase("checks", false, map[string]any{"findings": len(found)})

	if obs.Validation != nil {
		obs.Validation(false, map[string]any{"findings": len(found), "call_sites": len(sites)})
	}
	vres := validation.Validate(found, sites)
	if obs.Validation != nil {
		obs.Validation(true, map[string]any{"validated": vres.Upgraded, "corroborated_existing": vres.Corroborated})
	}

	kept := make([]findings.Finding, 0, len(found))
	for _, f := range found {
		if f.Severity.Rank() >= min {
			kept = append(kept, f)
			if obs.Finding != nil {
				obs.Finding(f)
			}
		}
	}

	return &AnalyzeReport{
		Framework: "aksum",
		Schema:    "1.0",
		Target:    c.Im.Target,
		Summary: AnalyzeSummary{
			Functions:         len(c.Funcs),
			StringsExtracted:  len(extracted),
			StringsClassified: len(classified),
			Imports:           len(ctx.Imports),
			CallSitesResolved: len(sites),
			ValidatedCount:    vres.Upgraded,
			BySeverity:        SeverityCounts(kept),
			ByConfidence:      ConfidenceCounts(kept),
		},
		Findings: kept,
	}, nil
}

// SeverityCounts tallies findings per severity.
func SeverityCounts(fs []findings.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[string(f.Severity)]++
	}
	return m
}

// ConfidenceCounts tallies findings per confidence state.
func ConfidenceCounts(fs []findings.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[string(f.Confidence)]++
	}
	return m
}
